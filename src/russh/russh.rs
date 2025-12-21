use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};
use russh_sftp::client::SftpSession;
use url::Url;

use cosmic::{
    Task,
    iced::{Subscription, futures::SinkExt, stream},
    widget,
};
use std::{
    any::TypeId, cell::Cell, collections::HashMap, future::pending, path::Path, path::PathBuf,
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock, mpsc};

use super::{ClientAuth, ClientItem, ClientItems, ClientMessage, Connector};
use crate::{
    config::IconSizes,
    tab::{self, DirSize, ItemMetadata, ItemThumbnail, Location},
};
use tokio::runtime::Builder;

fn get_key_files() -> Result<(PathBuf, PathBuf), String> {
    let home_dir = dirs::home_dir().ok_or_else(|| {
        "Could not determine the user home directory.\n\
        This usually indicates that the HOME environment variable is missing or invalid.\n\
        Please ensure HOME is set correctly before using SSH connections."
            .to_string()
    })?;

    let ssh_dir = home_dir.join(".ssh");
    if !ssh_dir.is_dir() {
        return Err(format!(
            "SSH configuration directory not found: {}.\n\
            Please ensure ~/.ssh exists and contains your SSH keys.",
            ssh_dir.display()
        ));
    }
    if ssh_dir.join("id_rsa").is_file() {
        Ok((ssh_dir.join("id_rsa"), ssh_dir.join("id_rsa.pub")))
    } else if ssh_dir.join("id_ed25519").is_file() {
        Ok((ssh_dir.join("id_ed25519"), ssh_dir.join("id_ed25519.pub")))
    } else if ssh_dir.join("id_ecdsa").is_file() {
        Ok((ssh_dir.join("id_ecdsa"), ssh_dir.join("id_ecdsa.pub")))
    } else if ssh_dir.join("id_dsa").is_file() {
        Ok((ssh_dir.join("id_dsa"), ssh_dir.join("id_dsa.pub")))
    } else {
        Err(format!(
            "No SSH key pair found in {}.\n\
            Expected one of: id_rsa, id_ed25519, id_ecdsa, id_dsa.\n\
            Please generate a key (e.g., with `ssh-keygen -t ed25519`) and try again.",
            ssh_dir.display()
        ))
    }
}

fn virtual_remote_root_items(sizes: IconSizes) -> Result<Vec<tab::Item>, String> {
    struct V {
        name: String,
        display_name: String,
        uri: String,
    }

    let entries = vec![V {
        name: "Remote".into(),
        display_name: "Remote".into(),
        uri: "ssh://michael@localhost:22/".into(),
    }];

    let mut items = Vec::new();

    for v in entries {
        let name = v.name;
        let uri = v.uri;
        let display_name = v.display_name;
        let location = Location::Remote(uri, display_name.clone(), Some("/".into()));

        let (mime, icon_handle_grid, icon_handle_list, icon_handle_list_condensed) = {
            let file_icon = |size| widget::icon::from_name("folder").size(size).handle();
            (
                //TODO: get mime from content_type?
                "inode/directory".parse().unwrap(),
                file_icon(sizes.grid()),
                file_icon(sizes.list()),
                file_icon(sizes.list_condensed()),
            )
        };

        items.push(tab::Item {
            name,
            is_mount_point: false,
            is_client_point: true,
            display_name,
            metadata: ItemMetadata::SimpleDir { entries: 0 },
            hidden: false,
            location_opt: Some(location),
            mime,
            icon_handle_grid,
            icon_handle_list,
            icon_handle_list_condensed,
            thumbnail_opt: Some(ItemThumbnail::NotImage),
            button_id: widget::Id::unique(),
            pos_opt: Cell::new(None),
            rect_opt: Cell::new(None),
            selected: false,
            highlighted: false,
            overlaps_drag_rect: false,
            dir_size: DirSize::NotDirectory,
            cut: false,
        });
    }
    Ok(items)
}

pub async fn dir_info(
    client: &Client,
    uri: &str,
) -> Result<(String, String, Option<PathBuf>), String> {
    let remote_file = remote_file_from_uri(uri)?;
    let resolved_uri = remote_file.uri();

    let channel = client.get_channel().await.map_err(|e| e.to_string())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| e.to_string())?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| e.to_string())?;

    if let Err(err) = sftp.metadata(&remote_file.path).await {
        return Err(format!(
            "dir_info(): metadata error for {}: {}",
            remote_file.path, err
        ));
    }

    // Display name = last component of `remote_file.path`
    let display_name = Path::new(&remote_file.path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&remote_file.path)
        .to_string();
    let filepath: Option<PathBuf> = Some(PathBuf::from(&remote_file.path));

    Ok((resolved_uri, display_name, filepath))
}

pub fn remote_file_from_uri(uri: &str) -> Result<RemoteFile, String> {
    let url = Url::parse(uri).map_err(|e| format!("Invalid remote URI {uri}: {e}"))?;
    if url.scheme() != "ssh" {
        return Err(format!(
            "Unsupported scheme '{}', expected ssh://",
            url.scheme()
        ));
    }
    let host = url.host_str().ok_or("Missing host in ssh URI")?.to_string();
    let port = url.port().unwrap_or(22);
    let username = if url.username().is_empty() {
        None
    } else {
        Some(url.username().to_string())
    };
    let mut path = url.path().to_string();
    if path.is_empty() {
        path = "/".into();
    }
    // Remove trailing slash except root
    if path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    Ok(RemoteFile {
        host,
        port,
        username,
        path,
    })
}

pub async fn resolve_symlink(
    client: &Client,
    remotefile: &RemoteFile,
) -> Result<RemoteFile, String> {
    let channel = client.get_channel().await.map_err(|e| e.to_string())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| e.to_string())?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| e.to_string())?;

    match sftp.read_link(&remotefile.path).await {
        Ok(link_path) => {
            // Build new URI using same host/username but new path
            let new_uri = format!(
                "ssh://{}{}:{}{}",
                remotefile
                    .username
                    .clone()
                    .map(|u| u + "@")
                    .unwrap_or_default(),
                remotefile.host,
                remotefile.port,
                link_path
            );
            remote_file_from_uri(&new_uri)
        }
        Err(_) => Ok(remotefile.clone()), // not a symlink → keep original
    }
}

async fn remote_sftp_list(
    client: &Client,
    uri: &str,
    sizes: IconSizes,
) -> Result<Vec<tab::Item>, String> {
    let mut remote_file = remote_file_from_uri(uri)?;
    let force_dir = uri.starts_with("ssh:///");
    let path = remote_file.path.clone();
    let channel = client.get_channel().await.map_err(|e| e.to_string())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| e.to_string())?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| e.to_string())?;
    let entries = sftp
        .read_dir(path.clone())
        .await
        .map_err(|e| format!("read_dir {path}: {e:?}"))?;

    let mut items = Vec::new();
    for entry in entries {
        let child_path = PathBuf::from(entry.file_name());
        let info = entry.metadata();
        if info.is_symlink() {
            remote_file = resolve_symlink(client, &remote_file).await?;
        }
        let name = child_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let new_path = PathBuf::from(&path).join(&child_path);
        let child_uri = format!(
            "ssh://{}{}:{}{}",
            remote_file
                .username
                .clone()
                .map(|u| u + "@")
                .unwrap_or_default(),
            remote_file.host,
            remote_file.port,
            new_path.to_string_lossy(),
        );

        let location = Location::Remote(child_uri, name.clone(), Some(new_path.clone()));

        let metadata = if !force_dir {
            let mtime = info
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let is_dir = info.is_dir();
            let size_opt = (!is_dir).then_some(info.size).flatten();
            let mut children_opt = None;
            if is_dir {
                // Cannot map remote SFTP entries to a local filesystem path here,
                // so avoid using a non-existent `file` variable; leave a safe default.
                // TODO: consider querying the SFTP session for child count asynchronously.
                children_opt = Some(0);
            }
            // TODO: ItemMetadata::Russh
            ItemMetadata::RusshPath {
                mtime,
                size_opt,
                children_opt,
            }
        } else {
            ItemMetadata::SimpleDir { entries: 0 }
        };

        let (mime, icon_handle_grid, icon_handle_list, icon_handle_list_condensed) = {
            let file_icon = |size| {
                widget::icon::from_name(if metadata.is_dir() {
                    "folder"
                } else {
                    "text-x-generic"
                })
                .size(size)
                .handle()
            };
            (
                // TODO: get mime from content_type?
                "inode/directory".parse().unwrap(),
                file_icon(sizes.grid()),
                file_icon(sizes.list()),
                file_icon(sizes.list_condensed()),
            )
        };

        // Check if item is hidden
        let hidden = name.starts_with('.');

        items.push(tab::Item {
            name: name.clone(),
            is_mount_point: false,
            is_client_point: true,
            display_name: name,
            metadata,
            hidden,
            location_opt: Some(location),
            mime,
            icon_handle_grid,
            icon_handle_list,
            icon_handle_list_condensed,
            thumbnail_opt: Some(ItemThumbnail::NotImage),
            button_id: widget::Id::unique(),
            pos_opt: Cell::new(None),
            rect_opt: Cell::new(None),
            selected: false,
            highlighted: false,
            overlaps_drag_rect: false,
            dir_size: DirSize::NotDirectory,
            cut: false,
        });
    }

    Ok(items)
}

fn request_password(uri: String, event_tx: mpsc::UnboundedSender<Event>) -> ClientAuth {
    let auth = ClientAuth {
        message: String::new(),
        username_opt: Some(String::new()),
        domain_opt: Some(String::new()),
        password_opt: Some(String::new()),
        remember_opt: Some(false),
        anonymous_opt: Some(false),
    };
    let (auth_tx, mut auth_rx) = mpsc::channel(1);
    event_tx
        .send(Event::RemoteAuth(uri.clone(), auth, auth_tx))
        .unwrap();

    if let Some(auth) = auth_rx.blocking_recv() {
        auth
    } else {
        ClientAuth {
            message: "Authentication cancelled".into(),
            username_opt: None,
            domain_opt: None,
            password_opt: None,
            remember_opt: None,
            anonymous_opt: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RemoteFile {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub path: String,
}

impl RemoteFile {
    pub fn uri(&self) -> String {
        let userpart = if let Some(user) = &self.username {
            format!("{}@", user)
        } else {
            "".into()
        };
        format!("ssh://{}{}:{}{}", userpart, self.host, self.port, self.path)
    }
}

enum Cmd {
    Items(IconSizes, mpsc::Sender<ClientItems>),
    Rescan,
    Connect(ClientItem, tokio::sync::oneshot::Sender<anyhow::Result<()>>),
    RemoteDrive(String, tokio::sync::oneshot::Sender<anyhow::Result<()>>),
    RemoteScan(
        String,
        IconSizes,
        mpsc::Sender<Result<Vec<tab::Item>, String>>,
    ),
    DirInfo(
        String,
        mpsc::Sender<Result<(String, String, Option<PathBuf>), anyhow::Error>>,
    ),
    Disconnect(ClientItem),
}

enum Event {
    Changed,
    Items(ClientItems),
    ClientResult(ClientItem, Result<bool, String>),
    RemoteAuth(String, ClientAuth, mpsc::Sender<ClientAuth>),
    RemoteResult(String, Result<bool, String>),
}
// async_ssh2_tokio::client::Client
// pub async fn connect(addr: impl ToSocketAddrsWithHostname, username: &str, auth: AuthMethod, server_check: ServerCheckMethod) -> Result<Self, crate::Error>

#[derive(Clone, Debug)]
pub struct Item {
    name: String,
    is_connected: bool,
    icon_opt: Option<PathBuf>,
    icon_symbolic_opt: Option<PathBuf>,
    path_opt: Option<PathBuf>,
    uri: String,
    host: String,
    port: u16,
    username: String,
    auth: AuthMethod,
    server_check: ServerCheckMethod,
}

impl Item {
    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub const fn is_connected(&self) -> bool {
        self.is_connected
    }

    pub fn uri(&self) -> String {
        self.uri.clone()
    }

    pub fn host(&self) -> String {
        self.host.clone()
    }

    pub fn icon(&self, symbolic: bool) -> Option<widget::icon::Handle> {
        if symbolic {
            self.icon_symbolic_opt.as_ref()
        } else {
            self.icon_opt.as_ref()
        }
        .map(|icon| widget::icon::from_path(icon.clone()))
    }

    pub fn path(&self) -> Option<PathBuf> {
        self.path_opt.clone()
    }
}

pub struct Russh {
    command_tx: mpsc::UnboundedSender<Cmd>,
    event_rx: Arc<Mutex<mpsc::UnboundedReceiver<Event>>>,
}

impl Russh {
    pub fn new() -> Self {
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            let rt = Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let clients = Arc::new(RwLock::new(HashMap::<String, Arc<Client>>::new()));
                let mut client_items = Vec::<ClientItem>::new();
                while let Some(command) = command_rx.recv().await {
                    match command {
                        Cmd::Items(_sizes, items_tx) => {
                            items_tx.send(client_items.clone()).await.unwrap();
                        }
                        Cmd::Rescan => {
                            event_tx.send(Event::Items(client_items.clone())).unwrap();
                        }
                        Cmd::Connect(client_item, complete_tx) => {
                            let client_item_clone = client_item.clone();
                            let ClientItem::Russh(item) = client_item else {
                                _ = complete_tx.send(Err(anyhow::anyhow!("No client item")));
                                continue;
                            };
                            let event_tx = event_tx.clone();

                            let res = Client::connect(
                                (item.host.as_str(), item.port),
                                item.username.as_str(),
                                item.auth.clone(),
                                item.server_check.clone(),
                            )
                            .await;
                            match res {
                                Ok(client) => {
                                    {
                                        let mut write = clients.write().await;
                                        write.insert(item.host.clone(), Arc::new(client));
                                    }
                                    client_items.push(ClientItem::Russh(Item {
                                        name: item.name.clone(),
                                        is_connected: true,
                                        icon_opt: item.icon_opt.clone(),
                                        icon_symbolic_opt: item.icon_symbolic_opt.clone(),
                                        path_opt: item.path_opt.clone(),
                                        uri: item.uri.clone(),
                                        host: item.host.clone(),
                                        port: item.port,
                                        username: item.username.clone(),
                                        auth: item.auth.clone(),
                                        server_check: item.server_check.clone(),
                                    }));
                                    _ = complete_tx.send(Ok(()));
                                    event_tx
                                        .send(Event::ClientResult(
                                            client_item_clone.clone(),
                                            Ok(true),
                                        ))
                                        .unwrap();
                                }
                                Err(err) => {
                                    _ = complete_tx.send(Err(anyhow::anyhow!("{err:?}")));
                                    event_tx
                                        .send(Event::ClientResult(
                                            client_item_clone,
                                            Err(format!("{err}")),
                                        ))
                                        .unwrap();
                                }
                            }
                        }
                        Cmd::RemoteDrive(uri, result_tx) => {
                            let mut result_tx_opt = Some(result_tx);
                            let event_tx = event_tx.clone();
                            let remote_file = match remote_file_from_uri(&uri) {
                                Ok(rf) => rf,
                                Err(err) => {
                                    if let Some(result_tx) = result_tx_opt.take() {
                                        _ = result_tx.send(Err(anyhow::anyhow!("{err:?}")));
                                    }
                                    let _ = event_tx.send(Event::RemoteResult(uri, Err(err.to_string())));
                                    continue;
                                }
                            };
                            let norm_uri = remote_file.uri();
                            let host = remote_file.host.as_str();
                            let port = remote_file.port;
                            let username = match remote_file.username {
                                Some(u) => u,
                                None => {
                                    let msg = "No username specified in URI";
                                    if let Some(result_tx) = result_tx_opt.take() {
                                        let _ = result_tx.send(Err(anyhow::anyhow!(msg)));
                                    }
                                    let _ = event_tx.send(Event::RemoteResult(
                                        norm_uri.clone(),
                                        Err(msg.to_string()),
                                    ));
                                    continue;
                                }
                            };
                            let auth = match get_key_files() {
                                Ok((key_path, _)) => AuthMethod::with_key_file(key_path, None),
                                Err(err) => {
                                    if let Some(result_tx) = result_tx_opt.take() {
                                        let _ = result_tx.send(Err(anyhow::anyhow!(err.to_string())));
                                    }
                                    let _ = event_tx
                                        .send(Event::RemoteResult(norm_uri.clone(), Err(err.to_string())));
                                    continue;
                                }
                            };
                            let existing_client = {
                                let read = clients.read().await;
                                read.contains_key(host)
                            };
                            let client_item = ClientItem::Russh(Item {
                                name: host.to_string(),
                                is_connected: true,
                                icon_opt: None,
                                icon_symbolic_opt: None,
                                path_opt: Some(PathBuf::from(remote_file.path.clone())),
                                uri: norm_uri.clone(),
                                host: host.to_string(),
                                port,
                                username: username.clone(),
                                auth: auth.clone(),
                                server_check: ServerCheckMethod::NoCheck,
                            });
                            if existing_client {
                                let has_item = client_items.iter().any(|item| {
                                    matches!(
                                        item,
                                        ClientItem::Russh(r) if r.host == host
                                    )
                                });
                                if !has_item {
                                    client_items.push(client_item);
                                    let _ = event_tx.send(Event::Changed);
                                }
                                if let Some(result_tx) = result_tx_opt.take() {
                                    let _ = result_tx.send(Ok(()));
                                }
                                let _ =
                                    event_tx.send(Event::RemoteResult(norm_uri.clone(), Ok(true)));
                                continue;
                            }
                            match Client::connect(
                                (host, port),
                                username.as_str(),
                                auth,
                                ServerCheckMethod::NoCheck,
                            )
                            .await
                            {
                                Ok(client) => {
                                    {
                                        let mut write = clients.write().await;
                                        write.insert(host.to_string(), Arc::new(client));
                                    }
                                    client_items.push(client_item);
                                    let _ = event_tx.send(Event::Changed);
                                    if let Some(result_tx) = result_tx_opt.take() {
                                        let _ = result_tx.send(Ok(()));
                                    }
                                    let _ = event_tx.send(Event::RemoteResult(norm_uri.clone(), Ok(true)));
                                }
                                Err(err) => {
                                    let msg = format!(
                                        "Connecting fresh session failed: {}",
                                        err
                                    );
                                    if let Some(result_tx) = result_tx_opt.take() {
                                        let _ = result_tx.send(Err(anyhow::anyhow!(msg.clone())));
                                    }
                                    let _ = event_tx
                                        .send(Event::RemoteResult(norm_uri.clone(), Err(msg.clone())));
                                }
                            }
                        }
                        Cmd::RemoteScan(uri, sizes, items_tx) => {
                            if uri == "ssh:///" {
                                let result =
                                    virtual_remote_root_items(sizes).map_err(|e| e.to_string());
                                let _ = items_tx.send(result).await;
                                continue;
                            }

                            let remote_file = match remote_file_from_uri(&uri) {
                                Ok(rf) => rf,
                                Err(e) => {
                                    let _ = items_tx.send(Err(e)).await;
                                    continue;
                                }
                            };
                            let norm_uri = remote_file.uri();
                            let host = remote_file.host.as_str();
                            let port = remote_file.port;
                            let username = match remote_file.username {
                                Some(u) => u,
                                None => {
                                    event_tx
                                        .send(Event::RemoteResult(
                                            norm_uri,
                                            Err("No username specified in URI".into()),
                                        ))
                                        .unwrap();
                                    continue;
                                }
                            };

                            let existing_client = {
                                let read = clients.read().await;
                                read.get(host).cloned()
                            };
                            if let Some(client) = existing_client {
                                let result = remote_sftp_list(&client, &norm_uri, sizes).await;
                                let _ = items_tx.send(result).await;
                            } else {
                                let key_path = match get_key_files() {
                                    Ok(key_pair) => key_pair.0,
                                    Err(e) => {
                                        event_tx
                                            .send(Event::RemoteResult(norm_uri, Err(e)))
                                            .unwrap();
                                        continue;
                                    }
                                };
                                let auth = AuthMethod::with_key_file(key_path, None);
                                match Client::connect(
                                    (host, port),
                                    username.as_str(),
                                    auth.clone(),
                                    ServerCheckMethod::NoCheck,
                                )
                                .await
                                {
                                    Ok(client) => {
                                        {
                                            let mut write = clients.write().await;
                                            write.insert(host.to_string(), Arc::new(client));
                                        }
                                        let client = {
                                            let read = clients.read().await;
                                            Arc::clone(read.get(host).unwrap())
                                        };
                                        let result =
                                            remote_sftp_list(&client, &norm_uri, sizes).await;
                                        let _ = items_tx.send(result).await;
                                        event_tx
                                            .send(Event::RemoteResult(norm_uri, Ok(true)))
                                            .unwrap();
                                    }
                                    Err(err) => {
                                        let msg = format!(
                                            "Cmd::RemoteScan: Connecting fresh session failed: {}",
                                            err
                                        );
                                        event_tx
                                            .send(Event::RemoteResult(norm_uri, Err(msg)))
                                            .unwrap();
                                    }
                                }
                            }
                        }
                        Cmd::DirInfo(uri, result_tx) => {
                            let remote_file = match remote_file_from_uri(&uri) {
                                Ok(rf) => rf,
                                Err(e) => {
                                    let _ = result_tx.send(Err(anyhow::anyhow!(e))).await;
                                    continue;
                                }
                            };
                            let host = remote_file.host.as_str();
                            let client = {
                                let read = clients.read().await;
                                match read.get(host) {
                                    Some(c) => Arc::clone(c),
                                    None => {
                                        let msg =
                                            format!("No SSH client connected for host: {}", host);
                                        let _ = result_tx.send(Err(anyhow::anyhow!(msg))).await;
                                        continue;
                                    }
                                }
                            };
                            let result = dir_info(&client, &uri)
                                .await
                                .map_err(|e| anyhow::anyhow!(e));
                            result_tx.send(result).await.unwrap();
                        }
                        Cmd::Disconnect(client_item) => {
                            log::info!("Disconnect command received");
                            let ClientItem::Russh(item) = client_item else {
                                continue;
                            };
                            {
                                let mut write = clients.write().await;
                                write.remove(&item.host);
                            }
                            client_items.retain(|ci| {
                                if let ClientItem::Russh(r) = ci {
                                    r.host != item.host
                                } else {
                                    true
                                }
                            });
                            let event_tx = event_tx.clone();
                            let _ = event_tx.send(Event::Changed);
                            log::info!("Disconnected from {}", item.host);
                        }
                    }
                }
            });
        });
        Self {
            command_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
        }
    }
}

impl Connector for Russh {
    fn items(&self, sizes: IconSizes) -> Option<ClientItems> {
        let (items_tx, mut items_rx) = mpsc::channel(1);
        self.command_tx.send(Cmd::Items(sizes, items_tx)).unwrap();
        items_rx.blocking_recv()
    }

    fn connect(&self, item: ClientItem) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::perform(
            async move {
                let (res_tx, res_rx) = tokio::sync::oneshot::channel();

                command_tx.send(Cmd::Connect(item, res_tx)).unwrap();
                res_rx.await
            },
            |x| {
                if let Err(err) = x {
                    log::error!("{err:?}");
                }
            },
        )
    }

    fn remote_drive(&self, uri: String) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::perform(
            async move {
                let (res_tx, res_rx) = tokio::sync::oneshot::channel();

                command_tx.send(Cmd::RemoteDrive(uri, res_tx)).unwrap();
                res_rx.await
            },
            |x| {
                if let Err(err) = x {
                    log::error!("{err:?}");
                }
            },
        )
    }

    fn remote_scan(&self, uri: &str, sizes: IconSizes) -> Option<Result<Vec<tab::Item>, String>> {
        let (items_tx, mut items_rx) = mpsc::channel(1);

        if let Err(e) = self
            .command_tx
            .send(Cmd::RemoteScan(uri.to_string(), sizes, items_tx))
        {
            log::error!(
                "remote_scan: failed to send Cmd::RemoteScan for uri {}: {}",
                uri,
                e
            );
            return Some(Err("command channel closed".into()));
        }

        items_rx.blocking_recv()
    }

    fn dir_info(&self, uri: &str) -> Option<(String, String, Option<PathBuf>)> {
        let (result_tx, mut result_rx) = mpsc::channel(1);
        self.command_tx
            .send(Cmd::DirInfo(uri.to_string(), result_tx))
            .unwrap();
        result_rx.blocking_recv().and_then(|res| res.ok())
    }

    fn disconnect(&self, item: ClientItem) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::perform(
            async move {
                command_tx.send(Cmd::Disconnect(item)).unwrap();
            },
            |_| {},
        )
    }

    fn subscription(&self) -> Subscription<ClientMessage> {
        let command_tx = self.command_tx.clone();
        let event_rx = self.event_rx.clone();
        Subscription::run_with_id(
            TypeId::of::<Self>(),
            stream::channel(1, |mut output| async move {
                command_tx.send(Cmd::Rescan).unwrap();
                while let Some(event) = event_rx.lock().await.recv().await {
                    match event {
                        Event::Changed => command_tx.send(Cmd::Rescan).unwrap(),
                        Event::Items(items) => {
                            output.send(ClientMessage::Items(items)).await.unwrap()
                        }
                        Event::ClientResult(item, res) => output
                            .send(ClientMessage::ClientResult(item, res))
                            .await
                            .unwrap(),
                        Event::RemoteAuth(uri, auth, auth_tx) => output
                            .send(ClientMessage::RemoteAuth(uri, auth, auth_tx))
                            .await
                            .unwrap(),
                        Event::RemoteResult(uri, res) => output
                            .send(ClientMessage::RemoteResult(uri, res))
                            .await
                            .unwrap(),
                    }
                }
                pending().await
            }),
        )
    }
}
