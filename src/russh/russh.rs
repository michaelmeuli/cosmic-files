use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};
use russh_sftp::client::SftpSession;
use url::Url;

use cosmic::{
    Task,
    iced::{Subscription, futures::SinkExt, stream},
    widget,
};
use std::{
    any::TypeId, cell::Cell, collections::HashMap, future::pending, path::PathBuf, sync::Arc,
};
use tokio::sync::{Mutex, RwLock, mpsc};

use super::{ClientAuth, ClientItem, ClientItems, ClientMessage, Connector};
use crate::{
    config::IconSizes,
    home_dir,
    tab::{self, DirSize, ItemMetadata, ItemThumbnail, Location},
};
use tokio::runtime::Builder;

pub fn normalize_ssh_uri(raw: &str) -> Result<String, String> {
    let url = Url::parse(raw).map_err(|e| format!("invalid ssh uri: {e}"))?;
    if url.scheme() != "ssh" {
        return Err("URI must use ssh://".into());
    }
    let user = match url.username() {
        "" => None,
        u => Some(u),
    };
    let host = url.host_str().unwrap_or("localhost");
    let port = url.port().unwrap_or(22);
    let mut path = url.path().to_string();
    if path.is_empty() {
        path = "/".into();
    }
    // Prevent duplicate slashes (avoid ssh:////path)
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    // Remove trailing slash except for root
    if path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    let normalized = if let Some(user) = user {
        format!("ssh://{}@{}:{}{}", user, host, port, path)
    } else {
        format!("ssh://{}:{}{}", host, port, path)
    };
    Ok(normalized)
}

fn items(keys: Vec<String>, _sizes: IconSizes) -> ClientItems {
    let mut items = ClientItems::new();
    for host in keys {
        items.push(ClientItem::Russh(Item {
            name: host.clone(),
            is_connected: true,
            icon_opt: None,
            icon_symbolic_opt: None,
            path_opt: None,
            uri: format!("ssh://{host}:22/"),
            host,
            port: 22,
            username: "michael".to_string(),
            auth: AuthMethod::with_key_file(home_dir().join(".ssh").join("id_ed25519"), None),
            server_check: ServerCheckMethod::NoCheck,
        }));
    }
    items
}

fn virtual_network_root_items(sizes: IconSizes) -> Result<Vec<tab::Item>, String> {
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
        let location = Location::Remote(uri, display_name.clone(), None);

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

async fn remote_sftp_list(
    client: &Client,
    uri: &str,
    sizes: IconSizes,
) -> Result<Vec<tab::Item>, String> {
    log::info!("remote_sftp_list: listing uri {}", uri);
    let force_dir = uri.starts_with("ssh:///");
    let url = Url::parse(uri).map_err(|e| format!("bad uri: {e}"))?;
    let mut path = url.path().to_string();
    if path.is_empty() {
        path = "/".into();
    }
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
        let name = child_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let child_uri = {
            let mut auth = String::new();
            if let Some(user) = url.username().strip_prefix("").filter(|u| !u.is_empty()) {
                auth.push_str(user);
                if let Some(pass) = url.password() {
                    let _ = pass;
                }
                auth.push('@');
            }
            let hostport = match (url.host_str(), url.port()) {
                (Some(h), Some(p)) => format!("{h}:{p}"),
                (Some(h), None) => h.to_string(),
                _ => "localhost".into(),
            };
            format!(
                "{}://{}{}",
                url.scheme(),
                auth + &hostport,
                child_path.to_string_lossy()
            )
        };
        let location = Location::Network(child_uri, name.clone(), None);

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
            ItemMetadata::GvfsPath {
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

        items.push(tab::Item {
            name: name.clone(),
            is_mount_point: false,
            is_client_point: true,
            display_name: name,
            metadata,
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
                let client_items = Vec::<ClientItem>::new();
                while let Some(command) = command_rx.recv().await {
                    match command {
                        Cmd::Items(sizes, items_tx) => {
                            let keys: Vec<String> = {
                                let read = clients.read().await;
                                read.keys().cloned().collect()
                            };
                            log::info!("Russh: Items - clients: {:?}", keys);
                            items_tx.send(client_items.clone()).await.unwrap();
                        }
                        Cmd::Rescan => {
                            let keys: Vec<String> = {
                                let read = clients.read().await;
                                read.keys().cloned().collect()
                            };
                            log::info!("Russh: Rescan - clients: {:?}", keys);
                            event_tx
                                .send(Event::Items(client_items.clone()))
                                .unwrap();
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
                                    log::info!("russh.rs: Connected to {} OK", item.host);
                                    {
                                        let mut write = clients.write().await;
                                        write.insert(item.host.clone(), Arc::new(client));
                                    }
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
                            log::info!("Cmd::RemoteDrive: connecting to uri {}", uri);
                            let mut result_tx_opt = Some(result_tx);
                            let event_tx = event_tx.clone();

                            let norm_uri = normalize_ssh_uri(&uri).unwrap_or(uri);
                            let norm_uri_clone = norm_uri.clone();
                            let url = Url::parse(&norm_uri).unwrap();
                            let host = url.host_str().unwrap_or("localhost");
                            let port = url.port().unwrap_or(22);
                            let username = url.username();

                            let existing_client = {
                                let read = clients.read().await;
                                read.get(host).cloned()
                            };

                            if let Some(_) = existing_client {
                                log::info!(
                                    "Cmd::RemoteDrive: Client already exists for host {}",
                                    host
                                );
                                if let Some(tx) = result_tx_opt.take() {
                                    let _ = tx.send(Ok(()));
                                }
                                event_tx
                                    .send(Event::RemoteResult(norm_uri_clone, Ok(true)))
                                    .unwrap();
                                return;
                            }

                            log::info!("Cmd::RemoteDrive: Connecting fresh session to {}", host);
                            let key_path = home_dir().join(".ssh").join("id_ed25519");
                            let auth = AuthMethod::with_key_file(key_path, None);
                            match Client::connect(
                                (host, port),
                                username,
                                auth,
                                ServerCheckMethod::NoCheck,
                            )
                            .await
                            {
                                Ok(client) => {
                                    log::info!("Cmd::RemoteDrive: Connected OK {}", host);
                                    {
                                        let mut write = clients.write().await;
                                        write.insert(host.to_string(), Arc::new(client));
                                    }
                                    if let Some(tx) = result_tx_opt.take() {
                                        let _ = tx.send(Ok(()));
                                    }
                                    event_tx
                                        .send(Event::RemoteResult(norm_uri_clone, Ok(true)))
                                        .unwrap();
                                    event_tx.send(Event::Changed).unwrap();
                                }
                                Err(err) => {
                                    let msg = format!("SSH connect failed: {}", err);
                                    if let Some(tx) = result_tx_opt.take() {
                                        let _ = tx.send(Err(anyhow::anyhow!(msg.clone())));
                                    }
                                    event_tx
                                        .send(Event::RemoteResult(norm_uri_clone, Err(msg)))
                                        .unwrap();
                                }
                            }
                        }
                        Cmd::RemoteScan(uri, sizes, items_tx) => {
                            log::info!("RemoteScan: scanning uri {}", uri);
                            if uri == "ssh:///" {
                                let result =
                                    virtual_network_root_items(sizes).map_err(|e| e.to_string());
                                let _ = items_tx.send(result).await;
                                continue;
                            }
                            let norm_uri = normalize_ssh_uri(&uri).unwrap_or(uri);
                            let url = Url::parse(&norm_uri).unwrap();
                            let host = url.host_str().unwrap_or("localhost");
                            log::info!("RemoteScan: normalized uri {}, host {}", norm_uri, host);
                            let client = {
                                let read = clients.read().await;
                                match read.get(host) {
                                    Some(c) => Arc::clone(c), // clone Arc<Client>
                                    None => {
                                        let msg =
                                            format!("No SSH client connected for host: {}", host);
                                        let _ = items_tx.send(Err(msg)).await;
                                        continue;
                                    }
                                }
                            };
                            let result = remote_sftp_list(&client, &norm_uri, sizes).await;
                            let _ = items_tx.send(result).await;
                        }
                        Cmd::Disconnect(client_item) => {
                            let ClientItem::Russh(mut item) = client_item else {
                                continue;
                            };
                            {
                                let mut write = clients.write().await;
                                write.remove(&item.host);
                            }
                            item.is_connected = false;
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
        self.command_tx
            .send(Cmd::RemoteScan(uri.to_string(), sizes, items_tx))
            .unwrap();
        items_rx.blocking_recv()
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
