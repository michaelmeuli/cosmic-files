use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};
use cosmic::{
    iced::{futures::SinkExt, stream, Subscription},
    widget, Task,
};
use dashmap::DashMap;
use std::{any::TypeId, cell::Cell, future::pending, path::PathBuf, sync::Arc};

use super::{Mounter, MounterAuth, MounterItem, MounterItems, MounterMessage};
use crate::{
    config::IconSizes,
    mounter::ssh,
    tab::{self, DirSize, ItemMetadata, ItemThumbnail, Location},
};

use russh_sftp::client::SftpSession;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, Mutex};
use url::Url;
use crate::home_dir;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EndpointKey(String); // e.g. "ssh://user@host:22"

fn endpoint_key_from_uri(uri: &str) -> Option<EndpointKey> {
    let url = url::Url::parse(uri).ok()?;
    if url.scheme() != "ssh" && url.scheme() != "sftp" {
        return None;
    }
    let user = url.username();
    let host = url.host_str()?;
    let port = url.port().unwrap_or(22);
    let auth = if user.is_empty() {
        format!("{host}:{port}")
    } else {
        format!("{user}@{host}:{port}")
    };
    Some(EndpointKey(format!("ssh://{auth}")))
}

//                                                  Option<Result<Vec<tab::Item>, String>>
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
        let location = Location::Ssh(uri, display_name.clone());

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

enum Cmd {
    Items(IconSizes, mpsc::Sender<MounterItems>),
    Rescan,
    Mount(
        MounterItem,
        tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    ),
    NetworkDrive(String, tokio::sync::oneshot::Sender<anyhow::Result<()>>),
    NetworkScan(
        String,
        IconSizes,
        mpsc::Sender<Result<Vec<tab::Item>, String>>,
    ),
    Unmount(MounterItem),
}

enum Event {
    Changed,
    Items(MounterItems),
    MountResult(MounterItem, Result<bool, String>),
    NetworkAuth(String, MounterAuth, mpsc::Sender<MounterAuth>),
    NetworkResult(String, Result<bool, String>),
}

#[derive(Clone, Debug)]
pub struct Item {
    uri: String,
    name: String,
    is_connected: bool,
    icon_opt: Option<PathBuf>,
    icon_symbolic_opt: Option<PathBuf>,
}

impl Item {
    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    pub fn set_connected(&mut self, connected: bool) {
        self.is_connected = connected;
    }

    pub fn uri(&self) -> String {
        self.uri.clone()
    }

    pub fn icon(&self, symbolic: bool) -> Option<widget::icon::Handle> {
        if symbolic {
            self.icon_symbolic_opt.as_ref()
        } else {
            self.icon_opt.as_ref()
        }
        .map(|icon| widget::icon::from_path(icon.clone()))
    }
}

pub struct Ssh {
    sessions: Arc<DashMap<EndpointKey, Arc<Client>>>,
    command_tx: mpsc::UnboundedSender<Cmd>,
    event_rx: Arc<Mutex<mpsc::UnboundedReceiver<Event>>>,
}

impl Ssh {
    pub fn new() -> Self {
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Self {
            sessions: Arc::new(DashMap::new()),
            command_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
        }
    }

    pub fn has_session(&self, key: &EndpointKey) -> bool {
        self.sessions.contains_key(key)
    }

    fn get_session(&self, key: &EndpointKey) -> Option<Arc<Client>> {
        self.sessions.get(key).map(|r| r.clone())
    }

    // TODO:somehow use MounterAuth instead of MounterItem?
    fn connect(&self, mut item: MounterItem) -> Task<()> {
        let sessions = self.sessions.clone();
        Task::perform(
            async move {
                let it: &mut ssh::Item = match &mut item {
                    MounterItem::Ssh(ref mut it) => it,
                    _ => return,
                };
                let url = match url::Url::parse(&it.uri) {
                    Ok(parsed_url) => parsed_url,
                    Err(_) => return,
                };
                if url.scheme() != "ssh" && url.scheme() != "sftp" {
                    return;
                }
                let user = url.username();
                let host = url.host_str();
                let port = url.port().unwrap_or(22);
                let key = EndpointKey(format!(
                    "ssh://{}@{}:{}",
                    user,
                    host.unwrap_or("unknown_host"),
                    port
                ));

                let key_path = home_dir()
                    .join(".ssh")
                    .join("id_rsa");
                let auth_method = AuthMethod::with_key_file(key_path, None);
                let client = Client::connect(
                    (host.unwrap_or("unknown_host"), port),
                    user,
                    auth_method,
                    ServerCheckMethod::NoCheck,
                )
                .await
                .map(Arc::new);

                // If you need to update is_connected, you must make item mutable and pass ownership.
                // Otherwise, remove this block or handle connection state elsewhere.
                it.set_connected(true);

                match client {
                    Ok(cli) => {
                        sessions.insert(key, cli);
                    }
                    Err(err) => {
                        log::warn!("ssh mount failed: {err:?}");
                    }
                }
            },
            |_| (),
        )
    }
}

impl Mounter for Ssh {
    fn items(&self, _sizes: IconSizes) -> Option<MounterItems> {
        let mut items = MounterItems::new();

        items.push(MounterItem::Ssh(Item {
            uri: "ssh://michael@localhost:22/".to_string(),
            name: "Tbprofiler".to_string(),
            is_connected: false,
            icon_opt: None,
            icon_symbolic_opt: None,
        }));
        Some(items)
    }

    fn mount(&self, item: MounterItem) -> Task<()> {
        self.connect(item)
    }

    fn network_drive(&self, _uri: String) -> Task<()> {
        Task::perform(async move {}, |x| x)
    }

    fn network_scan(&self, uri: &str, sizes: IconSizes) -> Option<Result<Vec<tab::Item>, String>> {
        let sessions = self.sessions.clone();
        if uri == "ssh:///" {
            return Some(virtual_network_root_items(sizes));
        }

        let url = match Url::parse(uri) {
            Ok(u) => u,
            Err(e) => return Some(Err(format!("bad uri: {e}"))),
        };
        match url.scheme() {
            "ssh" | "sftp" => {}
            _ => return None,
        }

        let endpoint_key = endpoint_key_from_uri(uri)?;
        let client_opt = self.sessions.get(&endpoint_key).map(|entry| entry.clone());
        let client = match client_opt {
            Some(client) => client,
            None => {
                // TODO: get auth from keyring/UI. Password shown only as example.
                // Run async connect in a blocking context
                let client_result = tokio::task::block_in_place(|| {
                    let user = url.username();
                    let host = url.host_str();
                    let port = url.port().unwrap_or(22);
                    let handle = Handle::current();
                    handle.block_on(Client::connect(
                        (host.unwrap_or("unknown_host"), port),
                        user,
                        AuthMethod::with_password("your_password_here"),
                        ServerCheckMethod::NoCheck,
                    ))
                })
                .map(Arc::new);

                match client_result {
                    Ok(cli) => {
                        let key = endpoint_key_from_uri(uri)?;
                        sessions.insert(key, cli.clone());
                        cli
                    }
                    Err(err) => {
                        log::warn!("ssh mount failed: {err:?}");
                        return Some(Err(format!("ssh mount failed: {err:?}")));
                    }
                }
            }
        };

        // From here: do async SFTP work by *blocking* inside this sync fn.
        let res: Result<Vec<tab::Item>, String> = tokio::task::block_in_place(|| {
            let handle = Handle::current();
            handle.block_on(async {
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
                    .read_dir(&path)
                    .await
                    .map_err(|e| format!("read_dir {path}: {e:?}"))?;

                let mut items = Vec::new();
                for entry in entries {
                    let child_path = PathBuf::from(entry.file_name());
                    let stat = entry.metadata();

                    let name = child_path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string();

                    let is_dir = stat.is_dir();

                    let child_uri = {
                        // Rebuild user@host[:port]
                        let mut auth = String::new();
                        if let Some(user) =
                            url.username().strip_prefix("").filter(|u| !u.is_empty())
                        {
                            auth.push_str(user);
                            if let Some(pass) = url.password() {
                                let _ = pass; // avoid embedding password in URIs
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

                    let metadata = if is_dir {
                        ItemMetadata::SimpleDir { entries: 0 }
                    } else {
                        ItemMetadata::SimpleFile { size: 0 }
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
                            //TODO: get mime from content_type?
                            "inode/directory".parse().unwrap(),
                            file_icon(sizes.grid()),
                            file_icon(sizes.list()),
                            file_icon(sizes.list_condensed()),
                        )
                    };

                    items.push(tab::Item {
                        name: name.clone(),
                        is_mount_point: false,
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
            })
        });

        Some(res)
    }

    fn unmount(&self, _item: MounterItem) -> Task<()> {
        Task::perform(async move {}, |x| x)
    }

    fn subscription(&self) -> Subscription<MounterMessage> {
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
                            output.send(MounterMessage::Items(items)).await.unwrap()
                        }
                        Event::MountResult(item, res) => output
                            .send(MounterMessage::MountResult(item, res))
                            .await
                            .unwrap(),
                        Event::NetworkAuth(uri, auth, auth_tx) => output
                            .send(MounterMessage::NetworkAuth(uri, auth, auth_tx))
                            .await
                            .unwrap(),
                        Event::NetworkResult(uri, res) => output
                            .send(MounterMessage::NetworkResult(uri, res))
                            .await
                            .unwrap(),
                    }
                }
                pending().await
            }),
        )
    }
}
