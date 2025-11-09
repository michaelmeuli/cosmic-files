use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};
use russh_sftp::client::SftpSession;
use url::Url;

use cctk::{cosmic_protocols::corner_radius::v1::client, sctk::reexports::calloop::channel};
use cosmic::{
    Task,
    iced::{Subscription, futures::SinkExt, stream},
    widget,
};
use gio::{glib, prelude::*};
use std::{any::TypeId, cell::Cell, future::pending, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, mpsc};

use super::{ClientAuth, ClientItem, ClientItems, ClientMessage, Connector};
use crate::{
    config::IconSizes,
    err_str, home_dir,
    tab::{self, DirSize, ItemMetadata, ItemThumbnail, Location},
};
use tokio::runtime::Builder;

fn items(sizes: IconSizes) -> ClientItems {
    let key_path = home_dir().join(".ssh").join("id_rsa");
    let auth_method = AuthMethod::with_key_file(key_path, None);
    let mut items = ClientItems::new();
    items.push(ClientItem::Russh(Item {
        name: "S3IT".to_string(),
        is_connected: false,
        icon_opt: None,
        icon_symbolic_opt: None,
        path_opt: None,
        uri: "130.60.24.133".to_string(),
        port: 22,
        username: "mimeul".to_string(),
        auth: auth_method,
        server_check: ServerCheckMethod::NoCheck,
        client: None,
    }));
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
    // Open a channel
    let channel = client.get_channel().await.map_err(|e| e.to_string())?;

    let url = Url::parse(uri).map_err(|e| format!("bad uri: {e}"))?;

    let mut path = url.path().to_string();
    if path.is_empty() {
        path = "/".into();
    }

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| e.to_string())?;

    let entries = sftp
        .read_dir(path.clone())
        .await
        .map_err(|e| format!("read_dir {path}: {e:?}"))?;

    let mut out_items = Vec::new();

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
            if let Some(user) = url.username().strip_prefix("").filter(|u| !u.is_empty()) {
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
                // TODO: get mime from content_type?
                "inode/directory".parse().unwrap(),
                file_icon(sizes.grid()),
                file_icon(sizes.list()),
                file_icon(sizes.list_condensed()),
            )
        };

        out_items.push(tab::Item {
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

    Ok(out_items)
}

enum Cmd {
    Items(IconSizes, mpsc::Sender<ClientItems>),
    Rescan,
    Connect(ClientItem, tokio::sync::oneshot::Sender<anyhow::Result<()>>),
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
    port: u16,
    username: String,
    auth: AuthMethod,
    server_check: ServerCheckMethod,
    client: Option<Client>,
}

impl Item {
    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected
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

    pub fn path(&self) -> Option<PathBuf> {
        self.path_opt.clone()
    }

    pub fn client(&self) -> Option<Client> {
        self.client.clone()
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
                tokio::task::spawn_local(async move {
                    while let Some(command) = command_rx.recv().await {
                        match command {
                            Cmd::Items(sizes, items_tx) => {
                                items_tx.send(items(sizes)).await.unwrap();
                            }
                            Cmd::Rescan => {
                                event_tx
                                    .send(Event::Items(items(IconSizes::default())))
                                    .unwrap();
                            }
                            Cmd::Connect(client_item, complete_tx) => {
                                let ClientItem::Russh(ref mut item) = client_item else {
                                    _ = complete_tx.send(Err(anyhow::anyhow!("No client item")));
                                    continue;
                                };
                                let event_tx = event_tx.clone();
                                let client_item = client_item.clone();
                                let res = Client::connect(
                                    (item.uri.as_str(), item.port),
                                    item.username.as_str(),
                                    item.auth.clone(),
                                    item.server_check.clone(),
                                )
                                .await;
                                match res {
                                    Ok(client) => {
                                        item.is_connected = true;
                                        item.client = Some(client);
                                        _ = complete_tx.send(Ok(()));
                                        event_tx
                                            .send(Event::ClientResult(client_item, Ok(true)))
                                            .unwrap();
                                    }
                                    Err(err) => {
                                        let err_str = err_str(&err);
                                        _ = complete_tx.send(Err(err.into()));
                                        event_tx
                                            .send(Event::ClientResult(client_item, Err(err_str)))
                                            .unwrap();
                                    }
                                }
                            }
                            Cmd::RemoteScan(uri, sizes, items_tx) => {
                                let items = items(IconSizes::default());

                                for item in items {
                                    match item.client() {
                                        Some(client) => {
                                            match remote_sftp_list(&client, &uri, sizes).await {
                                                Ok(remote_items) => {
                                                    items_tx.send(Ok(remote_items)).await;
                                                }
                                                Err(e) => {
                                                    items_tx.send(Err(e)).await;
                                                }
                                            }
                                        }
                                        None => {
                                            items_tx
                                                .send(Err("no client available for remote scan"
                                                    .to_string()))
                                                .await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            });
        });
        Self {
            command_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
        }
    }
}

impl Connector for Russh {
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

    fn remote_scan(&self, uri: &str, sizes: IconSizes) -> Option<Result<Vec<tab::Item>, String>> {
        let (items_tx, mut items_rx) = mpsc::channel(1);
        self.command_tx
            .send(Cmd::RemoteScan(uri.to_string(), sizes, items_tx))
            .unwrap();
        items_rx.blocking_recv()
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
