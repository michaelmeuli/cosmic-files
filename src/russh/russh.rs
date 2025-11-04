use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};

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

enum Cmd {
    Items(IconSizes, mpsc::Sender<ClientItems>),
    Rescan,
    Connect(ClientItem, tokio::sync::oneshot::Sender<anyhow::Result<()>>),
    NetworkScan(
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
        None
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
