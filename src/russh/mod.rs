use cosmic::{Task, iced::Subscription, widget};
use std::{
    collections::BTreeMap,
    fmt,
    path::PathBuf,
    sync::{Arc, LazyLock},
};
use tokio::sync::mpsc;

use crate::{config::IconSizes, tab};

#[cfg(feature = "russh")]
mod russh;


#[derive(Clone, Debug)]
pub enum ClientItem {
    #[cfg(feature = "russh")]
    Russh(russh::Item),
    #[allow(dead_code)]
    None,
}

impl ClientItem {
    pub fn name(&self) -> String {
        match self {
            #[cfg(feature = "russh")]
            Self::Russh(item) => item.name(),
            Self::None => unreachable!(),
        }
    }

    pub fn uri(&self) -> String {
        match self {
            #[cfg(feature = "russh")]
            Self::Russh(item) => item.uri(),
            Self::None => unreachable!(),
        }
    }

    pub fn is_mounted(&self) -> bool {
        match self {
            #[cfg(feature = "russh")]
            Self::Russh(item) => item.is_mounted(),
            Self::None => unreachable!(),
        }
    }

    pub fn icon(&self, symbolic: bool) -> Option<widget::icon::Handle> {
        match self {
            #[cfg(feature = "russh")]
            Self::Russh(item) => item.icon(symbolic),
            Self::None => unreachable!(),
        }
    }

    pub fn path(&self) -> Option<PathBuf> {
        match self {
            #[cfg(feature = "russh")]
            Self::Russh(item) => item.path(),
            Self::None => unreachable!(),
        }
    }
}

pub type ClientItems = Vec<ClientItem>;

#[derive(Clone, Debug)]
pub enum ClientMessage {
    Items(ClientItems),
    ClientResult(ClientItem, Result<bool, String>),
    RemoteAuth(String, ClientAuth, mpsc::Sender<ClientAuth>),
    RemoteResult(String, Result<bool, String>),
}


pub trait Connector: Send + Sync {
    fn connect(&self, item: ClientItem) -> Task<()>;
    fn network_scan(&self, uri: &str, sizes: IconSizes) -> Option<Result<Vec<tab::Item>, String>>;
    fn subscription(&self) -> Subscription<ClientMessage>;
}


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClientKey(pub &'static str);
pub type ClientMap = BTreeMap<ClientKey, Box<dyn Connector>>;
pub type Clients = Arc<ClientMap>;

pub fn clients() -> Clients {
    #[allow(unused_mut)]
    let mut clients = ClientMap::new();

    #[cfg(feature = "russh")]
    {
        clients.insert(ClientKey("russh"), Box::new(russh::Russh::new()));
    }

    Clients::new(clients)
}

pub static CLIENTS: LazyLock<Clients> = LazyLock::new(clients);