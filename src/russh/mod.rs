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


pub trait FilesClient: Send + Sync {
    fn connect(&self, item: ClientItem) -> Task<()>;
    fn network_scan(&self, uri: &str, sizes: IconSizes) -> Option<Result<Vec<tab::Item>, String>>;
}


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClientKey(pub &'static str);
pub type ClientMap = BTreeMap<ClientKey, Box<dyn FilesClient>>;
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