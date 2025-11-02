use async_ssh2_tokio::client::{Client, AuthMethod, ServerCheckMethod};

use cosmic::{
    Task,
    iced::{Subscription, futures::SinkExt, stream},
    widget,
};
use gio::{glib, prelude::*};
use std::{any::TypeId, cell::Cell, future::pending, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, mpsc};

use super::{Connector, ClientAuth, ClientItem, ClientItems, MounterMessage};
use crate::{
    config::IconSizes,
    err_str,
    tab::{self, DirSize, ItemMetadata, ItemThumbnail, Location},
};


pub struct Russh {}

impl Russh {
    pub fn new() -> Self {
        Russh {}
    }
}

impl Connector for Russh {

    fn connect(&self, item: ClientItem) -> Task<()> {
        async move {}
    }

    fn network_scan(&self, uri: &str, sizes: IconSizes) -> Option<Result<Vec<tab::Item>, String>> {
        None
    }
}