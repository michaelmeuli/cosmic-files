use cosmic::{Task, iced::Subscription, widget};
use std::{
    collections::BTreeMap,
    fmt,
    path::PathBuf,
    sync::{Arc, LazyLock},
};
use tokio::sync::mpsc;

use crate::{config::IconSizes, config::TBConfig, russh::russh::RemoteFile, tab};

pub(crate) mod jsondata;
#[cfg(feature = "russh")]
mod russh;

pub fn same_uri(a: &str, b: &str) -> bool {
    let Ok(a_file) = a.parse::<RemoteFile>() else {
        return false;
    };
    let Ok(b_file) = b.parse::<RemoteFile>() else {
        return false;
    };

    a_file.host == b_file.host && a_file.username == b_file.username && a_file.port == b_file.port
}

#[derive(Clone)]
pub struct ClientAuth {
    pub message: String,
    pub username_opt: Option<String>,
    pub domain_opt: Option<String>,
    pub password_opt: Option<String>,
    pub remember_opt: Option<bool>,
    pub anonymous_opt: Option<bool>,
}

// Custom debug for ClientAuth to hide password
impl fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientAuth")
            .field("username_opt", &self.username_opt)
            .field("domain_opt", &self.domain_opt)
            .field(
                "password_opt",
                if self.password_opt.is_some() {
                    &"Some(*)"
                } else {
                    &"None"
                },
            )
            .field("remember_opt", &self.remember_opt)
            .field("anonymous_opt", &self.anonymous_opt)
            .finish()
    }
}

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

    pub fn host(&self) -> String {
        match self {
            #[cfg(feature = "russh")]
            Self::Russh(item) => item.host(),
            Self::None => unreachable!(),
        }
    }

    pub fn is_connected(&self) -> bool {
        match self {
            #[cfg(feature = "russh")]
            Self::Russh(item) => item.is_connected(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct SlurmJobId {
    pub array_id: usize,
    pub tasks: usize,
    pub running_tasks: usize,
}

#[derive(Clone, Debug)]
pub enum ClientMessage {
    Items(ClientItems),
    ClientResult(ClientItem, Result<bool, String>),
    RemoteAuth(String, ClientAuth, mpsc::Sender<ClientAuth>),
    RemoteResult(String, Result<bool, String>),
    RunTbProfilerResult(String, Result<SlurmJobId, String>),
    DeleteRemoteFilesResult(String, Result<String, String>),
    JobStatusUpdate(String, usize, usize),
}

pub trait Connector: Send + Sync {
    fn items(&self, sizes: IconSizes) -> Option<ClientItems>;
    fn connect(&self, item: ClientItem) -> Task<()>;
    fn remote_drive(&self, uri: String) -> Task<()>;
    fn remote_scan(
        &self,
        uri: &str,
        sizes: IconSizes,
    ) -> Option<Result<Vec<tab::Item>, String>>;
    fn remote_parent_item(&self, uri: &str, sizes: IconSizes) -> Option<Result<tab::Item, String>>;
    fn dir_info(&self, uri: &str) -> Option<(String, String, Option<PathBuf>)>;
    fn disconnect(&self, item: ClientItem) -> Task<()>;
    fn download_file(&self, paths: Box<[PathBuf]>, uris: Vec<String>, to: PathBuf) -> Task<()>;
    fn run_tb_profiler(
        &self,
        paths: Box<[PathBuf]>,
        uris: Vec<String>,
        tb_config: TBConfig,
    ) -> Task<()>;
    fn delete_remote_files(&self, paths: Box<[PathBuf]>, uris: Vec<String>) -> Task<()>;
    fn delete_tb_profiler_results(&self, uri: String, tb_config: TBConfig) -> Task<()>;
    fn poll_job_status(&self, job_id: usize, uri: String) -> Task<()>;
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
