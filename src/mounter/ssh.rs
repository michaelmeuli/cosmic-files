use async_ssh2_tokio::client::{self, AuthMethod, Client, ServerCheckMethod};
use cosmic::{iced::Subscription, widget, Task};
use std::{any::TypeId, collections::BTreeMap, path::PathBuf, sync::Arc};
use std::cell::Cell;
use tokio::sync::{mpsc, Mutex};

use super::{Mounter, MounterAuth, MounterItem, MounterItems, MounterMessage};
use crate::{
    config::IconSizes,
    err_str,
    tab::{self, DirSize, ItemMetadata, ItemThumbnail, Location},
};

use tokio::runtime::Handle;
use url::Url;
use russh_sftp::{client::SftpSession, protocol::OpenFlags};


#[derive(Clone, Debug)]
pub struct Item {
    host: String,
    port: u16,
    username: String,
    name: String,
    is_mounted: bool,
    icon_opt: Option<PathBuf>,
    icon_symbolic_opt: Option<PathBuf>,
    path_opt: Option<PathBuf>,
}

impl Item {
    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn is_mounted(&self) -> bool {
        self.is_mounted
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

pub struct Ssh {
    client: Arc<Mutex<Option<Client>>>,
}

impl Ssh {
    pub fn new() -> Self {
        Self {
            client: Arc::new(Mutex::new(None)),
        }
    }
}

impl Mounter for Ssh {
    fn items(&self, _sizes: IconSizes) -> Option<MounterItems> {
        let mut items = MounterItems::new();

        items.push(MounterItem::Ssh(Item {
            host: "localhost".to_string(),
            port: 22,
            username: "michael".to_string(),
            name: "Tbprofiler".to_string(),
            is_mounted: false,
            icon_opt: None,
            icon_symbolic_opt: None,
            path_opt: None,
        }));
        Some(items)
    }

    fn mount(&self, item: MounterItem) -> Task<()> {
        let client_arc = Arc::clone(&self.client);

        Task::perform(
            async move {
                if let MounterItem::Ssh(item) = item {
                    match Client::connect(
                        (item.host.as_str(), item.port),
                        item.username.as_str(),
                        AuthMethod::with_password("michael"),
                        ServerCheckMethod::NoCheck,
                    )
                    .await
                    {
                        Ok(client) => {
                            let mut guard = client_arc.lock().await;
                            *guard = Some(client);
                            println!("SSH connection stored.");
                        }
                        Err(err) => {
                            eprintln!("SSH connection failed: {:?}", err);
                        }
                    }
                } else {
                    eprintln!("Invalid MounterItem variant for SSH mount.");
                }
            },
            |_| (),
        )
    }

    fn network_drive(&self, _uri: String) -> Task<()> {
        Task::perform(async move {}, |x| x)
    }

    fn network_scan(&self, uri: &str, sizes: IconSizes) -> Option<Result<Vec<tab::Item>, String>> {
        // Only handle ssh/sftp here; otherwise say "this mounter doesn't support it".
        let url = match Url::parse(uri) {
            Ok(u) => u,
            Err(e) => return Some(Err(format!("bad uri: {e}"))),
        };
        match url.scheme() {
            "ssh" | "sftp" => {}
            _ => return None, // let other mounters try
        }

        // Non-blocking check for a live client.
        let client_opt = match self.client.try_lock() {
            Ok(g) => g.clone(), // Option<Client>
            Err(_) => None,     // busy; treat as not connected here
        };
        let Some(client) = client_opt else {
            return Some(Err("SSH not connected".into()));
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
                channel.request_subsystem(true, "sftp").await.map_err(|e| e.to_string())?;
                let sftp = SftpSession::new(channel.into_stream()).await.map_err(|e| e.to_string())?;

                let entries = sftp
                    .read_dir(&path)
                    .await
                    .map_err(|e| format!("read_dir {path}: {e:?}"))?;

                // 4) Map to tab::Item
                let mut items = Vec::new();
                for entry in entries {
                    let child_path = PathBuf::from(entry.file_name());
                    let stat = entry.metadata();

                    let name = child_path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string();

                    let is_dir = stat.is_dir(); // adapt to your API

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

                    let icon = |sz| {
                        widget::icon::from_name(if is_dir { "folder" } else { "text-x-generic" })
                            .size(sz)
                            .handle()
                    };

                    let metadata = if is_dir {
                        ItemMetadata::SimpleDir { entries: 0 }
                    } else {
                        ItemMetadata::GvfsPath {
                            mtime: stat.mtime.unwrap_or(0) as u64,
                            size_opt: stat.size.map(|s| s as u64),
                            children_opt: None,
                        }
                    };

                    items.push(tab::Item {
                        name: name.clone(),
                        is_mount_point: false,
                        display_name: name,
                        metadata,
                        hidden: false,
                        location_opt: Some(location),
                        mime: "inode/directory".parse().unwrap(), // tweak if you compute real mime
                        icon_handle_grid: icon(sizes.grid()),
                        icon_handle_list: icon(sizes.list()),
                        icon_handle_list_condensed: icon(sizes.list_condensed()),
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

    fn unmount(&self, item: MounterItem) -> Task<()> {
        Task::perform(async move {}, |x| x)
    }

    fn subscription(&self) -> Subscription<MounterMessage> {
        Subscription::none()
    }
}
