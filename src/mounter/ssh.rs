use async_ssh2_tokio::client::{Client, AuthMethod, ServerCheckMethod};
use cosmic::{iced::Subscription, widget, Task};
use std::{any::TypeId, collections::BTreeMap, path::PathBuf, sync::Arc};
use tokio::sync::{mpsc, Mutex};

use super::{Mounter, MounterAuth, MounterItem, MounterItems, MounterMessage};
use crate::{
    config::IconSizes,
    err_str,
    tab::{self, DirSize, ItemMetadata, ItemThumbnail, Location},
};




pub async fn get_raw_reads(
    client: &Client,
    config: &TbguiConfig,
) -> Result<RemoteState, async_ssh2_tokio::Error> {
    let remote_raw_dir: &str = config.remote_raw_dir.as_str();
    check_if_dir_exists(client, remote_raw_dir).await?;
    let command = format!("ls {}", remote_raw_dir);
    let result = client.execute(&command).await.map_err(|e| {
        log_error(&format!(
            "Failed to list files in remote directory: {:?}",
            e
        ));
        async_ssh2_tokio::Error::from(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to list files in remote directory: {:?}", e),
        ))
    })?;
    let stdout = result.stdout;

    let raw_reads: Vec<String> = stdout.lines().map(String::from).collect();
    let tasks = create_tasks(raw_reads);
    Ok(RemoteState { items: tasks })
}

fn network_scan(uri: &str, sizes: IconSizes) -> Result<Vec<tab::Item>, String> {
    let file = gio::File::for_uri(uri);
    let mut items = Vec::new();
    for info_res in file
        .enumerate_children("*", gio::FileQueryInfoFlags::NONE, gio::Cancellable::NONE)
        .map_err(err_str)?
    {
        let info = info_res.map_err(err_str)?;
        let name = info.name().to_string_lossy().to_string();
        let display_name = info.display_name().to_string();

        //TODO: what is the best way to resolve shortcuts?
        let location = Location::Network(
            if let Some(target_uri) = info.attribute_string(gio::FILE_ATTRIBUTE_STANDARD_TARGET_URI)
            {
                target_uri.to_string()
            } else {
                file.child(info.name()).uri().to_string()
            },
            display_name.clone(),
        );

        //TODO: support dir or file
        let metadata = ItemMetadata::SimpleDir { entries: 0 };

        let (mime, icon_handle_grid, icon_handle_list, icon_handle_list_condensed) = {
            let file_icon = |size| {
                info.icon()
                    .as_ref()
                    .and_then(|icon| gio_icon_to_path(icon, size))
                    .map(widget::icon::from_path)
                    .unwrap_or(
                        widget::icon::from_name(if metadata.is_dir() {
                            "folder"
                        } else {
                            "text-x-generic"
                        })
                        .size(size)
                        .handle(),
                    )
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
            name,
            display_name,
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
            //TODO: scan directory size on gvfs mounts?
            dir_size: DirSize::NotDirectory,
            cut: false,
        });
    }
    Ok(items)
}



#[derive(Clone, Debug)]
pub struct Item {
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
    client: Arc<Mutex<Client>>,
}

impl Ssh {
    pub async fn new() -> Self {
        let client = Client::connect(
            ("localhost", 22),
            "root",
            AuthMethod::with_password("root"),
            ServerCheckMethod::NoCheck,
        ).await.unwrap();

        Self {
            client: Arc::new(Mutex::new(client)),
        }
    }
}

impl Mounter for Ssh {
    fn items(&self, sizes: IconSizes) -> Option<MounterItems> {
        let mut items = MounterItems::new();
        items.push(MounterItem::Ssh(Item {
            name: "Tbprofiler".to_string(),
            is_mounted: true,
            icon_opt: None,
            icon_symbolic_opt: None,
            path_opt: None,
        }));
        Some(items)
    }

    fn mount(&self, item: MounterItem) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::perform(
            async move {
                command_tx.send(Cmd::Mount(item)).unwrap();
            },
            |x| x,
        )
    }


    fn network_drive(&self, uri: String) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::perform(
            async move {
                command_tx.send(Cmd::NetworkDrive(uri)).unwrap();
            },
            |x| x,
        )
    }

    fn network_scan(&self, uri: &str, sizes: IconSizes) -> Option<Result<Vec<tab::Item>, String>> {
        let (items_tx, mut items_rx) = mpsc::channel(1);
        self.command_tx
            .send(Cmd::NetworkScan(uri.to_string(), sizes, items_tx))
            .unwrap();
        items_rx.blocking_recv()
    }

    fn unmount(&self, item: MounterItem) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::perform(
            async move {
                command_tx.send(Cmd::Unmount(item)).unwrap();
            },
            |x| x,
        )
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