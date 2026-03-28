use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::FileType;
use url::Url;

use cosmic::{
    Task,
    iced::{Subscription, futures::SinkExt, stream},
    widget,
};
use std::{
    any::TypeId,
    cell::Cell,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    future::pending,
    hash::Hash,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock, mpsc};

use super::{ClientAuth, ClientItem, ClientItems, ClientMessage, Connector};

use crate::{
    config::IconSizes,
    fl,
    russh::jsondata::TbProfilerJson,
    tab::{self, DirSize, ItemMetadata, ItemThumbnail, Location},
};
use mime_guess::MimeGuess;
use tokio::io::AsyncReadExt;
use tokio::runtime::Builder;

use crate::config::TBConfig;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SampleFiles {
    json: Option<PathBuf>,
    csv: Option<PathBuf>,
    docx: Option<PathBuf>,
    mtime: u64,
    size: Option<u64>,
}

use super::SlurmJobId;

fn get_key_files() -> Result<(PathBuf, PathBuf), String> {
    let home_dir = dirs::home_dir().ok_or_else(|| {
        "Could not determine the user home directory.\n\
        This usually indicates that the HOME environment variable is missing or invalid.\n\
        Please ensure HOME is set correctly before using SSH connections."
            .to_string()
    })?;

    let ssh_dir = home_dir.join(".ssh");
    if !ssh_dir.is_dir() {
        return Err(format!(
            "SSH configuration directory not found: {}.\n\
            Please ensure ~/.ssh exists and contains your SSH keys.",
            ssh_dir.display()
        ));
    }
    if ssh_dir.join("id_rsa").is_file() {
        Ok((ssh_dir.join("id_rsa"), ssh_dir.join("id_rsa.pub")))
    } else if ssh_dir.join("id_ed25519").is_file() {
        Ok((ssh_dir.join("id_ed25519"), ssh_dir.join("id_ed25519.pub")))
    } else if ssh_dir.join("id_ecdsa").is_file() {
        Ok((ssh_dir.join("id_ecdsa"), ssh_dir.join("id_ecdsa.pub")))
    } else if ssh_dir.join("id_dsa").is_file() {
        Ok((ssh_dir.join("id_dsa"), ssh_dir.join("id_dsa.pub")))
    } else {
        Err(format!(
            "No SSH key pair found in {}.\n\
            Expected one of: id_rsa, id_ed25519, id_ecdsa, id_dsa.\n\
            Please generate a key (e.g., with `ssh-keygen -t ed25519`) and try again.",
            ssh_dir.display()
        ))
    }
}

pub async fn dir_info(
    client: &Client,
    uri: &str,
) -> Result<(String, String, Option<PathBuf>), String> {
    let remote_file = uri.parse::<RemoteFile>().map_err(|e| e.to_string())?;
    let resolved_uri = remote_file.uri();

    let channel = client.get_channel().await.map_err(|e| e.to_string())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| e.to_string())?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| e.to_string())?;

    if let Err(err) = sftp.metadata(&remote_file.path).await {
        return Err(format!(
            "dir_info(): metadata error for {}: {}",
            remote_file.path, err
        ));
    }

    // Display name = last component of `remote_file.path`
    let display_name = Path::new(&remote_file.path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&remote_file.path)
        .to_string();
    let filepath: Option<PathBuf> = Some(PathBuf::from(&remote_file.path));

    Ok((resolved_uri, display_name, filepath))
}

pub async fn resolve_symlink(
    client: &Client,
    remotefile: &RemoteFile,
) -> Result<RemoteFile, String> {
    let channel = client.get_channel().await.map_err(|e| e.to_string())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| e.to_string())?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| e.to_string())?;

    match sftp.read_link(&remotefile.path).await {
        Ok(link_path) => {
            // Build new URI using same host/username but new path
            let new_uri = format!(
                "ssh://{}{}:{}{}",
                remotefile
                    .username
                    .clone()
                    .map(|u| u + "@")
                    .unwrap_or_default(),
                remotefile.host,
                remotefile.port,
                link_path
            );
            new_uri.parse::<RemoteFile>().map_err(|e| e.to_string())
        }
        Err(_) => Ok(remotefile.clone()), // not a symlink → keep original
    }
}

fn sample_key(name: &str) -> &str {
    if let Some((sample, _)) = name.split_once(".results.") {
        sample
    } else {
        name
    }
}

async fn remote_sftp_list(
    client: &Client,
    uri: &str,
    sizes: IconSizes,
) -> Result<Vec<tab::Item>, String> {
    log::info!("Listing remote directory: {}", uri);
    let mut remote_file = uri.parse::<RemoteFile>().map_err(|e| e.to_string())?;
    let force_dir = uri.starts_with("ssh:///");
    let path = remote_file.path.clone();
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
    let mut samples: HashMap<String, SampleFiles> = HashMap::new();

    // ------------------------------------------------------------
    // First pass — collect samples & normal files
    // ------------------------------------------------------------
    for entry in entries {
        let child_path = PathBuf::from(entry.file_name());
        let file_type = entry.file_type();
        let info = entry.metadata();
        if info.is_symlink() {
            remote_file = resolve_symlink(client, &remote_file).await?;
        }
        let name = child_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let new_path = PathBuf::from(&path).join(&child_path);
        let mut url = Url::parse(&format!(
            "ssh://{}{}:{}",
            remote_file
                .username
                .clone()
                .map(|u| u + "@")
                .unwrap_or_default(),
            remote_file.host,
            remote_file.port,
        ))
        .unwrap();
        let url_path = format!("{}/{}", path.trim_end_matches('/'), name);
        url.set_path(&url_path);
        let child_uri = url.to_string();
        let location = Location::Remote(child_uri.clone(), name.clone(), Some(new_path.clone()));

        // Always register .results.* files in the samples map for grouped items,
        // but also add them individually (is_raw_sample_file = true) so the
        // display layer can toggle without a rescan.
        let mut is_raw_sample_file = false;
        if file_type == FileType::File {
            if let Some((sample_id, suffix)) = name.split_once(".results.") {
                let entry = samples.entry(sample_id.to_string()).or_insert(SampleFiles {
                    json: None,
                    csv: None,
                    docx: None,
                    mtime: info
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    size: None,
                });

                match suffix {
                    "json" => entry.json = Some(new_path.clone()),
                    "csv" => entry.csv = Some(new_path.clone()),
                    "docx" => entry.docx = Some(new_path.clone()),
                    _ => {}
                }

                is_raw_sample_file = true;
            }
        }

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
            let is_json =
                MimeGuess::from_path(&new_path).first_or_octet_stream() == mime::APPLICATION_JSON;
            let mut json_opt = None;
            let mut is_susceptible = false;
            if is_json {
                match load_remote_json(client, &child_uri).await {
                    Ok(json) => {
                        let sus = json.dr_variants.iter().all(|v| v.is_susceptible());
                        json_opt = Some(json);
                        is_susceptible = sus;
                    }
                    Err(e) => {
                        log::info!("Failed to load JSON for {}: {}", new_path.display(), e);
                    }
                }
            }
            if is_dir {
                let mut count = 0;
                match sftp.read_dir(new_path.to_string_lossy().to_string()).await {
                    Ok(mut dir) => {
                        while let Some(entry) = dir.next() {
                            if entry.file_name() == "." || entry.file_name() == ".." {
                                continue;
                            }
                            count += 1;
                        }
                    }
                    Err(_) => {
                        log::info!(
                            "Could not read directory to count children: {}",
                            new_path.display()
                        );
                    }
                }
                children_opt = Some(count);
            }
            ItemMetadata::RusshPath {
                mtime,
                size_opt,
                children_opt,
                is_json,
                json_opt,
                is_tb_result: false,
                is_raw_sample_file,
                sample_json_path_opt: None,
                sample_csv_path_opt: None,
                sample_docx_path_opt: None,
                is_susceptible,
            }
        } else {
            ItemMetadata::SimpleDir { entries: 0 }
        };

        let (mime, icon_handle_grid, icon_handle_list, icon_handle_list_condensed) = {
            let mime = if metadata.is_dir() {
                "inode/directory".parse().unwrap()
            } else {
                MimeGuess::from_path(&new_path).first_or_octet_stream()
            };
            let mime_clone = mime.clone();
            let file_icon = |size| {
                widget::icon::from_name(if metadata.is_dir() {
                    "folder"
                } else if mime_clone.type_() == mime::IMAGE {
                    "image-x-generic"
                } else if mime_clone == mime::APPLICATION_PDF {
                    "application-pdf"
                } else {
                    "text-x-generic"
                })
                .size(size)
                .handle()
            };
            (
                // TODO: get mime from content_type?
                mime,
                file_icon(sizes.grid()),
                file_icon(sizes.list()),
                file_icon(sizes.list_condensed()),
            )
        };

        // Check if item is hidden
        let hidden = name.starts_with('.');

        items.push(tab::Item {
            name: name.clone(),
            is_mount_point: false,
            is_client_point: false,
            display_name: name.clone(),
            metadata,
            hidden,
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

    // ------------------------------------------------------------
    // Second pass — build grouped sample items
    // ------------------------------------------------------------
    for (sample_id, files) in samples {
        let mut json_opt = None;
        let mut is_susceptible = false;

        if let Some(json_path) = &files.json {
            let mut url = Url::parse(&format!(
                "ssh://{}{}:{}",
                remote_file
                    .username
                    .clone()
                    .map(|u| u + "@")
                    .unwrap_or_default(),
                remote_file.host,
                remote_file.port,
            ))
            .unwrap();

            let url_path = json_path.to_string_lossy().replace('\\', "/");
            url.set_path(&url_path);
            match load_remote_json(client, url.as_str()).await {
                Ok(json) => {
                    let sus = json.dr_variants.iter().all(|v| v.is_susceptible());
                    json_opt = Some(json);
                    is_susceptible = sus;
                }
                Err(e) => log::warn!("Failed to load sample JSON: {}", e),
            }
        }

        let location = Location::Remote(uri.to_string(), sample_id.clone(), None);

        let metadata = ItemMetadata::RusshPath {
            mtime: files.mtime,
            size_opt: None,
            children_opt: None,
            is_json: true,
            json_opt,
            is_tb_result: true,
            is_raw_sample_file: false,
            sample_json_path_opt: files.json.clone(),
            sample_csv_path_opt: files.csv.clone(),
            sample_docx_path_opt: files.docx.clone(),
            is_susceptible,
        };

        items.push(tab::Item {
            name: sample_id.clone(),
            display_name: sample_id.clone(),
            metadata,
            hidden: false,
            location_opt: Some(location),
            mime: "application/json".parse().unwrap(),
            icon_handle_grid: widget::icon::from_name("text-x-generic")
                .size(sizes.grid())
                .handle(),
            icon_handle_list: widget::icon::from_name("text-x-generic")
                .size(sizes.list())
                .handle(),
            icon_handle_list_condensed: widget::icon::from_name("text-x-generic")
                .size(sizes.list_condensed())
                .handle(),
            is_mount_point: false,
            is_client_point: false,
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

async fn remote_sftp_parent(
    client: &Client,
    uri: &str,
    sizes: IconSizes,
) -> Result<tab::Item, String> {
    let remote_file = uri.parse::<RemoteFile>().map_err(|e| e.to_string())?;
    let path = remote_file.path.clone();
    let channel = client.get_channel().await.map_err(|e| e.to_string())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| e.to_string())?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| e.to_string())?;
    let metadata = sftp
        .metadata(path.clone())
        .await
        .map_err(|e| format!("metadata {path}: {e:?}"))?;

    let child_path = PathBuf::from(remote_file.path.clone());
    let name = child_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let child_uri = format!(
        "ssh://{}{}:{}{}",
        remote_file
            .username
            .clone()
            .map(|u| u + "@")
            .unwrap_or_default(),
        remote_file.host,
        remote_file.port,
        remote_file.path.clone(),
    );

    let location = Location::Remote(
        child_uri,
        name.clone(),
        Some(PathBuf::from(remote_file.path.clone())),
    );

    let item_metadata = {
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let is_dir = metadata.is_dir();
        let size_opt = (!is_dir).then_some(metadata.size).flatten();
        let mut children_opt = None;
        if is_dir {
            let mut count = 0;
            match sftp.read_dir(remote_file.path.clone()).await {
                Ok(mut dir) => {
                    while let Some(entry) = dir.next() {
                        if entry.file_name() == "." || entry.file_name() == ".." {
                            continue;
                        }
                        count += 1;
                    }
                }
                Err(_) => {
                    log::info!(
                        "Could not read directory to count children: {}",
                        remote_file.path.clone()
                    );
                }
            }
            children_opt = Some(count);
        }
        ItemMetadata::RusshPath {
            mtime,
            size_opt,
            children_opt,
            is_json: false,
            json_opt: None,
            is_tb_result: false,
            is_raw_sample_file: false,
            sample_json_path_opt: None,
            sample_csv_path_opt: None,
            sample_docx_path_opt: None,
            is_susceptible: false,
        }
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
            "inode/directory".parse().unwrap(),
            file_icon(sizes.grid()),
            file_icon(sizes.list()),
            file_icon(sizes.list_condensed()),
        )
    };
    let hidden = name.starts_with('.');
    let item = tab::Item {
        name: name.clone(),
        is_mount_point: false,
        is_client_point: false,
        display_name: name,
        metadata: item_metadata,
        hidden,
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
    };
    Ok(item)
}

async fn load_remote_json(client: &Client, uri: &str) -> Result<TbProfilerJson, String> {
    let remote_file = uri.parse::<RemoteFile>().map_err(|e| e.to_string())?;
    let channel = client.get_channel().await.map_err(|e| e.to_string())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| e.to_string())?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| e.to_string())?;
    let mut file = sftp
        .open(remote_file.path.clone())
        .await
        .map_err(|e| e.to_string())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .await
        .map_err(|e| e.to_string())?;

    let parsed: TbProfilerJson = serde_json::from_str(&contents).map_err(|e| e.to_string())?;
    Ok(parsed)
}

async fn perform_download(
    client: &Client,
    paths: Box<[PathBuf]>,
    to: PathBuf,
    zip_output: Option<PathBuf>,
) -> Result<(), anyhow::Error> {
    let mut reserved = HashSet::new();

    // Shell-safe single-quote escaping: replace ' with '\''
    let sq = |s: &str| s.replace('\'', "'\\''");

    // Open one SFTP session to check whether each path is a directory.
    let channel = client.get_channel().await?;
    channel.request_subsystem(true, "sftp").await?;
    let sftp = SftpSession::new(channel.into_stream()).await?;

    // Partition into directories and plain files.
    let mut dirs: Vec<&PathBuf> = Vec::new();
    let mut files: Vec<&PathBuf> = Vec::new();
    for from in paths.iter() {
        if from.file_name().is_none() {
            continue;
        }
        let remote = from.to_string_lossy().replace('\\', "/");
        let is_dir = sftp
            .metadata(&remote)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if is_dir {
            dirs.push(from);
        } else {
            files.push(from);
        }
    }

    // --- Multiple (or single) directories → one combined zip ---
    if !dirs.is_empty() {
        let remote_zip = format!(
            "/tmp/cosmic_files_{}.zip",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );

        // Each dir may live in a different parent, so cd into the right parent
        // per entry and append to the same archive with `zip -r`.
        let parts: Vec<String> = dirs
            .iter()
            .map(|dir| {
                let parent = dir
                    .parent()
                    .unwrap_or_else(|| Path::new("/"))
                    .to_string_lossy()
                    .replace('\\', "/");
                let dir_name = dir.file_name().unwrap().to_string_lossy();
                format!(
                    "(cd '{}' && zip -r '{}' '{}')",
                    sq(&parent),
                    sq(&remote_zip),
                    sq(&dir_name),
                )
            })
            .collect();
        let zip_cmd = parts.join(" && ");

        let res = client.execute(&zip_cmd).await?;
        if res.exit_status != 0 {
            let _ = client
                .execute(&format!("rm -f '{}'", sq(&remote_zip)))
                .await;
            return Err(anyhow::anyhow!(
                "zip failed: stdout: {} stderr: {}",
                res.stdout,
                res.stderr
            ));
        }

        // Use the user-chosen path when provided (SaveFile dialog), otherwise derive a name.
        let local_target = if let Some(ref out) = zip_output {
            out.clone()
        } else {
            let zip_name = if dirs.len() == 1 {
                format!("{}.zip", dirs[0].file_name().unwrap().to_string_lossy())
            } else {
                "folders.zip".to_string()
            };
            let zip_stem_path = PathBuf::from(&zip_name);
            let mut t = to.join(&zip_name);
            if t.try_exists().unwrap_or(false) || reserved.contains(&t) {
                t = download_unique_path(&zip_stem_path, &to, &mut reserved);
            }
            t
        };
        reserved.insert(local_target.clone());

        let dl_result = client
            .download_file(remote_zip.clone(), local_target.clone())
            .await;
        let _ = client
            .execute(&format!("rm -f '{}'", sq(&remote_zip)))
            .await;
        if let Err(err) = dl_result {
            return Err(anyhow::anyhow!("Download failed for zip: {}", err));
        }
    }

    // --- Plain files downloaded individually ---
    for from in files {
        let name = from.file_name().unwrap();
        let remote = from.to_string_lossy().replace('\\', "/");
        let mut target = to.join(name);
        if target.try_exists().unwrap_or(false) || reserved.contains(&target) {
            target = download_unique_path(from, &to, &mut reserved);
        }
        reserved.insert(target.clone());

        if let Err(err) = client.download_file(remote.clone(), target.clone()).await {
            return Err(anyhow::anyhow!("Download failed for {}: {}", remote, err));
        }
    }

    Ok(())
}

pub fn download_unique_path(from: &Path, to: &Path, reserved: &mut HashSet<PathBuf>) -> PathBuf {
    // List of compound extensions to check
    const COMPOUND_EXTENSIONS: &[&str] = &[
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".tar.zst",
        ".tar.lz",
        ".tar.lzma",
        ".tar.sz",
        ".tar.lzo",
        ".tar.br",
        ".tar.Z",
        ".tar.pz",
    ];

    let to = to.to_owned();
    let file_name = from.file_name().and_then(|n| n.to_str()).unwrap();
    let file_name = file_name.to_string();

    // --- split into stem/ext correctly ---
    let (stem, ext) = COMPOUND_EXTENSIONS
        .iter()
        .copied()
        .find(|&e| file_name.ends_with(e))
        .map(|e| {
            (
                file_name.strip_suffix(e).unwrap().to_string(),
                Some(e[1..].to_string()),
            )
        })
        .unwrap_or_else(|| {
            from.file_stem()
                .and_then(|s| s.to_str())
                .map_or((file_name.clone(), None), |s| {
                    (
                        s.to_string(),
                        from.extension()
                            .and_then(|e| e.to_str())
                            .map(str::to_string),
                    )
                })
        });

    // --- find free name ---
    for n in 0.. {
        let new_name = if n == 0 {
            file_name.clone()
        } else {
            match &ext {
                Some(ext) => format!("{} ({} {}).{}", stem, fl!("copy_noun"), n, ext),
                None => format!("{} ({} {})", stem, fl!("copy_noun"), n),
            }
        };

        let candidate = to.join(new_name);

        // IMPORTANT: check both filesystem AND reserved names
        if !candidate.exists() && !reserved.contains(&candidate) {
            reserved.insert(candidate.clone());
            return candidate;
        }
    }

    unreachable!()
}

pub async fn run_tbprofiler(
    client: &Client,
    paths: Box<[PathBuf]>,
    tb_config: TBConfig,
) -> Result<SlurmJobId, anyhow::Error> {
    if tb_config.script_path.is_empty()
        || tb_config.out_dir.is_empty()
        || tb_config.docx_template_path.is_empty()
    {
        return Err(anyhow::anyhow!(
            "Please configure paths under TB profiler settings..."
        ));
    }
    let mut sample_map: BTreeMap<String, BTreeSet<u8>> = BTreeMap::new();
    for path in paths.iter() {
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid filename in path: {:?}", path))?;
        if let Some(sample) = filename.strip_suffix(tb_config.pair1_suffix.as_str()) {
            sample_map.entry(sample.to_string()).or_default().insert(1);
        } else if let Some(sample) = filename.strip_suffix(tb_config.pair2_suffix.as_str()) {
            sample_map.entry(sample.to_string()).or_default().insert(2);
        } else {
            return Err(anyhow::anyhow!(
                "Unexpected FASTQ filename format: {}",
                filename
            ));
        }
    }
    if sample_map.is_empty() {
        return Err(anyhow::anyhow!("No valid FASTQ files provided"));
    }
    for (sample, reads) in &sample_map {
        if reads.len() != 2 {
            return Err(anyhow::anyhow!(
                "Sample {} does not have both {} and {} FASTQ files",
                sample,
                tb_config.pair1_suffix,
                tb_config.pair2_suffix
            ));
        }
    }
    let sample_ids: Vec<String> = sample_map.keys().cloned().collect();
    let sample_ids_string = sample_ids.join(",");
    let array_end = sample_ids
        .len()
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("Need at least 1 sample"))?;

    let raw_sequence_dir_paired = {
        let first_parent = paths
            .first()
            .and_then(|p| p.parent())
            .ok_or_else(|| anyhow::anyhow!("Could not determine parent directory"))?;

        for p in paths.iter() {
            let parent = p
                .parent()
                .ok_or_else(|| anyhow::anyhow!("Path has no parent: {:?}", p))?;
            if parent != first_parent {
                return Err(anyhow::anyhow!(
                    "FASTQ files are in different directories: {:?} vs {:?}",
                    first_parent,
                    parent
                ));
            }
        }
        first_parent.to_string_lossy().into_owned()
    };

    let command_run_tbprofiler = format!(
        "sbatch --parsable --array 0-{} {} \"{}\" {} {} {}",
        array_end,
        tb_config.script_path,
        sample_ids_string,
        raw_sequence_dir_paired,
        tb_config.out_dir,
        tb_config.docx_template_path,
    );
    let res = client.execute(&command_run_tbprofiler).await?;
    if res.exit_status != 0 {
        return Err(anyhow::anyhow!(
            "tbprofiler failed (exit {}):\nstdout:\n{}\nstderr:\n{}",
            res.exit_status,
            res.stdout,
            res.stderr
        ));
    }
    if !res.stderr.is_empty() {
        log::warn!("tbprofiler stderr: {}", res.stderr);
    }
    log::info!("tbprofiler stdout: {}", res.stdout);
    let job_id: usize = res.stdout.split(';').next().unwrap().trim().parse()?;
    let tasks = array_end
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("Overflow when calculating tasks"))?;
    let job_id = SlurmJobId {
        array_id: job_id,
        tasks,
        running_tasks: tasks,
    };
    Ok(job_id)
}

async fn poll_running_tasks(
    client: &Client,
    array_id: usize,
) -> Result<usize, anyhow::Error> {
    log::info!("poll_running_tasks: querying squeue for job_id={array_id}");
    let cmd = format!(
        "squeue -j {} -r -h -o \"%T\" 2>/dev/null | grep -c RUNNING || true",
        array_id
    );
    let res = client.execute(&cmd).await?;
    log::info!(
        "poll_running_tasks: squeue exit_status={} stdout={:?} for job_id={array_id}",
        res.exit_status,
        res.stdout.trim()
    );
    let count: usize = res.stdout.trim().parse().unwrap_or(0);
    log::info!("poll_running_tasks: job_id={array_id} running_count={count}");
    Ok(count)
}

pub async fn delete_remote_files(
    client: &Client,
    paths: &[PathBuf],
) -> Result<String, anyhow::Error> {
    if paths.is_empty() {
        return Ok(String::new());
    }
    let filenames: Vec<String> = paths
        .iter()
        .map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<invalid>")
                .to_string()
        })
        .collect();
    let files = paths
        .iter()
        .map(|p| {
            let remote = p.to_string_lossy().replace('\\', "/");
            format!("'{}'", remote.replace('\'', "'\\''"))
        })
        .collect::<Vec<_>>()
        .join(" ");
    let command = format!("rm -rf {}", files);
    let res = client.execute(&command).await?;
    if res.exit_status != 0 {
        return Err(anyhow::anyhow!(
            "Failed to delete files (exit {}):\nstderr:\n{}",
            res.exit_status,
            res.stderr
        ));
    }
    Ok(filenames.join("\n"))
}

pub async fn delete_tbprofiler_results(
    client: &Client,
    tb_config: TBConfig,
) -> Result<String, anyhow::Error> {
    let command = format!("rm -rf {}/results/*", tb_config.out_dir);
    let res = client.execute(&command).await?;
    if res.exit_status != 0 {
        return Err(anyhow::anyhow!(
            "Failed to delete remote file (exit {}):\nstderr:\n{}",
            res.exit_status,
            res.stderr
        ));
    }
    Ok(res.stdout)
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

#[derive(Debug, Clone)]
pub struct RemoteFile {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub path: String,
}

impl RemoteFile {
    pub fn uri(&self) -> String {
        let userpart = if let Some(user) = &self.username {
            format!("{}@", user)
        } else {
            "".into()
        };
        format!("ssh://{}{}:{}{}", userpart, self.host, self.port, self.path)
    }
}

#[derive(Debug)]
pub enum RemoteFileError {
    InvalidUrl(String),
    UnsupportedScheme(String),
    MissingHost,
}

impl fmt::Display for RemoteFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemoteFileError::InvalidUrl(e) => write!(f, "Invalid URL: {e}"),
            RemoteFileError::UnsupportedScheme(s) => {
                write!(f, "Unsupported scheme: {s}")
            }
            RemoteFileError::MissingHost => write!(f, "Missing host"),
        }
    }
}

impl FromStr for RemoteFile {
    type Err = RemoteFileError;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(uri).map_err(|e| RemoteFileError::InvalidUrl(e.to_string()))?;
        if url.scheme() != "ssh" {
            return Err(RemoteFileError::UnsupportedScheme(url.scheme().to_string()));
        }
        let host = url
            .host_str()
            .ok_or(RemoteFileError::MissingHost)?
            .to_string();
        let port = url.port().unwrap_or(22);
        let username = if url.username().is_empty() {
            None
        } else {
            Some(url.username().to_string())
        };
        let mut path = url.path().to_string();
        if path.is_empty() {
            path = "/".into();
        }
        if path.len() > 1 && path.ends_with('/') {
            path.pop();
        }
        Ok(Self {
            host,
            port,
            username,
            path,
        })
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
    RemoteParent(String, IconSizes, mpsc::Sender<Result<tab::Item, String>>),
    DirInfo(
        String,
        mpsc::Sender<Result<(String, String, Option<PathBuf>), anyhow::Error>>,
    ),
    Disconnect(ClientItem),
    Download(
        Box<[PathBuf]>,
        Vec<String>,
        PathBuf,
        Option<PathBuf>,
        tokio::sync::oneshot::Sender<anyhow::Result<()>>,
    ),
    RunTbProfiler(
        Box<[PathBuf]>,
        Vec<String>,
        TBConfig,
        tokio::sync::oneshot::Sender<anyhow::Result<SlurmJobId>>,
    ),
    DeleteRemoteFiles(
        Box<[PathBuf]>,
        Vec<String>,
        tokio::sync::oneshot::Sender<anyhow::Result<String>>,
    ),
    DeleteTbProfilerResults(
        String,
        TBConfig,
        tokio::sync::oneshot::Sender<anyhow::Result<String>>,
    ),
    PollJobStatus(usize, String),
}

enum Event {
    Changed,
    Items(ClientItems),
    ClientResult(ClientItem, Result<bool, String>),
    RemoteAuth(String, ClientAuth, mpsc::Sender<ClientAuth>),
    RemoteResult(String, Result<bool, String>),
    RunTbProfilerResult(String, Result<SlurmJobId, String>),
    DeleteRemoteFilesResult(String, Result<String, String>),
    JobStatusUpdate(String, usize, usize),
}

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
                let mut client_items = Vec::<ClientItem>::new();
                while let Some(command) = command_rx.recv().await {
                    match command {
                        Cmd::Items(_sizes, items_tx) => {
                            items_tx.send(client_items.clone()).await.unwrap();
                        }
                        Cmd::Rescan => {
                            event_tx.send(Event::Items(client_items.clone())).unwrap();
                        }
                        Cmd::Connect(client_item, result_tx) => {
                            let client_item_clone = client_item.clone();
                            let ClientItem::Russh(item) = client_item else {
                                _ = result_tx.send(Err(anyhow::anyhow!("No client item")));
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
                                    {
                                        let mut write = clients.write().await;
                                        write.insert(item.host.clone(), Arc::new(client));
                                    }
                                    client_items.push(ClientItem::Russh(Item {
                                        name: item.name.clone(),
                                        is_connected: true,
                                        icon_opt: item.icon_opt.clone(),
                                        icon_symbolic_opt: item.icon_symbolic_opt.clone(),
                                        path_opt: item.path_opt.clone(),
                                        uri: item.uri.clone(),
                                        host: item.host.clone(),
                                        port: item.port,
                                        username: item.username.clone(),
                                        auth: item.auth.clone(),
                                        server_check: item.server_check.clone(),
                                    }));
                                    _ = result_tx.send(Ok(()));
                                    event_tx
                                        .send(Event::ClientResult(
                                            client_item_clone.clone(),
                                            Ok(true),
                                        ))
                                        .unwrap();
                                }
                                Err(err) => {
                                    _ = result_tx.send(Err(anyhow::anyhow!("{err:?}")));
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
                            let mut result_tx_opt = Some(result_tx);
                            let event_tx = event_tx.clone();
                            let remote_file =
                                match uri.parse::<RemoteFile>().map_err(|e| e.to_string()) {
                                    Ok(rf) => rf,
                                    Err(err) => {
                                        if let Some(result_tx) = result_tx_opt.take() {
                                            _ = result_tx.send(Err(anyhow::anyhow!("{err:?}")));
                                        }
                                        let _ = event_tx
                                            .send(Event::RemoteResult(uri, Err(err.to_string())));
                                        continue;
                                    }
                                };
                            let norm_uri = remote_file.uri();
                            let host = remote_file.host.as_str();
                            let port = remote_file.port;
                            let username = match remote_file.username {
                                Some(u) => u,
                                None => {
                                    let msg = "No username specified in URI";
                                    if let Some(result_tx) = result_tx_opt.take() {
                                        let _ = result_tx.send(Err(anyhow::anyhow!(msg)));
                                    }
                                    let _ = event_tx.send(Event::RemoteResult(
                                        norm_uri.clone(),
                                        Err(msg.to_string()),
                                    ));
                                    continue;
                                }
                            };
                            let auth = match get_key_files() {
                                Ok((key_path, _)) => AuthMethod::with_key_file(key_path, None),
                                Err(err) => {
                                    if let Some(result_tx) = result_tx_opt.take() {
                                        let _ =
                                            result_tx.send(Err(anyhow::anyhow!(err.to_string())));
                                    }
                                    let _ = event_tx.send(Event::RemoteResult(
                                        norm_uri.clone(),
                                        Err(err.to_string()),
                                    ));
                                    continue;
                                }
                            };
                            let existing_client = {
                                let read = clients.read().await;
                                read.contains_key(host)
                            };
                            let client_item = ClientItem::Russh(Item {
                                name: host.to_string(),
                                is_connected: true,
                                icon_opt: None,
                                icon_symbolic_opt: None,
                                path_opt: Some(PathBuf::from(remote_file.path.clone())),
                                uri: norm_uri.clone(),
                                host: host.to_string(),
                                port,
                                username: username.clone(),
                                auth: auth.clone(),
                                server_check: ServerCheckMethod::NoCheck,
                            });
                            if existing_client {
                                let has_item = client_items.iter().any(|item| {
                                    matches!(
                                        item,
                                        ClientItem::Russh(r) if r.host == host
                                    )
                                });
                                if !has_item {
                                    client_items.push(client_item);
                                    let _ = event_tx.send(Event::Changed);
                                }
                                if let Some(result_tx) = result_tx_opt.take() {
                                    let _ = result_tx.send(Ok(()));
                                }
                                let _ =
                                    event_tx.send(Event::RemoteResult(norm_uri.clone(), Ok(true)));
                                continue;
                            }
                            match Client::connect(
                                (host, port),
                                username.as_str(),
                                auth,
                                ServerCheckMethod::NoCheck,
                            )
                            .await
                            {
                                Ok(client) => {
                                    {
                                        let mut write = clients.write().await;
                                        write.insert(host.to_string(), Arc::new(client));
                                    }
                                    client_items.push(client_item);
                                    let _ = event_tx.send(Event::Changed);
                                    if let Some(result_tx) = result_tx_opt.take() {
                                        let _ = result_tx.send(Ok(()));
                                    }
                                    let _ = event_tx
                                        .send(Event::RemoteResult(norm_uri.clone(), Ok(true)));
                                }
                                Err(err) => {
                                    let msg = format!("Connecting fresh session failed: {}", err);
                                    if let Some(result_tx) = result_tx_opt.take() {
                                        let _ = result_tx.send(Err(anyhow::anyhow!(msg.clone())));
                                    }
                                    let _ = event_tx.send(Event::RemoteResult(
                                        norm_uri.clone(),
                                        Err(msg.clone()),
                                    ));
                                }
                            }
                        }
                        Cmd::RemoteScan(uri, sizes, items_tx) => {
                            log::info!("RemoteScan for URI: {}", uri);
                            let remote_file =
                                match uri.parse::<RemoteFile>().map_err(|e| e.to_string()) {
                                    Ok(rf) => rf,
                                    Err(e) => {
                                        let _ = items_tx.send(Err(e)).await;
                                        continue;
                                    }
                                };
                            let norm_uri = remote_file.uri();
                            let host = remote_file.host.as_str();
                            let port = remote_file.port;
                            let username = match remote_file.username {
                                Some(u) => u,
                                None => {
                                    event_tx
                                        .send(Event::RemoteResult(
                                            norm_uri,
                                            Err("No username specified in URI".into()),
                                        ))
                                        .unwrap();
                                    continue;
                                }
                            };

                            let existing_client = {
                                let read = clients.read().await;
                                read.get(host).cloned()
                            };
                            if let Some(client) = existing_client {
                                let result =
                                    remote_sftp_list(&client, &norm_uri, sizes)
                                        .await;
                                let _ = items_tx.send(result).await;
                            } else {
                                let key_path = match get_key_files() {
                                    Ok(key_pair) => key_pair.0,
                                    Err(e) => {
                                        event_tx
                                            .send(Event::RemoteResult(norm_uri, Err(e)))
                                            .unwrap();
                                        continue;
                                    }
                                };
                                let auth = AuthMethod::with_key_file(key_path, None);
                                match Client::connect(
                                    (host, port),
                                    username.as_str(),
                                    auth.clone(),
                                    ServerCheckMethod::NoCheck,
                                )
                                .await
                                {
                                    Ok(client) => {
                                        {
                                            let mut write = clients.write().await;
                                            write.insert(host.to_string(), Arc::new(client));
                                        }
                                        let client = {
                                            let read = clients.read().await;
                                            Arc::clone(read.get(host).unwrap())
                                        };
                                        let result = remote_sftp_list(
                                            &client,
                                            &norm_uri,
                                            sizes,
                                        )
                                        .await;
                                        let _ = items_tx.send(result).await;
                                        event_tx
                                            .send(Event::RemoteResult(norm_uri, Ok(true)))
                                            .unwrap();
                                    }
                                    Err(err) => {
                                        let msg =
                                            format!("Connecting fresh session failed: {}", err);
                                        event_tx
                                            .send(Event::RemoteResult(norm_uri, Err(msg)))
                                            .unwrap();
                                    }
                                }
                            }
                        }
                        Cmd::RemoteParent(uri, sizes, items_tx) => {
                            let remote_file =
                                match uri.parse::<RemoteFile>().map_err(|e| e.to_string()) {
                                    Ok(rf) => rf,
                                    Err(e) => {
                                        let _ = items_tx.send(Err(e)).await;
                                        continue;
                                    }
                                };
                            let norm_uri = remote_file.uri();
                            let host = remote_file.host.as_str();
                            let port = remote_file.port;
                            let username = match remote_file.username {
                                Some(u) => u,
                                None => {
                                    event_tx
                                        .send(Event::RemoteResult(
                                            norm_uri,
                                            Err("No username specified in URI".into()),
                                        ))
                                        .unwrap();
                                    continue;
                                }
                            };
                            let existing_client = {
                                let read = clients.read().await;
                                read.get(host).cloned()
                            };
                            if let Some(client) = existing_client {
                                let result = remote_sftp_parent(&client, &norm_uri, sizes).await;
                                let _ = items_tx.send(result).await;
                            } else {
                                let key_path = match get_key_files() {
                                    Ok(key_pair) => key_pair.0,
                                    Err(e) => {
                                        event_tx
                                            .send(Event::RemoteResult(norm_uri, Err(e)))
                                            .unwrap();
                                        continue;
                                    }
                                };
                                let auth = AuthMethod::with_key_file(key_path, None);
                                match Client::connect(
                                    (host, port),
                                    username.as_str(),
                                    auth.clone(),
                                    ServerCheckMethod::NoCheck,
                                )
                                .await
                                {
                                    Ok(client) => {
                                        {
                                            let mut write = clients.write().await;
                                            write.insert(host.to_string(), Arc::new(client));
                                        }
                                        let client = {
                                            let read = clients.read().await;
                                            Arc::clone(read.get(host).unwrap())
                                        };
                                        let result =
                                            remote_sftp_parent(&client, &norm_uri, sizes).await;
                                        let _ = items_tx.send(result).await;
                                        event_tx
                                            .send(Event::RemoteResult(norm_uri, Ok(true)))
                                            .unwrap();
                                    }
                                    Err(err) => {
                                        let msg =
                                            format!("Connecting fresh session failed: {}", err);
                                        event_tx
                                            .send(Event::RemoteResult(norm_uri, Err(msg)))
                                            .unwrap();
                                    }
                                }
                            }
                        }
                        Cmd::DirInfo(uri, result_tx) => {
                            let remote_file =
                                match uri.parse::<RemoteFile>().map_err(|e| e.to_string()) {
                                    Ok(rf) => rf,
                                    Err(e) => {
                                        let _ = result_tx.send(Err(anyhow::anyhow!(e))).await;
                                        continue;
                                    }
                                };
                            let host = remote_file.host.as_str();
                            let client = {
                                let read = clients.read().await;
                                match read.get(host) {
                                    Some(c) => Arc::clone(c),
                                    None => {
                                        let msg =
                                            format!("No SSH client connected for host: {}", host);
                                        let _ = result_tx.send(Err(anyhow::anyhow!(msg))).await;
                                        continue;
                                    }
                                }
                            };
                            let result = dir_info(&client, &uri)
                                .await
                                .map_err(|e| anyhow::anyhow!(e));
                            result_tx.send(result).await.unwrap();
                        }
                        Cmd::Disconnect(client_item) => {
                            log::info!("Disconnect command received");
                            let ClientItem::Russh(item) = client_item else {
                                continue;
                            };
                            {
                                let mut write = clients.write().await;
                                write.remove(&item.host);
                            }
                            client_items.retain(|ci| {
                                if let ClientItem::Russh(r) = ci {
                                    r.host != item.host
                                } else {
                                    true
                                }
                            });
                            let event_tx = event_tx.clone();
                            let _ = event_tx.send(Event::Changed);
                            log::info!("Disconnected from {}", item.host);
                        }
                        Cmd::Download(paths, uris, path, zip_output, result_tx) => {
                            let result: Result<(), anyhow::Error> = async {
                                let remote_files: Vec<_> = uris
                                    .iter()
                                    .map(|u| {
                                        u.parse::<RemoteFile>().map_err(|e| anyhow::anyhow!(e))
                                    })
                                    .collect::<Result<_, anyhow::Error>>()?;
                                let host = remote_files
                                    .first()
                                    .ok_or_else(|| anyhow::anyhow!("No URIs provided"))?
                                    .host
                                    .clone();
                                if remote_files.iter().any(|rf| rf.host != host) {
                                    return Err(anyhow::anyhow!(
                                        "All download URIs must be from the same host"
                                    ));
                                }
                                let client = {
                                    let read = clients.read().await;
                                    read.get(&host).cloned()
                                }
                                .ok_or_else(|| anyhow::anyhow!("No client for host {host}"))?;
                                perform_download(&client, paths.clone(), path.clone(), zip_output.clone()).await?;
                                Ok(())
                            }
                            .await;
                            let _ = result_tx.send(result);
                        }
                        Cmd::RunTbProfiler(paths, uris, tb_config, result_tx) => {
                            let uri = uris
                                .first()
                                .cloned()
                                .unwrap_or_else(|| "ssh:///".to_string());
                            if uris.is_empty() {
                                let err = anyhow::anyhow!("No URIs provided");
                                let _ = result_tx.send(Err(err));
                                continue;
                            }
                            let remote_files: Vec<_> = match uris
                                .iter()
                                .map(|u| u.parse::<RemoteFile>().map_err(|e| anyhow::anyhow!(e)))
                                .collect::<Result<_, _>>()
                            {
                                Ok(v) => v,
                                Err(err) => {
                                    let _ = result_tx.send(Err(err));
                                    continue;
                                }
                            };
                            let host = match remote_files.first() {
                                Some(rf) => rf.host.clone(),
                                None => {
                                    let _ =
                                        result_tx.send(Err(anyhow::anyhow!("No URIs provided")));
                                    continue;
                                }
                            };
                            if remote_files.iter().any(|rf| rf.host != host) {
                                let _ = result_tx.send(Err(anyhow::anyhow!(
                                    "All URIs must be from the same host"
                                )));
                                continue;
                            }
                            let client = {
                                let read = clients.read().await;
                                read.get(&host).cloned()
                            };
                            let client = match client {
                                Some(c) => c,
                                None => {
                                    let err = anyhow::anyhow!("No client for host {}", host);
                                    let _ = result_tx.send(Err(err));
                                    continue;
                                }
                            };
                            let result = run_tbprofiler(&client, paths, tb_config).await;
                            let event_result: Result<SlurmJobId, String> = result
                                .as_ref()
                                .copied()
                                .map_err(|e| e.to_string());
                            let _ = result_tx.send(result);
                            event_tx
                                .send(Event::RunTbProfilerResult(uri, event_result))
                                .unwrap();
                        }
                        Cmd::DeleteRemoteFiles(paths, uris, result_tx) => {
                            let uri = uris
                                .first()
                                .cloned()
                                .unwrap_or_else(|| "ssh:///".to_string());
                            if uris.is_empty() {
                                let err = anyhow::anyhow!("No URIs provided");
                                let _ = result_tx.send(Err(err));
                                continue;
                            }
                            let remote_files: Vec<_> = match uris
                                .iter()
                                .map(|u| u.parse::<RemoteFile>().map_err(|e| anyhow::anyhow!(e)))
                                .collect::<Result<_, _>>()
                            {
                                Ok(v) => v,
                                Err(err) => {
                                    let _ = result_tx.send(Err(err));
                                    continue;
                                }
                            };
                            let host = match remote_files.first() {
                                Some(rf) => rf.host.clone(),
                                None => {
                                    let _ =
                                        result_tx.send(Err(anyhow::anyhow!("No URIs provided")));
                                    continue;
                                }
                            };
                            if remote_files.iter().any(|rf| rf.host != host) {
                                let _ = result_tx.send(Err(anyhow::anyhow!(
                                    "All URIs must be from the same host"
                                )));
                                continue;
                            }
                            let client = {
                                let read = clients.read().await;
                                read.get(&host).cloned()
                            };
                            let client = match client {
                                Some(c) => c,
                                None => {
                                    let err = anyhow::anyhow!("No client for host {}", host);
                                    let _ = result_tx.send(Err(err));
                                    continue;
                                }
                            };
                            let result = delete_remote_files(&client, &paths).await;
                            let event_result: Result<String, String> = result
                                .as_ref()
                                .map(|s| s.clone())
                                .map_err(|e| e.to_string());
                            let _ = result_tx.send(result);
                            event_tx
                                .send(Event::DeleteRemoteFilesResult(uri, event_result))
                                .unwrap();
                        }
                        Cmd::DeleteTbProfilerResults(uri, tb_config, result_tx) => {
                            let remote_file =
                                match uri.parse::<RemoteFile>().map_err(|e| e.to_string()) {
                                    Ok(rf) => rf,
                                    Err(e) => {
                                        let _ = result_tx.send(Err(anyhow::anyhow!(e)));
                                        continue;
                                    }
                                };
                            let host = remote_file.host.as_str();
                            let client = {
                                let read = clients.read().await;
                                match read.get(host) {
                                    Some(c) => Arc::clone(c),
                                    None => {
                                        let msg =
                                            format!("No SSH client connected for host: {}", host);
                                        let _ = result_tx.send(Err(anyhow::anyhow!(msg)));
                                        continue;
                                    }
                                }
                            };
                            let result = delete_tbprofiler_results(&client, tb_config).await;
                            let _ = result_tx.send(result);
                        }
                        Cmd::PollJobStatus(array_id, uri) => {
                            log::info!("PollJobStatus: received command for job_id={array_id} uri={uri}");
                            let remote_file = match uri.parse::<RemoteFile>() {
                                Ok(rf) => rf,
                                Err(e) => {
                                    log::warn!("PollJobStatus: invalid URI {uri}: {e}");
                                    continue;
                                }
                            };
                            log::info!("PollJobStatus: resolved host={}", remote_file.host);
                            let client = {
                                let read = clients.read().await;
                                read.get(remote_file.host.as_str()).cloned()
                            };
                            let client = match client {
                                Some(c) => c,
                                None => {
                                    log::warn!("PollJobStatus: no client for host {}", remote_file.host);
                                    continue;
                                }
                            };
                            log::info!("PollJobStatus: found client for host={}, spawning poll loop for job_id={array_id}", remote_file.host);
                            let event_tx = event_tx.clone();
                            tokio::spawn(async move {
                                log::info!("PollJobStatus: poll loop started for job_id={array_id}");
                                loop {
                                    log::info!("PollJobStatus: sleeping 30s before next poll for job_id={array_id}");
                                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                                    log::info!("PollJobStatus: polling running tasks for job_id={array_id}");
                                    let running = match poll_running_tasks(&client, array_id).await {
                                        Ok(n) => n,
                                        Err(e) => {
                                            log::warn!("Failed to poll job {array_id}: {e}");
                                            break;
                                        }
                                    };
                                    log::info!("PollJobStatus: job_id={array_id} has {running} running tasks");
                                    if event_tx
                                        .send(Event::JobStatusUpdate(uri.clone(), array_id, running))
                                        .is_err()
                                    {
                                        log::warn!("PollJobStatus: event_tx send failed for job_id={array_id}, stopping poll loop");
                                        break;
                                    }
                                    if running == 0 {
                                        log::info!("PollJobStatus: job_id={array_id} completed (0 running tasks), stopping poll loop");
                                        break;
                                    }
                                }
                                log::info!("PollJobStatus: poll loop exited for job_id={array_id}");
                            });
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

    fn download_file(&self, paths: Box<[PathBuf]>, uris: Vec<String>, to: PathBuf, zip_output: Option<PathBuf>) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::perform(
            async move {
                let (res_tx, res_rx) = tokio::sync::oneshot::channel();

                command_tx
                    .send(Cmd::Download(paths, uris, to, zip_output, res_tx))
                    .unwrap();
                res_rx.await
            },
            |x| {
                if let Err(err) = x {
                    log::error!("{err:?}");
                }
            },
        )
    }

    fn remote_scan(
        &self,
        uri: &str,
        sizes: IconSizes,
    ) -> Option<Result<Vec<tab::Item>, String>> {
        let (items_tx, mut items_rx) = mpsc::channel(1);

        if let Err(e) = self.command_tx.send(Cmd::RemoteScan(
            uri.to_string(),
            sizes,
            items_tx,
        )) {
            log::error!(
                "remote_scan: failed to send Cmd::RemoteScan for uri {}: {}",
                uri,
                e
            );
            return Some(Err("command channel closed".into()));
        }

        items_rx.blocking_recv()
    }

    fn remote_parent_item(&self, uri: &str, sizes: IconSizes) -> Option<Result<tab::Item, String>> {
        let (items_tx, mut items_rx) = mpsc::channel(1);

        if let Err(e) = self
            .command_tx
            .send(Cmd::RemoteParent(uri.to_string(), sizes, items_tx))
        {
            log::error!(
                "remote_parent: failed to send Cmd::RemoteParent for uri {}: {}",
                uri,
                e
            );
            return Some(Err("command channel closed".into()));
        }

        items_rx.blocking_recv()
    }

    fn dir_info(&self, uri: &str) -> Option<(String, String, Option<PathBuf>)> {
        let (result_tx, mut result_rx) = mpsc::channel(1);
        self.command_tx
            .send(Cmd::DirInfo(uri.to_string(), result_tx))
            .unwrap();
        result_rx.blocking_recv().and_then(|res| res.ok())
    }

    fn disconnect(&self, item: ClientItem) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::future(async move {
            command_tx.send(Cmd::Disconnect(item)).unwrap();
        })
    }

    fn run_tb_profiler(
        &self,
        paths: Box<[PathBuf]>,
        uris: Vec<String>,
        tb_config: TBConfig,
    ) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::perform(
            async move {
                let (res_tx, res_rx) = tokio::sync::oneshot::channel();

                command_tx
                    .send(Cmd::RunTbProfiler(paths, uris, tb_config, res_tx))
                    .unwrap();

                res_rx.await
            },
            |x| match x {
                Ok(Ok(job)) => log::info!("TBProfiler started: job_id={}, tasks={}", job.array_id, job.tasks),
                Ok(Err(err)) => log::error!("TBProfiler failed: {err}"),
                Err(err) => log::error!("Channel error: {err}"),
            },
        )
    }

    fn delete_remote_files(&self, paths: Box<[PathBuf]>, uris: Vec<String>) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::perform(
            async move {
                let (res_tx, res_rx) = tokio::sync::oneshot::channel();

                command_tx
                    .send(Cmd::DeleteRemoteFiles(paths, uris, res_tx))
                    .unwrap();

                res_rx.await
            },
            |x| match x {
                Ok(Ok(msg)) => log::info!("Remote files deleted: {msg}"),
                Ok(Err(err)) => log::error!("Remote file deletion failed: {err}"),
                Err(err) => log::error!("Channel error: {err}"),
            },
        )
    }

    fn poll_job_status(&self, job_id: usize, uri: String) -> Task<()> {
        log::info!("poll_job_status: invoked with job_id={job_id} uri={uri}");
        let command_tx = self.command_tx.clone();
        Task::future(async move {
            log::info!("poll_job_status: sending Cmd::PollJobStatus job_id={job_id} uri={uri}");
            command_tx.send(Cmd::PollJobStatus(job_id, uri)).unwrap();
            log::info!("poll_job_status: Cmd::PollJobStatus sent successfully for job_id={job_id}");
        })
    }

    fn delete_tb_profiler_results(&self, uri: String, tb_config: TBConfig) -> Task<()> {
        let command_tx = self.command_tx.clone();
        Task::perform(
            async move {
                let (res_tx, res_rx) = tokio::sync::oneshot::channel();

                command_tx
                    .send(Cmd::DeleteTbProfilerResults(uri, tb_config, res_tx))
                    .unwrap();

                res_rx.await
            },
            |x| match x {
                Ok(Ok(msg)) => log::info!("TBProfiler results deleted: {msg}"),
                Ok(Err(err)) => log::error!("TBProfiler deletion failed: {err}"),
                Err(err) => log::error!("Channel error: {err}"),
            },
        )
    }

    fn subscription(&self) -> Subscription<ClientMessage> {
        let command_tx = self.command_tx.clone();
        let event_rx = self.event_rx.clone();
        struct Wrapper {
            command_tx: mpsc::UnboundedSender<Cmd>,
            event_rx: Arc<Mutex<mpsc::UnboundedReceiver<Event>>>,
        }
        impl Hash for Wrapper {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                TypeId::of::<Self>().hash(state);
            }
        }
        Subscription::run_with(
            Wrapper {
                command_tx,
                event_rx,
            },
            |Wrapper {
                 command_tx,
                 event_rx,
             }| {
                let command_tx = command_tx.clone();
                let event_rx = event_rx.clone();
                stream::channel(
                    1,
                    move |mut output: cosmic::iced::futures::channel::mpsc::Sender<
                        ClientMessage,
                    >| async move {
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
                                Event::RunTbProfilerResult(uri, res) => output
                                    .send(ClientMessage::RunTbProfilerResult(uri, res))
                                    .await
                                    .unwrap(),
                                Event::DeleteRemoteFilesResult(uri, res) => output
                                    .send(ClientMessage::DeleteRemoteFilesResult(uri, res))
                                    .await
                                    .unwrap(),
                                Event::JobStatusUpdate(uri, array_id, running_tasks) => output
                                    .send(ClientMessage::JobStatusUpdate(uri, array_id, running_tasks))
                                    .await
                                    .unwrap(),
                            }
                        }
                        pending().await
                    },
                )
            },
        )
    }
}
