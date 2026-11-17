//! Download AB1 chromatograms from the Microsynth secure download area.
//!
//! Microsynth's "Secure Download FTP" (<https://shop.microsynth.com/SecureDownload/Ftp/Ftp>)
//! is an SFTP server at `shop.microsynth.com:22` that accepts the webshop username and
//! password. Results are delivered as one folder per order number containing `.zip`
//! archives. [`sync_ab1`] downloads new archives and extracts the `.ab1` files they hold
//! directly into `dest` (no order or archive subfolders); loose `.ab1` files are copied
//! there too. The local directory is then analysed by
//! [`super::batch::scan_ab1_directory`] as usual.
//!
//! The password is kept in the OS keyring ([`load_password`] / [`store_password`]),
//! never in the cosmic config.

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};
use russh_sftp::client::SftpSession;
use tokio::io::AsyncReadExt;

/// Microsynth SFTP host.
pub const HOST: &str = "shop.microsynth.com";
/// Microsynth SFTP port.
pub const PORT: u16 = 22;
/// Keyring service name under which the webshop password is stored.
const KEYRING_SERVICE: &str = "cosmic-files-microsynth";
/// File in `dest` recording which remote archives were already extracted.
const MANIFEST_NAME: &str = ".microsynth_sync.json";

/// Outcome of one [`sync_ab1`] run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncSummary {
    /// Remote files (archives or loose `.ab1`) fetched in this run.
    pub downloaded: usize,
    /// `.ab1` files written to disk (extracted from archives or copied).
    pub ab1_written: usize,
    /// Remote files skipped because they were already synced or too old.
    pub skipped: usize,
    pub failed: usize,
}

/// Reads the Microsynth password for `username` from the OS keyring.
pub fn load_password(username: &str) -> Option<String> {
    if username.is_empty() {
        return None;
    }
    keyring::Entry::new(KEYRING_SERVICE, username)
        .and_then(|e| e.get_password())
        .map_err(|e| {
            if !matches!(e, keyring::Error::NoEntry) {
                log::warn!("microsynth: keyring read failed: {e}");
            }
        })
        .ok()
        .filter(|p| !p.is_empty())
}

/// Stores the Microsynth password for `username` in the OS keyring.
pub fn store_password(username: &str, password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!username.is_empty(), "Microsynth username is empty");
    keyring::Entry::new(KEYRING_SERVICE, username)?.set_password(password)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteKind {
    Ab1,
    Zip,
}

/// A regular `.ab1` or `.zip` file found on the server.
#[derive(Debug, Clone)]
struct RemoteFile {
    /// Full remote path (`/` separated).
    remote: String,
    /// Path relative to the remote root, used to place output under `dest`.
    relative: String,
    size: u64,
    mtime: u64,
    kind: RemoteKind,
}

/// Remote archives already extracted: remote relative path → (size, mtime).
type Manifest = HashMap<String, (u64, u64)>;

fn has_ext(name: &str, ext: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// `true` when `name` has an `.ab1` extension (case-insensitive).
fn is_ab1(name: &str) -> bool {
    has_ext(name, "ab1")
}

fn remote_kind(name: &str) -> Option<RemoteKind> {
    if is_ab1(name) {
        Some(RemoteKind::Ab1)
    } else if has_ext(name, "zip") {
        Some(RemoteKind::Zip)
    } else {
        None
    }
}

/// Maps a `/`-separated relative path to a path below `dest`.
///
/// Returns `None` for anything that could escape `dest` (`..`, absolute paths,
/// drive prefixes) or that has no normal components at all.
fn local_path_for(dest: &Path, relative: &str) -> Option<PathBuf> {
    let mut out = dest.to_path_buf();
    let mut any = false;
    for part in relative.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        let mut comps = Path::new(part).components();
        match (comps.next(), comps.next()) {
            (Some(Component::Normal(c)), None) => {
                out.push(c);
                any = true;
            }
            _ => return None,
        }
    }
    any.then_some(out)
}

/// File name part of a `/`-separated remote path (`"4861178/x.ab1"` → `"x.ab1"`).
fn remote_file_name(relative: &str) -> &str {
    relative.rsplit('/').next().unwrap_or(relative)
}

/// `true` when the file is older than the reporting window and should not be fetched.
fn too_old(mtime: u64, max_age_days: u32, now: SystemTime) -> bool {
    if max_age_days == 0 || mtime == 0 {
        return false;
    }
    let file_time = UNIX_EPOCH + Duration::from_secs(mtime);
    now.duration_since(file_time)
        .is_ok_and(|age| age > Duration::from_secs(u64::from(max_age_days) * 86_400))
}

/// Decides whether a file with `size`/`mtime` may be written to `local`.
///
/// All files land in one flat directory, so two orders can deliver the same file
/// name. The newest version wins: write when the local file is missing, is older,
/// or has the same mtime but a different size. Never replace a newer local file.
fn should_write(local: &Path, size: u64, mtime: u64) -> bool {
    let Ok(meta) = std::fs::metadata(local) else {
        return true;
    };
    let local_mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    local_mtime < mtime || (local_mtime == mtime && meta.len() != size)
}

/// Picks the host-key check: verify against `~/.ssh/known_hosts` when it lists the
/// Microsynth host, otherwise accept the key (matching the rest of the russh client).
fn server_check() -> ServerCheckMethod {
    let known = dirs::home_dir()
        .map(|h| h.join(".ssh").join("known_hosts"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .is_some_and(|s| s.lines().any(|l| l.contains(HOST)));
    if known {
        ServerCheckMethod::DefaultKnownHostsFile
    } else {
        log::warn!(
            "microsynth: {HOST} not in ~/.ssh/known_hosts; host key is not verified \
             (run `ssh-keyscan {HOST} >> ~/.ssh/known_hosts` to pin it)"
        );
        ServerCheckMethod::NoCheck
    }
}

/// Lists `.ab1` and `.zip` files below the SFTP login directory.
///
/// Top-level directories are Microsynth order folders; those whose mtime is older
/// than `max_age_days` are skipped without being listed, which keeps a sync from
/// walking the whole order history every time.
async fn list_remote(
    sftp: &SftpSession,
    max_age_days: u32,
    now: SystemTime,
) -> anyhow::Result<Vec<RemoteFile>> {
    let root = sftp
        .canonicalize(".")
        .await
        .context("resolving remote home directory")?;
    let root = root.trim_end_matches('/').to_string();

    let mut found = Vec::new();
    let mut stack = vec![String::new()];
    let mut skipped_dirs = 0usize;
    while let Some(rel_dir) = stack.pop() {
        let remote_dir = if rel_dir.is_empty() {
            if root.is_empty() {
                "/".to_string()
            } else {
                root.clone()
            }
        } else {
            format!("{root}/{rel_dir}")
        };
        let entries = match sftp.read_dir(remote_dir.clone()).await {
            Ok(entries) => entries,
            Err(e) => {
                log::warn!("microsynth: cannot list {remote_dir}: {e}");
                continue;
            }
        };
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let rel = if rel_dir.is_empty() {
                name.clone()
            } else {
                format!("{rel_dir}/{name}")
            };
            let ft = entry.file_type();
            let meta = entry.metadata();
            let mtime = meta.mtime.map_or(0, u64::from);
            if ft.is_dir() {
                if rel_dir.is_empty() && too_old(mtime, max_age_days, now) {
                    skipped_dirs += 1;
                } else {
                    stack.push(rel);
                }
            } else if ft.is_file()
                && let Some(kind) = remote_kind(&name)
            {
                found.push(RemoteFile {
                    remote: format!("{root}/{rel}"),
                    relative: rel,
                    size: meta.size.unwrap_or(0),
                    mtime,
                    kind,
                });
            }
        }
    }
    log::debug!(
        "microsynth: {} candidate files, {skipped_dirs} old order folders skipped",
        found.len()
    );
    Ok(found)
}

/// Reads a whole remote file into memory.
async fn fetch(sftp: &SftpSession, file: &RemoteFile) -> anyhow::Result<Vec<u8>> {
    let mut remote = sftp
        .open(file.remote.clone())
        .await
        .with_context(|| format!("opening {}", file.remote))?;
    let mut buf = Vec::with_capacity(usize::try_from(file.size).unwrap_or(0));
    remote
        .read_to_end(&mut buf)
        .await
        .with_context(|| format!("reading {}", file.remote))?;
    Ok(buf)
}

/// Writes `data` to `local` via a `.part` file and sets its mtime (when non-zero).
fn write_file(local: &Path, data: &[u8], mtime: u64) -> anyhow::Result<()> {
    if let Some(parent) = local.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut part_name = local.as_os_str().to_owned();
    part_name.push(".part");
    let part = PathBuf::from(part_name);
    std::fs::write(&part, data)?;
    std::fs::rename(&part, local)?;
    if mtime != 0 {
        let ft = filetime::FileTime::from_unix_time(i64::try_from(mtime).unwrap_or(i64::MAX), 0);
        filetime::set_file_mtime(local, ft)?;
    }
    Ok(())
}

/// Extracts every `.ab1` entry of a zip archive directly into `out_dir`, dropping any
/// folders inside the archive. Extracted files get `mtime` so rescans hit the AB1 disk
/// cache. Returns the number of `.ab1` files written.
fn extract_ab1_from_zip(data: &[u8], out_dir: &Path, mtime: u64) -> anyhow::Result<usize> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).context("opening zip")?;
    let mut written = 0;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if !entry.is_file() {
            continue;
        }
        let Some(inner) = entry.enclosed_name() else {
            log::warn!("microsynth: unsafe zip entry {:?} skipped", entry.name());
            continue;
        };
        let Some(file_name) = inner.file_name().filter(|n| is_ab1(&n.to_string_lossy())) else {
            continue;
        };
        let local = out_dir.join(file_name);
        if !should_write(&local, entry.size(), mtime) {
            log::debug!("microsynth: keeping existing {}", local.display());
            continue;
        }
        let mut buf = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
        entry.read_to_end(&mut buf)?;
        write_file(&local, &buf, mtime)?;
        written += 1;
    }
    Ok(written)
}

fn load_manifest(dest: &Path) -> Manifest {
    std::fs::read_to_string(dest.join(MANIFEST_NAME))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_manifest(dest: &Path, manifest: &Manifest) {
    let res = serde_json::to_string_pretty(manifest)
        .map_err(anyhow::Error::from)
        .and_then(|s| write_file(&dest.join(MANIFEST_NAME), s.as_bytes(), 0));
    if let Err(e) = res {
        log::warn!("microsynth: writing manifest failed: {e:#}");
    }
}

/// Logs in to the Microsynth SFTP server and opens an SFTP session.
async fn connect(username: &str, password: &str) -> anyhow::Result<(Client, SftpSession)> {
    log::info!("microsynth: connecting to {HOST}:{PORT} as {username}");
    let client = Client::connect(
        (HOST, PORT),
        username,
        AuthMethod::with_password(password),
        server_check(),
    )
    .await
    .context("connecting to Microsynth SFTP")?;

    let channel = client.get_channel().await?;
    channel.request_subsystem(true, "sftp").await?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .context("starting SFTP session")?;
    Ok((client, sftp))
}

/// Syncs `.ab1` files from the Microsynth SFTP account into `dest`.
///
/// Order folders and files older than `max_age_days` (by remote mtime; `0` disables
/// the limit) are skipped. Zip archives already recorded in the manifest
/// (`dest/.microsynth_sync.json`) with the same size and mtime are not downloaded
/// again; loose `.ab1` files are skipped when the local copy matches.
/// A failure on a single file is logged and counted; it does not abort the sync.
pub async fn sync_ab1(
    username: &str,
    password: &str,
    dest: &Path,
    max_age_days: u32,
) -> anyhow::Result<SyncSummary> {
    let (client, sftp) = connect(username, password).await?;

    let now = SystemTime::now();
    let mut files = list_remote(&sftp, max_age_days, now).await?;
    // Newest first, so recent results are available even if a long first sync is cut short.
    files.sort_by_key(|f| std::cmp::Reverse(f.mtime));

    let mut manifest = load_manifest(dest);
    let mut summary = SyncSummary::default();
    for file in &files {
        if too_old(file.mtime, max_age_days, now) {
            summary.skipped += 1;
            continue;
        }
        let result = match file.kind {
            RemoteKind::Zip => {
                if manifest.get(&file.relative) == Some(&(file.size, file.mtime)) {
                    summary.skipped += 1;
                    continue;
                }
                let out_dir = dest.to_path_buf();
                match fetch(&sftp, file).await {
                    Ok(data) => {
                        summary.downloaded += 1;
                        let mtime = file.mtime;
                        tokio::task::spawn_blocking(move || {
                            extract_ab1_from_zip(&data, &out_dir, mtime)
                        })
                        .await
                        .map_err(anyhow::Error::from)
                        .and_then(|r| r)
                        .inspect(|_| {
                            manifest.insert(file.relative.clone(), (file.size, file.mtime));
                        })
                    }
                    Err(e) => Err(e),
                }
            }
            RemoteKind::Ab1 => {
                let Some(local) = local_path_for(dest, remote_file_name(&file.relative)) else {
                    log::warn!("microsynth: refusing unsafe remote path {}", file.relative);
                    summary.failed += 1;
                    continue;
                };
                if !should_write(&local, file.size, file.mtime) {
                    summary.skipped += 1;
                    continue;
                }
                match fetch(&sftp, file).await {
                    Ok(data) => {
                        summary.downloaded += 1;
                        write_file(&local, &data, file.mtime).map(|()| 1)
                    }
                    Err(e) => Err(e),
                }
            }
        };
        match result {
            Ok(n) => {
                log::debug!("microsynth: {} → {n} .ab1 file(s)", file.relative);
                summary.ab1_written += n;
            }
            Err(e) => {
                log::warn!("microsynth: {} failed: {e:#}", file.remote);
                summary.failed += 1;
            }
        }
    }
    save_manifest(dest, &manifest);

    let _ = sftp.close().await;
    let _ = client.disconnect().await;
    log::info!(
        "microsynth: sync done ({} downloaded, {} .ab1 written, {} skipped, {} failed)",
        summary.downloaded,
        summary.ab1_written,
        summary.skipped,
        summary.failed
    );
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Live check against the real server: logs in with `MICROSYNTH_USER` and the
    /// keyring password, lists order folders newer than `MICROSYNTH_MAX_AGE` days
    /// (default 30) and prints the contents of the newest zip. Writes nothing to disk.
    /// Run with `MICROSYNTH_USER=<user> cargo test -- --ignored microsynth_live --nocapture`.
    #[test]
    #[ignore = "needs network and Microsynth credentials"]
    fn microsynth_live() {
        let user = std::env::var("MICROSYNTH_USER").expect("set MICROSYNTH_USER");
        let max_age: u32 = std::env::var("MICROSYNTH_MAX_AGE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        let password = load_password(&user).expect("no password in keyring for this user");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (client, sftp) = connect(&user, &password).await.expect("login failed");
            let t = std::time::Instant::now();
            let mut files = list_remote(&sftp, max_age, SystemTime::now())
                .await
                .expect("listing failed");
            files.sort_by_key(|f| std::cmp::Reverse(f.mtime));
            println!(
                "{} files in the last {max_age} days (listed in {:?})",
                files.len(),
                t.elapsed()
            );
            for f in files.iter().take(5) {
                println!("  {} ({} bytes, mtime {})", f.relative, f.size, f.mtime);
            }
            if let Some(zip) = files.iter().find(|f| f.kind == RemoteKind::Zip) {
                let data = fetch(&sftp, zip).await.expect("download failed");
                let mut archive = zip::ZipArchive::new(Cursor::new(data)).expect("bad zip");
                println!("{} entries in {}:", archive.len(), zip.relative);
                for i in 0..archive.len().min(20) {
                    let e = archive.by_index(i).unwrap();
                    println!("    {:?} ({} bytes)", e.name(), e.size());
                }
            }
            let _ = sftp.close().await;
            let _ = client.disconnect().await;

            // Optional end-to-end run: sync twice into MICROSYNTH_SYNC_DIR.
            if let Ok(dir) = std::env::var("MICROSYNTH_SYNC_DIR") {
                let dir = PathBuf::from(dir);
                for run in 1..=2 {
                    let s = sync_ab1(&user, &password, &dir, max_age)
                        .await
                        .expect("sync");
                    println!("sync run {run}: {s:?}");
                }
            }
        });
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("microsynth_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ab1_filter() {
        assert!(is_ab1("sample_rrl.ab1"));
        assert!(is_ab1("SAMPLE.AB1"));
        assert!(!is_ab1("sample.ab1.part"));
        assert!(!is_ab1("sample.seq"));
        assert!(!is_ab1("ab1"));
        assert_eq!(remote_kind("x.ZIP"), Some(RemoteKind::Zip));
        assert_eq!(remote_kind("x.pdf"), None);
    }

    #[test]
    fn local_path_mapping() {
        let dest = Path::new("base");
        assert_eq!(
            local_path_for(dest, "order1/a.ab1"),
            Some(Path::new("base").join("order1").join("a.ab1"))
        );
        assert_eq!(
            local_path_for(dest, "./x//a.ab1"),
            Some(Path::new("base").join("x").join("a.ab1"))
        );
        assert_eq!(local_path_for(dest, "../a.ab1"), None);
        assert_eq!(local_path_for(dest, "x/../../a.ab1"), None);
        assert_eq!(local_path_for(dest, "x\\..\\..\\a.ab1"), None);
        assert_eq!(local_path_for(dest, ""), None);
        #[cfg(windows)]
        assert_eq!(local_path_for(dest, "C:/a.ab1"), None);
        assert_eq!(remote_file_name("4861178/x.ab1"), "x.ab1");
        assert_eq!(remote_file_name("x.ab1"), "x.ab1");
    }

    #[test]
    fn age_filter() {
        let now = UNIX_EPOCH + Duration::from_secs(100 * 86_400);
        assert!(too_old(10 * 86_400, 60, now));
        assert!(!too_old(50 * 86_400, 60, now));
        assert!(!too_old(10 * 86_400, 0, now));
        assert!(!too_old(0, 60, now));
    }

    #[test]
    fn write_decision() {
        let dir = temp_dir("decision");
        let f = dir.join("a.ab1");
        assert!(should_write(&f, 3, 1_000));
        std::fs::write(&f, b"abc").unwrap();
        filetime::set_file_mtime(&f, filetime::FileTime::from_unix_time(1_000, 0)).unwrap();
        assert!(!should_write(&f, 3, 1_000)); // identical
        assert!(should_write(&f, 4, 1_000)); // same time, different size
        assert!(should_write(&f, 3, 2_000)); // newer remote
        assert!(!should_write(&f, 9, 500)); // older remote never overwrites
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut zw = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default();
        for (name, body) in entries {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(body).unwrap();
        }
        zw.finish().unwrap();
        buf.into_inner()
    }

    #[test]
    fn zip_extraction_is_flat_and_keeps_only_ab1() {
        let data = make_zip(&[
            ("run1/s1_rrl.ab1", b"AB1A"),
            ("run1/s1_rrl.seq", b"ACGT"),
            ("s2.AB1", b"AB1B"),
            ("report.pdf", b"%PDF"),
        ]);
        let dir = temp_dir("zip");
        let n = extract_ab1_from_zip(&data, &dir, 1_700_000_000).unwrap();
        assert_eq!(n, 2);
        assert_eq!(std::fs::read(dir.join("s1_rrl.ab1")).unwrap(), b"AB1A");
        assert_eq!(std::fs::read(dir.join("s2.AB1")).unwrap(), b"AB1B");
        // No folders are created, and non-AB1 entries are ignored.
        let subdirs = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().path().is_dir())
            .count();
        assert_eq!(subdirs, 0);
        assert!(!dir.join("s1_rrl.seq").exists());
        assert!(!dir.join("report.pdf").exists());
        // Second extraction writes nothing: files already match.
        assert_eq!(extract_ab1_from_zip(&data, &dir, 1_700_000_000).unwrap(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn older_archive_does_not_overwrite_newer_file() {
        let dir = temp_dir("collide");
        let newer = make_zip(&[("x.ab1", b"NEW")]);
        let older = make_zip(&[("x.ab1", b"OLD-VERSION")]);
        assert_eq!(
            extract_ab1_from_zip(&newer, &dir, 2_000_000_000).unwrap(),
            1
        );
        assert_eq!(
            extract_ab1_from_zip(&older, &dir, 1_000_000_000).unwrap(),
            0
        );
        assert_eq!(std::fs::read(dir.join("x.ab1")).unwrap(), b"NEW");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
