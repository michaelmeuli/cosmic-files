//! SQLite-backed on-disk cache of analysed AB1 files: one row per file, keyed by canonical path.
//!
//! Replaces the earlier single JSON file, which was re-read and fully rewritten on every scan
//! that found a new file (25–50 MB for ~900 files), wasn't written atomically, and never dropped
//! entries for deleted files. Here each analysed file is one upsert, writes are transactional,
//! and [`DiskCache::prune_under`] removes rows for files a scan no longer sees.
//!
//! The record itself stays serde_json text in the `record` column: it is already `Serialize`,
//! readable with the `sqlite3` CLI, and nothing queries inside it.

use super::batch::{ANALYSIS_VERSION, SampleSusceptibilityRecord};
use rusqlite::{Connection, ErrorCode, OptionalExtension, params};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Bumped when the table layout changes; a database with another `user_version` is recreated.
const SCHEMA_VERSION: i64 = 1;

/// Uncommitted upserts after which a batch is committed, so a long first scan that crashes
/// keeps most of its progress.
const BATCH_COMMIT_EVERY: usize = 20;

/// Folder names of cloud-sync clients, where SQLite's lock/journal files can be synced
/// mid-write and corrupt the database.
const SYNCED_FOLDER_MARKERS: [&str; 4] = ["OneDrive", "Dropbox", "Google Drive", "iCloud"];

pub(crate) struct DiskCache {
    conn: Connection,
    path: PathBuf,
    /// `Some(n)` while a batch transaction is open, `n` being its uncommitted upserts.
    batch: Option<usize>,
}

impl DiskCache {
    /// Opens (or creates) the cache at `path`. A file that isn't a usable SQLite database is
    /// renamed to `<name>.corrupt` and replaced by a fresh one. Returns `None`, after logging,
    /// if the cache can't be opened at all; callers then run uncached.
    pub(crate) fn open(path: &Path) -> Option<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            log::warn!("ab1 cache: failed to create {}: {e}", parent.display());
            return None;
        }
        let path_str = path.to_string_lossy();
        if SYNCED_FOLDER_MARKERS.iter().any(|m| path_str.contains(m)) {
            log::warn!(
                "ab1 cache: {} is in a cloud-synced folder; syncing an SQLite database while it \
                 is written can corrupt it. Point the cache path at a local folder.",
                path.display()
            );
        }
        let old_json = path.with_extension("json");
        if old_json.is_file() {
            log::info!(
                "ab1 cache: {} is no longer used (replaced by {}) and can be deleted",
                old_json.display(),
                path.display()
            );
        }

        match Self::try_open(path) {
            Ok(cache) => Some(cache),
            Err(e) if is_corruption(&e) => {
                let corrupt = path.with_extension("corrupt");
                log::warn!(
                    "ab1 cache: {} is unreadable ({e}); moving it to {} and starting afresh",
                    path.display(),
                    corrupt.display()
                );
                if let Err(e) = std::fs::rename(path, &corrupt) {
                    log::warn!("ab1 cache: failed to move corrupt cache aside: {e}");
                    return None;
                }
                Self::try_open(path)
                    .inspect_err(|e| {
                        log::warn!("ab1 cache: failed to open {}: {e}", path.display());
                    })
                    .ok()
            }
            Err(e) => {
                log::warn!("ab1 cache: failed to open {}: {e}", path.display());
                None
            }
        }
    }

    /// Like [`Self::open`], but `None` when no database exists at `path` yet, so a lookup in a
    /// cache that was never written doesn't create an empty file.
    pub(crate) fn open_existing(path: &Path) -> Option<Self> {
        if path.is_file() {
            Self::open(path)
        } else {
            None
        }
    }

    fn try_open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        // Rollback journal rather than WAL: no long-lived -wal/-shm side files, which matters
        // when the cache sits on a network share.
        conn.pragma_update(None, "journal_mode", "DELETE")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != SCHEMA_VERSION {
            conn.execute_batch("DROP TABLE IF EXISTS ab1_record;")?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ab1_record (
                 path       TEXT PRIMARY KEY NOT NULL,
                 mtime_secs INTEGER NOT NULL,
                 file_size  INTEGER NOT NULL,
                 version    INTEGER NOT NULL,
                 record     TEXT NOT NULL
             );",
        )?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
            batch: None,
        })
    }

    /// The cached record for `key` if it was stored for this exact `mtime_secs`/`file_size`
    /// by the current [`ANALYSIS_VERSION`].
    pub(crate) fn get(
        &self,
        key: &str,
        mtime_secs: u64,
        file_size: u64,
    ) -> Option<SampleSusceptibilityRecord> {
        let row: Option<String> = self
            .conn
            .query_row(
                "SELECT record FROM ab1_record
                 WHERE path = ?1 AND mtime_secs = ?2 AND file_size = ?3 AND version = ?4",
                params![key, to_i64(mtime_secs), to_i64(file_size), ANALYSIS_VERSION],
                |r| r.get(0),
            )
            .optional()
            .inspect_err(|e| log::warn!("ab1 cache: lookup failed in {}: {e}", self.display()))
            .ok()
            .flatten();
        let json = row?;
        serde_json::from_str(&json)
            .inspect_err(|e| log::warn!("ab1 cache: dropping undecodable row {key}: {e}"))
            .ok()
    }

    /// Every row written by the current [`ANALYSIS_VERSION`], as `(key, mtime_secs, file_size,
    /// record)`, in one query. Rows that don't decode are skipped. Callers check the stamps
    /// against the files themselves.
    pub(crate) fn load_current(&self) -> Vec<(String, u64, u64, SampleSusceptibilityRecord)> {
        let mut stmt = match self.conn.prepare(
            "SELECT path, mtime_secs, file_size, record FROM ab1_record WHERE version = ?1",
        ) {
            Ok(stmt) => stmt,
            Err(e) => {
                log::warn!("ab1 cache: load query failed in {}: {e}", self.display());
                return Vec::new();
            }
        };
        let rows = stmt.query_map(params![ANALYSIS_VERSION], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        });
        let Ok(rows) = rows else {
            return Vec::new();
        };
        rows.filter_map(Result::ok)
            .filter_map(|(key, mtime, size, json)| {
                let record = serde_json::from_str(&json)
                    .inspect_err(|e| log::warn!("ab1 cache: skipping undecodable row {key}: {e}"))
                    .ok()?;
                Some((
                    key,
                    u64::try_from(mtime).unwrap_or(0),
                    u64::try_from(size).unwrap_or(0),
                    record,
                ))
            })
            .collect()
    }

    /// Stores `record` for `key`, replacing any previous row. Inside a batch
    /// ([`Self::begin_batch`]) it is committed with the batch; otherwise immediately.
    pub(crate) fn put(
        &mut self,
        key: &str,
        mtime_secs: u64,
        file_size: u64,
        record: &SampleSusceptibilityRecord,
    ) {
        let json = match serde_json::to_string(record) {
            Ok(json) => json,
            Err(e) => {
                log::warn!("ab1 cache: failed to serialise record for {key}: {e}");
                return;
            }
        };
        if let Err(e) = self.conn.execute(
            "INSERT INTO ab1_record (path, mtime_secs, file_size, version, record)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(path) DO UPDATE SET
                 mtime_secs = excluded.mtime_secs,
                 file_size  = excluded.file_size,
                 version    = excluded.version,
                 record     = excluded.record",
            params![
                key,
                to_i64(mtime_secs),
                to_i64(file_size),
                ANALYSIS_VERSION,
                json
            ],
        ) {
            log::warn!(
                "ab1 cache: failed to write {key} to {}: {e}",
                self.display()
            );
            return;
        }
        if let Some(pending) = &mut self.batch {
            *pending += 1;
            if *pending >= BATCH_COMMIT_EVERY {
                self.commit_batch();
                self.begin_batch();
            }
        }
    }

    /// Starts grouping [`Self::put`]s into transactions of up to [`BATCH_COMMIT_EVERY`] rows.
    pub(crate) fn begin_batch(&mut self) {
        if self.batch.is_some() {
            return;
        }
        match self.conn.execute_batch("BEGIN") {
            Ok(()) => self.batch = Some(0),
            Err(e) => log::warn!("ab1 cache: failed to begin transaction: {e}"),
        }
    }

    /// Commits the open batch, if any. Also done on drop.
    pub(crate) fn commit_batch(&mut self) {
        if self.batch.take().is_some()
            && let Err(e) = self.conn.execute_batch("COMMIT")
        {
            log::warn!("ab1 cache: failed to commit {}: {e}", self.display());
        }
    }

    /// Deletes rows for files under `root` whose key isn't in `keep`, i.e. files a scan of
    /// `root` no longer found (deleted, renamed, or outside the age window). Rows outside
    /// `root` are left alone, so one database can serve several scan directories. Returns the
    /// number of rows deleted.
    pub(crate) fn prune_under(&mut self, root: &Path, keep: &HashSet<String>) -> usize {
        let stale: Vec<String> = {
            let mut stmt = match self.conn.prepare("SELECT path FROM ab1_record") {
                Ok(stmt) => stmt,
                Err(e) => {
                    log::warn!("ab1 cache: prune query failed: {e}");
                    return 0;
                }
            };
            let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) else {
                return 0;
            };
            rows.filter_map(Result::ok)
                .filter(|p| Path::new(p).starts_with(root) && !keep.contains(p))
                .collect()
        };
        let mut deleted = 0;
        for path in &stale {
            match self
                .conn
                .execute("DELETE FROM ab1_record WHERE path = ?1", params![path])
            {
                Ok(n) => deleted += n,
                Err(e) => log::warn!("ab1 cache: failed to prune {path}: {e}"),
            }
        }
        deleted
    }

    /// The database file this cache was opened from.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn display(&self) -> std::path::Display<'_> {
        self.path.display()
    }
}

impl Drop for DiskCache {
    fn drop(&mut self) {
        self.commit_batch();
    }
}

/// `true` for errors meaning the file exists but isn't a usable SQLite database.
fn is_corruption(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt)
    )
}

/// SQLite integers are signed; mtimes and sizes never get near `i64::MAX`.
fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sequencing::SusceptibilityCalls;

    fn record(name: &str) -> SampleSusceptibilityRecord {
        SampleSusceptibilityRecord {
            sample_id: name.to_string(),
            gene: Some("16S".to_string()),
            file_name: format!("{name}-16S.ab1"),
            file_path: PathBuf::from(name),
            file_created: None,
            susceptibility_calls: SusceptibilityCalls::default(),
            species: Some("Mycobacterium kansasii".to_string()),
            identity: Some(99.5),
            species_gtdb: None,
            identity_gtdb: None,
            is_susceptible: None,
            seq_id_hits: Vec::new(),
            analysis_version: ANALYSIS_VERSION,
        }
    }

    #[test]
    fn put_get_round_trip_and_staleness() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = DiskCache::open(&dir.path().join("c.sqlite")).unwrap();
        cache.put("a", 10, 100, &record("a"));

        let got = cache.get("a", 10, 100).expect("hit");
        assert_eq!(got.sample_id, "a");
        assert_eq!(got.species.as_deref(), Some("Mycobacterium kansasii"));
        assert!(cache.get("a", 11, 100).is_none(), "mtime changed");
        assert!(cache.get("a", 10, 101).is_none(), "size changed");
        assert!(cache.get("b", 10, 100).is_none(), "unknown key");

        // Upsert replaces the row.
        let mut newer = record("a");
        newer.identity = Some(98.0);
        cache.put("a", 12, 100, &newer);
        assert!(cache.get("a", 10, 100).is_none());
        assert_eq!(cache.get("a", 12, 100).unwrap().identity, Some(98.0));
    }

    #[test]
    fn rows_of_another_analysis_version_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(&dir.path().join("c.sqlite")).unwrap();
        cache
            .conn
            .execute(
                "INSERT INTO ab1_record VALUES ('a', 1, 1, ?1, '{}')",
                params![ANALYSIS_VERSION - 1],
            )
            .unwrap();
        assert!(cache.get("a", 1, 1).is_none());
    }

    #[test]
    fn load_current_returns_only_current_version_rows() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = DiskCache::open(&dir.path().join("c.sqlite")).unwrap();
        cache.put("a", 10, 100, &record("a"));
        cache
            .conn
            .execute(
                "INSERT INTO ab1_record VALUES ('old', 1, 1, ?1, '{}')",
                params![ANALYSIS_VERSION - 1],
            )
            .unwrap();
        let rows = cache.load_current();
        assert_eq!(rows.len(), 1);
        let (key, mtime, size, rec) = &rows[0];
        assert_eq!((key.as_str(), *mtime, *size), ("a", 10, 100));
        assert_eq!(rec.sample_id, "a");
    }

    #[test]
    fn open_existing_does_not_create_a_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.sqlite");
        assert!(DiskCache::open_existing(&path).is_none());
        assert!(!path.exists());
        DiskCache::open(&path).unwrap();
        assert!(DiskCache::open_existing(&path).is_some());
    }

    #[test]
    fn batch_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.sqlite");
        {
            let mut cache = DiskCache::open(&path).unwrap();
            cache.begin_batch();
            for i in 0..(BATCH_COMMIT_EVERY * 2 + 3) {
                cache.put(&format!("f{i}"), 1, 1, &record("x"));
            }
            // Dropped with a batch still open: Drop commits it.
        }
        let cache = DiskCache::open(&path).unwrap();
        assert!(cache.get("f0", 1, 1).is_some());
        assert!(
            cache
                .get(&format!("f{}", BATCH_COMMIT_EVERY * 2 + 2), 1, 1)
                .is_some()
        );
    }

    #[test]
    fn prune_only_touches_unseen_rows_under_root() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = DiskCache::open(&dir.path().join("c.sqlite")).unwrap();
        let root = dir.path().join("scan");
        let other = dir.path().join("other");
        let kept = root.join("kept.ab1").to_string_lossy().into_owned();
        let gone = root
            .join("sub")
            .join("gone.ab1")
            .to_string_lossy()
            .into_owned();
        let elsewhere = other.join("x.ab1").to_string_lossy().into_owned();
        for key in [&kept, &gone, &elsewhere] {
            cache.put(key, 1, 1, &record("x"));
        }

        let keep = HashSet::from([kept.clone()]);
        assert_eq!(cache.prune_under(&root, &keep), 1);
        assert!(cache.get(&kept, 1, 1).is_some());
        assert!(cache.get(&gone, 1, 1).is_none());
        assert!(cache.get(&elsewhere, 1, 1).is_some(), "outside root");
    }

    #[test]
    fn corrupt_file_is_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.sqlite");
        std::fs::write(
            &path,
            b"definitely not an sqlite database, just some text padding",
        )
        .unwrap();

        let mut cache = DiskCache::open(&path).expect("recreated");
        cache.put("a", 1, 1, &record("a"));
        assert!(cache.get("a", 1, 1).is_some());
        assert!(path.with_extension("corrupt").is_file());
    }
}
