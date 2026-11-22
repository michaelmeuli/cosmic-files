# Sequencing Cache Architecture

## Layer 1 — Disk cache (SQLite)

`scan_ab1_directory` and `analyse_ab1_for_preview` store one row per analysed AB1 file in an SQLite database (`DiskCache`, `disk_cache.rs`):

| column | meaning |
|---|---|
| `path` | canonical path (primary key; same key as `AB1_SEQ_CACHE`) |
| `mtime_secs`, `file_size` | staleness check |
| `version` | `ANALYSIS_VERSION` the record was produced with |
| `record` | `SampleSusceptibilityRecord` as serde_json text |

**Hit condition:** mtime, size and version match, the record has non-empty `seq_id_hits`, and `cached_record_current` holds (the gene the filename parser assigns hasn't changed).

**On hit:** loads the stored record directly, without running alignment.

**On miss or stale:** runs the full pipeline (AB1 parse → quality trim → alignment → resistance calls), then upserts the row. During a scan, upserts are committed in transactions of 20, so an interrupted first scan keeps most of its progress.

**Two passes:** the scan first walks the whole tree and serves every hit, collecting the misses. It aligns the misses only afterwards, so no cached result waits behind a slow alignment.

**Startup preload:** `preload_disk_cache` loads every current row of the scan cache(s) (`scan_cache_files`) into the in-memory caches in one query. A row is current when its file still exists with the same mtime and size and `cached_record_current` holds. The preload runs at launch (`Message::PreloadAb1Cache`), ahead of the scan, which may first wait for a Microsynth sync. It is read-only: it never writes or prunes.

**Pruning:** after a scan, rows for paths under the scan directory that the scan didn't see are deleted. This covers deleted files, renamed files and files outside `report_max_age_days`. Rows outside the scan directory are kept, so one database can serve several scan directories.

**Location:** `ab1_cache_path` (a directory, or a file; a legacy `*.json` name maps to `*.sqlite`), otherwise the user cache dir (`dirs::cache_dir()/cosmic-files`). Avoid cloud-synced folders: opening a database there logs a warning. A database that isn't readable is moved to `*.corrupt` and rebuilt.

**What is stored:** the scan record keeps the top 5 `SeqIdHit`s per reference source (the preview cache keeps all 10; a file the preview finds in a scan cache therefore shows 5), including the alignment rows (serialised as strings), so the preview panel can show alignments without re-running them. Two things are left out to keep rows small:
- pncA calls on every hit but the top one; only the top hit is ever read.
- `PncaSnpCall::resistance_alts`, which is a copy of the WHO catalogue entry and is looked up again on deserialisation.

---

## Layer 2 — In-memory cache (`AB1_SEQ_CACHE`)

A static `LazyLock<RwLock<HashMap<PathBuf, Vec<SeqIdHit>>>>` in `batch.rs`.

It is filled both on a disk-cache hit and after a fresh alignment. Only the top 10 `SeqIdHit`s per reference source are kept, already sorted by identity. The full hit list against every reference is never retained, because scanning many AB1 files would otherwise keep one unbounded hit list per file for the life of the process.

The key is the **canonical path** (with the `\\?\` prefix on Windows), so it matches what `item_from_entry` in `tab.rs` looks up when building file list items on the UI thread.

---

## How the two layers interlock

```
preload_disk_cache()  (startup, background thread)
  └─ all current scan-cache rows → AB1_SEQ_CACHE → tabs get Ab1CacheUpdated

scan_ab1_directory()  (background thread)
  ├─ pass 1: disk cache hit?  → populate AB1_SEQ_CACHE, return record
  ├─ pass 2: misses           → align → populate AB1_SEQ_CACHE → upsert row
  └─ end                      → commit, prune unseen rows; tabs get Ab1CacheUpdated

analyse_ab1_for_preview()  (selected AB1 item without stored hits)
  └─ AB1_SEQ_CACHE → scan cache(s) → preview cache → align (stored in preview cache)
       → Ab1Analysed stores the hits on the item and recomputes its susceptibility calls

tab::Message::Ab1CacheUpdated
  └─ listed AB1 items without stored hits take theirs from AB1_SEQ_CACHE (+ calls)

item_from_entry()     (UI thread, per file)
  └─ AB1_SEQ_CACHE.read().get(&canonical_path)
       → SeqIdHit list for preview panel (no alignment on UI thread)

Tab::seq_id_hits_cached()  (preview panel)
  ├─ stored hits on Item non-empty? → use those
  └─ else fall back to AB1_SEQ_CACHE lookup
```

A folder listing (`item_from_entry`) doesn't read AB1 files at all: an item starts with only its cached hits (`SeqData::read_opt` = `None`). The chromatogram, lengths and quality are read (`item::read_ab1`) on a worker thread when the file is first previewed (`tab::Message::Ab1Read`), separately from the alignment.

The key design constraint: alignment is too slow for the UI thread, so the background scan pre-computes results and the UI thread only does a hash map read.
