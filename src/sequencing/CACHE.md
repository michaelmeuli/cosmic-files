# Sequencing Cache Architecture

## Layer 1 — Disk cache (JSON file)

`scan_ab1_directory` maintains a `HashMap<path_string, (mtime_secs, SampleSusceptibilityRecord)>` serialised to a JSON file (the `cache_path` argument).

**Hit condition:** `mtime_secs` of the file on disk matches the cached value **and** `seq_id_hits` is non-empty.

**On hit:** loads the stored `SampleSusceptibilityRecord` directly — no alignment runs.

**On miss/stale:** runs the full pipeline (AB1 parse → quality trim → k-mer alignment → resistance calls), then writes the new entry back.

**Dirty-write:** the JSON file is only rewritten when at least one entry changed (`cache_dirty` flag), so unchanged scans don't write to disk.

The top 5 `SeqIdHit`s are stored in the record (`batch.rs:294`) — alignment strings are preserved so the preview panel can display them without re-running alignment.

---

## Layer 2 — In-memory cache (`AB1_SEQ_CACHE`)

A static `LazyLock<RwLock<HashMap<PathBuf, Vec<SeqIdHit>>>>` (`batch.rs:22-23`).

Populated **both** on a disk-cache hit (`batch.rs:165-166`) and after a fresh alignment (`batch.rs:230-231`).

The key is the **canonical path** (with `\\?\` prefix on Windows) so it matches what `item_from_entry` in `tab.rs:944` looks up when building file list items on the UI thread.

---

## How the two layers interlock

```
scan_ab1_directory()  (background thread)
  ├─ disk cache hit?  → populate AB1_SEQ_CACHE, return record
  └─ miss             → align → populate AB1_SEQ_CACHE → write disk cache

item_from_entry()     (UI thread, per file)
  └─ AB1_SEQ_CACHE.read().get(&canonical_path)
       → SeqIdHit list for preview panel (no alignment on UI thread)

Tab::seq_id_hits_cached()  (preview panel)
  ├─ stored hits on Item non-empty? → use those
  └─ else fall back to AB1_SEQ_CACHE lookup
```

The key design constraint: alignment (Smith-Waterman + k-mer seeding) is too slow for the UI thread, so the background scan pre-computes results and the UI thread only does a hash map read.
