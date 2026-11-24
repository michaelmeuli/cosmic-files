//! Batch scanning of a directory of AB1 files into per-sample susceptibility records.
//!
//! [`scan_ab1_directory`] is the entry point: it walks a directory tree, infers each file's gene
//! from its filename ([`parse_ab1_filename`]), runs the appropriate `identify_sequence_*` from
//! the gene-specific modules, and combines the resulting hits into one
//! [`SampleSusceptibilityRecord`] per file — with both an in-memory cache
//! ([`AB1_SEQ_CACHE`], shared with the interactive single-file view) and an optional on-disk
//! SQLite cache ([`DiskCache`]) keyed by canonical path and checked against file mtime and size,
//! so re-scanning an unchanged directory is cheap.
//! [`analyse_ab1_for_preview`] runs the same per-file pipeline on demand for files outside the
//! scan directories, with its own disk cache (`ab1_preview_cache.sqlite`).
//! [`write_ab1_csv`] and [`write_rare_mutations_csv`] export the results.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

pub use super::ab1_filename::{Ab1Gene, RpoBRegion, parse_ab1_filename};
use super::{
    DESC_MASSILIENSE, MIN_SEQ_ID_IDENTITY, RefSource, SeqIdHit, SusceptibilityCalls, best_snp_hit,
    disk_cache::DiskCache,
    erm41::{Erm41SusceptibilityCalls, identify_sequence_erm41, is_susceptible_erm41},
    hits_from,
    hsp65::identify_sequence_hsp65,
    parse_ab1_quality, parse_ab1_sequence,
    pnca::{PncaSusceptibilityCalls, identify_sequence_pnca, is_susceptible_pnca},
    rpob::{RpobSusceptibilityCalls, identify_sequence_rpob, is_susceptible_rpob},
    rrl::{
        RrlSusceptibilityCalls, identify_sequence_rrl_ntm, is_susceptible_rrl,
        is_susceptible_rrl_by_snp_calls_rare,
    },
    rrs::{
        RrsSusceptibilityCalls, identify_sequence_16s, is_susceptible_rrs,
        is_susceptible_rrs_by_snp_calls_rare,
    },
    rrs3end::{
        RrsSusceptibilityCalls3End, identify_sequence_16s3end, is_susceptible_rrs_3end,
        is_susceptible_rrs_by_snp_calls_rare_3end,
    },
    species_group, trim_to_min_quality, truncate_per_source,
};

/// Worker pool for the scan's alignments (pass 2 of [`scan_ab1_directory`]). Shared by both
/// scan directories, so two concurrent scans together never use more than half the logical
/// cores (1..=8), leaving room for the UI, thumbnailer and preview alignments. Preview
/// alignments ([`analyse_ab1_for_preview`]) don't use it, so they never queue behind a scan.
static SCAN_POOL: LazyLock<Option<rayon::ThreadPool>> = LazyLock::new(|| {
    let threads = (num_cpus::get() / 2).clamp(1, 8);
    match rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("ab1-align-{i}"))
        .build()
    {
        Ok(pool) => Some(pool),
        Err(e) => {
            log::warn!("ab1_scan: failed to build alignment thread pool, aligning serially: {e}");
            None
        }
    }
});

/// Hits in [`AB1_SEQ_CACHE`], with the stamp of the file they were computed for.
pub(crate) struct CachedHits {
    /// `(mtime_secs, file_size)` from [`file_stamp`].
    stamp: (u64, u64),
    pub(crate) hits: Vec<SeqIdHit>,
}

/// In-memory cache: maps each AB1 file's canonical path to its top seq_id_hits (by identity),
/// from a scan, the disk caches or a preview alignment. `item_from_entry()` reads from this
/// cache instead of running alignment on the UI thread. Read it with [`cached_hits`], which
/// ignores entries computed for an older version of the file.
pub(crate) static AB1_SEQ_CACHE: LazyLock<RwLock<HashMap<PathBuf, CachedHits>>> =
    LazyLock::new(|| RwLock::new(HashMap::default()));

/// The [`AB1_SEQ_CACHE`] hits for `path` (canonical), if they were computed for the file as
/// `meta` describes it (same mtime and size). No file I/O, so callers on the UI thread pass the
/// metadata they already have.
pub(crate) fn cached_hits(path: &Path, meta: &std::fs::Metadata) -> Option<Vec<SeqIdHit>> {
    let guard = AB1_SEQ_CACHE.read().ok()?;
    let entry = guard.get(path)?;
    (entry.stamp == file_stamp(Some(meta))).then(|| entry.hits.clone())
}

fn insert_hits(canonical_path: PathBuf, stamp: (u64, u64), hits: Vec<SeqIdHit>) {
    if let Ok(mut guard) = AB1_SEQ_CACHE.write() {
        guard.insert(canonical_path, CachedHits { stamp, hits });
    }
}

/// Sample-id → 16S seq_id_hits, populated by [`scan_ab1_directory`]. Unlike `AB1_SEQ_CACHE`
/// (keyed by path), this lets a sibling file look up its sample's 16S species even when the
/// 16S AB1 lives in a different directory than the file being previewed.
pub(crate) static SIXTEEN_S_HITS_CACHE: LazyLock<RwLock<HashMap<String, Vec<SeqIdHit>>>> =
    LazyLock::new(|| RwLock::new(HashMap::default()));

/// File name of the on-disk cache for AB1 files aligned on demand by the preview panel, kept
/// separate from the scan caches so they only ever hold files from their own scan directory.
const PREVIEW_CACHE_FILE_NAME: &str = "ab1_preview_cache.sqlite";

/// The preview disk cache, opened on first use. [`DiskCache::path`] tells whether a changed
/// `ab1_cache_path` setting requires reopening.
static PREVIEW_DISK_CACHE: LazyLock<Mutex<Option<DiskCache>>> = LazyLock::new(|| Mutex::new(None));

/// Default directory for the disk caches when no `ab1_cache_path` is configured: the local
/// user cache dir, so the SQLite files stay out of (possibly cloud-synced) data folders.
fn default_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("cosmic-files")
}

/// Location of a scan's disk cache for the `ab1_cache_path` setting, which may name a
/// directory (the cache is `file_name` inside it) or a cache file. A legacy `.json` cache file
/// name maps to the same name with `.sqlite`. Empty → [`default_cache_dir`].
pub fn scan_cache_file(ab1_cache_path: &str, file_name: &str) -> PathBuf {
    if ab1_cache_path.is_empty() {
        return default_cache_dir().join(file_name);
    }
    let p = PathBuf::from(ab1_cache_path);
    if p.is_dir() {
        p.join(file_name)
    } else if p
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
    {
        p.with_extension("sqlite")
    } else {
        p
    }
}

/// Cache file name of the first and second scan directory (`ab1_scan_path`/`ab1_scan_path_2`).
pub const SCAN_CACHE_FILE_NAME: &str = "ab1_scan_cache.sqlite";
pub const SCAN_CACHE_FILE_NAME_2: &str = "ab1_scan_cache_2.sqlite";

/// Disk caches of the configured scan directories (those with a non-empty scan path).
pub fn scan_cache_files(tb_config: &crate::config::TBConfig) -> Vec<PathBuf> {
    [
        (
            &tb_config.ab1_scan_path,
            &tb_config.ab1_cache_path,
            SCAN_CACHE_FILE_NAME,
        ),
        (
            &tb_config.ab1_scan_path_2,
            &tb_config.ab1_cache_path_2,
            SCAN_CACHE_FILE_NAME_2,
        ),
    ]
    .into_iter()
    .filter(|(scan_path, _, _)| !scan_path.is_empty())
    .map(|(_, cache_path, file_name)| scan_cache_file(cache_path, file_name))
    .collect()
}

/// Size and mtime (whole seconds; 0 if unknown) of a file, the disk cache's staleness key.
fn file_stamp(meta: Option<&std::fs::Metadata>) -> (u64, u64) {
    let mtime_secs = meta
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    (mtime_secs, meta.map_or(0, std::fs::Metadata::len))
}

/// Looks up the 16S seq_id_hits previously computed by a background [`scan_ab1_directory`] run
/// for `sample_id`, regardless of which directory the 16S AB1 file lives in.
pub(crate) fn sixteen_s_hits_for_sample(sample_id: &str) -> Option<Vec<SeqIdHit>> {
    SIXTEEN_S_HITS_CACHE.read().ok()?.get(sample_id).cloned()
}

/// Per-sample susceptibility result produced by the batch AB1 directory scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SampleSusceptibilityRecord {
    pub sample_id: String,
    /// Gene inferred from the filename by [`parse_ab1_filename`], or `None` if unrecognized.
    pub gene: Option<String>,
    pub file_name: String,
    pub file_path: PathBuf,
    #[serde(with = "super::serde_helpers::option_systemtime_secs")]
    pub file_created: Option<SystemTime>,
    /// Per-gene susceptibility evidence, populated from the best (first) alignment hit.
    pub susceptibility_calls: SusceptibilityCalls,
    /// Species call from the NCBI references ([`RefSource::Ncbi`]).
    pub species: Option<String>,
    /// Alignment identity (%) of the best NCBI hit.
    pub identity: Option<f32>,
    /// Species call from the GTDB amplicon references ([`RefSource::Gtdb`]).
    #[serde(default)]
    pub species_gtdb: Option<String>,
    /// Alignment identity (%) of the best GTDB hit.
    #[serde(default)]
    pub identity_gtdb: Option<f32>,
    /// Combined susceptibility verdict across all genes, from [`susceptibility_from_hits`]:
    /// erm41 (a *massiliense* top hit is susceptible) → rrl → rrs → rrs3end → pncA → rpoB,
    /// first `Some` wins.
    pub is_susceptible: Option<bool>,
    /// Top alignment hits, alignments included, stored in the disk cache so the preview panel
    /// can be populated from it without re-running alignment.
    #[serde(default)]
    pub seq_id_hits: Vec<SeqIdHit>,
    /// [`ANALYSIS_VERSION`] the record was produced with; 0 for records cached before
    /// versioning, which are therefore re-analysed.
    #[serde(default)]
    pub analysis_version: u32,
}

/// Version of the per-file analysis stored in disk-cached records. Bump it whenever the calls
/// a record carries change (new gene calls, catalogue logic), so cached records are redone.
/// 1: rpoB rifampicin (RRDR) calls.
/// 2: NCBI and GTDB references kept apart (hit `source`, per-source species/identity).
/// 3: slimmed records (pncA calls only on the top hit, catalogue alts not stored).
/// 4: 16S species calls named by species group (cosmic-seq `species_groups.tsv`).
/// 5: species group lookup ignores genus synonyms (Mycobacteroides, `[Mycobacterium]`, ...).
/// 6: chelonae-abscessus complex = NCBI genus Mycobacteroides (adds fukienense, runyonii).
/// 7: rrl 2058/2059 non-ACGT base is undetermined (was resistant); rrs3end in the combined
///    verdict.
/// 8: species groups list NCBI subspecies under their former species names (M. chimaera,
///    M. yongonense → MAC).
pub(crate) const ANALYSIS_VERSION: u32 = 8;

impl SampleSusceptibilityRecord {
    /// Highest identity over both reference sources; the report filters on this, so targets
    /// with only GTDB references (hsp65, Mtb rpoB regions) are still reported.
    #[must_use]
    pub fn best_identity(&self) -> Option<f32> {
        match (self.identity, self.identity_gtdb) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }
}

/// Species call for `gene` from the hits of one reference source.
fn species_call(gene: Option<Ab1Gene>, hits: &[&SeqIdHit]) -> Option<String> {
    match gene {
        Some(Ab1Gene::Rrs16S) => species_from_16s_hits(hits),
        Some(Ab1Gene::Rrs3End) => species_from_16s3end(hits),
        Some(Ab1Gene::RpoB(_)) => species_from_rpob_hits(hits),
        _ => hits.first().map(|h| h.description.clone()),
    }
}

/// `true` if a disk-cached record can be reused: it was written by the current
/// [`ANALYSIS_VERSION`] and still carries the gene the current filename parser assigns (so
/// records written by an older parser, e.g. `erm39` labelled erm(41), are re-analysed).
fn cached_record_current(record: &SampleSusceptibilityRecord) -> bool {
    record.analysis_version == ANALYSIS_VERSION
        && record.gene.as_deref() == parse_ab1_filename(&record.file_name).1.map(Ab1Gene::label)
}

/// rpoB rifampicin calls for the summary record, flagged when the read's species isn't
/// *M. tuberculosis* (the WHO catalogue applies only to the MTB complex).
pub(crate) fn rpob_susceptibility_calls(hit: &SeqIdHit) -> RpobSusceptibilityCalls {
    RpobSusceptibilityCalls {
        snp_calls: hit.rpob_snp_calls.clone(),
        is_susceptible: is_susceptible_rpob(&hit.rpob_snp_calls),
        species_validated: hit.description.starts_with("Mycobacterium tuberculosis"),
    }
}

/// Per-gene susceptibility calls and the combined verdict for one file's alignment hits
/// (sorted by identity, best first). Shared by the batch scan and the preview, so both always
/// agree.
///
/// The calls come from the top hit, except the rrl/rrs/rrs3end catalogue SNPs, which come from
/// the best same-species hit that has them ([`best_snp_hit`]). A *massiliense* top hit is
/// erm(41)-susceptible, since its erm(41) is non-functional. The combined verdict is the first
/// per-gene verdict that is `Some`, in the order erm41 → rrl → rrs → rrs3end → pncA → rpoB.
#[must_use]
pub fn susceptibility_from_hits(hits: &[SeqIdHit]) -> (Option<bool>, SusceptibilityCalls) {
    let Some(hit) = hits.first() else {
        return (None, SusceptibilityCalls::default());
    };
    let rrl_hit = best_snp_hit(hits, |h| !h.rrl_snp_calls.is_empty()).unwrap_or(hit);
    let rrs_hit = best_snp_hit(hits, |h| !h.rrs_snp_calls.is_empty()).unwrap_or(hit);
    let rrs3end_hit = best_snp_hit(hits, |h| !h.rrs_snp_calls_3end.is_empty()).unwrap_or(hit);
    let rrl_pos = hit.rrl_position_2058_2059_opt.as_ref();

    let calls = SusceptibilityCalls {
        erm41: Erm41SusceptibilityCalls {
            position_28: hit.erm41_position_28_opt,
            lof_snp_calls: hit.erm41_snp_calls.clone(),
            is_susceptible: if hit.description == DESC_MASSILIENSE {
                Some(true)
            } else {
                is_susceptible_erm41(hit.erm41_position_28_opt.as_ref(), &hit.erm41_snp_calls)
            },
        },
        rrl: RrlSusceptibilityCalls {
            position_2058_2059: hit.rrl_position_2058_2059_opt,
            snp_calls: rrl_hit.rrl_snp_calls.clone(),
            is_susceptible: is_susceptible_rrl(rrl_pos, &rrl_hit.rrl_snp_calls),
            is_susceptible_rare: is_susceptible_rrl_by_snp_calls_rare(
                rrl_pos,
                &rrl_hit.rrl_snp_calls,
            ),
        },
        rrs: RrsSusceptibilityCalls {
            snp_calls: rrs_hit.rrs_snp_calls.clone(),
            is_susceptible: is_susceptible_rrs(&rrs_hit.rrs_snp_calls),
            is_susceptible_rare: is_susceptible_rrs_by_snp_calls_rare(&rrs_hit.rrs_snp_calls),
        },
        rrs3end: RrsSusceptibilityCalls3End {
            position_1248: hit.rrs3end_position_1248_opt,
            snp_calls: rrs3end_hit.rrs_snp_calls_3end.clone(),
            is_susceptible: is_susceptible_rrs_3end(&rrs3end_hit.rrs_snp_calls_3end),
            is_susceptible_rare: is_susceptible_rrs_by_snp_calls_rare_3end(
                &rrs3end_hit.rrs_snp_calls_3end,
            ),
        },
        pnca: PncaSusceptibilityCalls {
            snp_calls: hit.pnca_snp_calls.clone(),
            is_susceptible: is_susceptible_pnca(&hit.pnca_snp_calls),
        },
        rpob: rpob_susceptibility_calls(hit),
    };
    let verdict = calls
        .erm41
        .is_susceptible
        .or(calls.rrl.is_susceptible)
        .or(calls.rrs.is_susceptible)
        .or(calls.rrs3end.is_susceptible)
        .or(calls.pnca.is_susceptible)
        .or(calls.rpob.is_susceptible);
    (verdict, calls)
}

/// Identity window of a tie: hits within this many percentage points of the best hit are
/// reported together.
const TIE_IDENTITY: f32 = 0.1;

/// The best hit and the hits tied with it (`hits` sorted by identity, best first).
fn tied_hits<'a>(hits: &[&'a SeqIdHit]) -> Vec<&'a SeqIdHit> {
    let Some(first) = hits.first() else {
        return Vec::new();
    };
    hits.iter()
        .copied()
        .take_while(|hit| (hit.identity - first.identity).abs() <= TIE_IDENTITY)
        .collect()
}

/// Species epithets of tied hits joined after the first hit's genus, e.g.
/// "Mycobacterium gastri/kansasii"; the first description alone when all hits share it.
fn join_epithets(ties: &[&SeqIdHit]) -> Option<String> {
    let first = ties.first()?;
    let (prefix, first_epithet) = first
        .description
        .rsplit_once(' ')
        .unwrap_or(("", first.description.as_str()));
    let mut epithets: Vec<&str> = vec![first_epithet];
    for hit in &ties[1..] {
        if let Some((_, epithet)) = hit.description.rsplit_once(' ')
            && !epithets.contains(&epithet)
        {
            epithets.push(epithet);
        }
    }
    Some(if epithets.len() == 1 {
        first.description.clone()
    } else {
        format!("{} {}", prefix, epithets.join("/"))
    })
}

/// For 16S hits: 16S does not separate the members of a complex, so tied hits are named by their
/// species group ([`species_group`], cosmic-seq `species_groups.tsv`), e.g. "M. kansasii complex".
/// Ties in no group are joined by epithet as in [`join_epithets`]; a tie that spans several groups
/// lists them, e.g. "M. kansasii complex / Mycobacterium szulgai".
pub(crate) fn species_from_16s_hits(hits: &[&SeqIdHit]) -> Option<String> {
    let ties = tied_hits(hits);
    let mut parts: Vec<String> = Vec::new();
    let mut ungrouped: Vec<&SeqIdHit> = Vec::new();
    let mut ungrouped_at = None;
    for hit in &ties {
        if let Some(label) = species_group(&hit.description) {
            if !parts.iter().any(|part| part == label) {
                parts.push(label.to_string());
            }
        } else {
            ungrouped_at.get_or_insert(parts.len());
            ungrouped.push(hit);
        }
    }
    if let Some(at) = ungrouped_at {
        parts.insert(at, join_epithets(&ungrouped)?);
    }
    (!parts.is_empty()).then(|| parts.join(" / "))
}

/// For 16S 3'-end hits, only *M. marinum*/*M. ulcerans* (the pair position 1248 discriminates)
/// gets a species description; other species return an empty string since this amplicon isn't
/// diagnostic for them.
fn species_from_16s3end(hits: &[&SeqIdHit]) -> Option<String> {
    let first = hits.first()?;
    if !first.description.starts_with("Mycobacterium ulcerans")
        && !first.description.starts_with("Mycobacterium marinum")
    {
        return Some(String::new());
    }
    Some(first.description.clone())
}

/// For rpoB hits, concatenates species epithets of ties into e.g. "Mycobacterium gastri/kansasii".
pub(crate) fn species_from_rpob_hits(hits: &[&SeqIdHit]) -> Option<String> {
    let first = hits.first()?;
    if first.description.contains("abscessus") {
        return Some("M. abscessus complex".to_string());
    }
    if first.description.contains("chelonae") {
        return Some("M. chelonae".to_string());
    }
    join_epithets(&tied_hits(hits))
}

/// Walk `scan_path` recursively, analyse every `.ab1` file, and return a
/// `SampleSusceptibilityRecord` per file sorted reverse-alphabetically by
/// `sample_id` (highest first).
///
/// `cache_path` — the SQLite disk cache ([`DiskCache`], see [`scan_cache_file`]); `None`
/// disables disk caching. Rows for files under `scan_path` that this scan didn't see are pruned.
/// `max_age_days` — files whose creation time is older than this many days are skipped
/// (mirrors the PDF report window). Pass `0` to disable age filtering.
pub fn scan_ab1_directory(
    scan_path: PathBuf,
    cache_path: Option<PathBuf>,
    max_age_days: u32,
) -> Vec<SampleSusceptibilityRecord> {
    log::debug!(
        "ab1_scan: starting scan of {} (max_age_days={}, cache_path={:?})",
        scan_path.display(),
        max_age_days,
        cache_path
    );

    let mut disk_cache = cache_path.as_deref().and_then(DiskCache::open);
    if let Some(cache) = &mut disk_cache {
        cache.begin_batch();
    }
    // Keys (canonical paths) of every file seen, for pruning the cache afterwards.
    let mut seen: HashSet<String> = HashSet::new();

    let now = SystemTime::now();
    let max_age = (max_age_days > 0).then(|| Duration::from_secs(u64::from(max_age_days) * 86_400));

    let mut records = Vec::new();
    // Files without a current disk-cache row, aligned after the walk so every cached result
    // reaches `AB1_SEQ_CACHE` (and the preview) before the first slow alignment starts.
    let mut misses: Vec<(PathBuf, String, u64, u64, Option<SystemTime>)> = Vec::new();

    for entry in WalkDir::new(&scan_path).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("ab1"))
            .unwrap_or(false)
        {
            continue;
        }

        let meta = std::fs::metadata(path).ok();
        let file_created: Option<SystemTime> = meta.as_ref().and_then(|m| m.created().ok());

        // Skip files outside the reporting window (same filter as the PDF report).
        if let (Some(max_age), Some(created)) = (&max_age, file_created)
            && now.duration_since(created).is_ok_and(|age| age > *max_age)
        {
            log::debug!("ab1_scan: skipping old file: {}", path.display());
            continue;
        }

        let (mtime_secs, file_size) = file_stamp(meta.as_ref());

        // Canonicalize so the key matches the \\?\ -prefixed paths the file manager uses.
        let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let key = canonical_path.to_string_lossy().into_owned();
        seen.insert(key.clone());

        // Disk cache hit: mtime/size unchanged and seq_id_hits stored → reuse previous result.
        if let Some(cache) = &disk_cache {
            match cache.get(&key, mtime_secs, file_size) {
                Some(cached)
                    if !cached.seq_id_hits.is_empty() && cached_record_current(&cached) =>
                {
                    log::debug!(
                        "ab1_scan: disk cache hit for {} ({} hits)",
                        path.display(),
                        cached.seq_id_hits.len(),
                    );
                    insert_cached_record(canonical_path, (mtime_secs, file_size), &cached);
                    records.push(cached);
                    continue;
                }
                Some(_) => {
                    log::debug!("ab1_scan: disk cache entry outdated for {}", path.display())
                }
                None => log::debug!(
                    "ab1_scan: no current disk cache entry for {}",
                    path.display()
                ),
            }
        }

        misses.push((path.to_path_buf(), key, mtime_secs, file_size, file_created));
    }

    log::debug!(
        "ab1_scan: {} disk cache hits, {} files to align",
        records.len(),
        misses.len()
    );

    // Cache misses — run the full alignment pipeline on the bounded worker pool. Workers send
    // finished records back here; this thread alone owns the (non-`Sync`) disk cache, so rows
    // are still upserted in batches as they arrive and an interrupted scan keeps its progress.
    let started = std::time::Instant::now();
    let n_misses = misses.len();
    let mut store = |key: String, mtime_secs: u64, file_size: u64, record| {
        if let Some(cache) = &mut disk_cache {
            cache.put(&key, mtime_secs, file_size, &record);
        }
        records.push(record);
    };
    let analyse = |(path, key, mtime_secs, file_size, file_created): (
        PathBuf,
        String,
        u64,
        u64,
        Option<SystemTime>,
    )| {
        analyse_ab1_file(&path, file_created, (mtime_secs, file_size))
            .map(|(_, record)| (key, mtime_secs, file_size, record))
    };
    match SCAN_POOL.as_ref() {
        Some(pool) if n_misses > 1 => {
            use rayon::iter::{IntoParallelIterator, ParallelIterator};
            log::debug!(
                "ab1_scan: aligning {n_misses} files on {} threads",
                pool.current_num_threads()
            );
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::scope(|s| {
                s.spawn(|| {
                    pool.install(|| {
                        misses.into_par_iter().for_each_with(tx, |tx, miss| {
                            if let Some(done) = analyse(miss) {
                                let _ = tx.send(done);
                            }
                        });
                    });
                });
                for (key, mtime_secs, file_size, record) in rx {
                    store(key, mtime_secs, file_size, record);
                }
            });
        }
        _ => {
            for miss in misses {
                if let Some((key, mtime_secs, file_size, record)) = analyse(miss) {
                    store(key, mtime_secs, file_size, record);
                }
            }
        }
    }
    if n_misses > 0 {
        log::debug!(
            "ab1_scan: aligned {n_misses} files in {:.1?}",
            started.elapsed()
        );
    }

    if let Some(cache) = &mut disk_cache {
        cache.commit_batch();
        let root = scan_path
            .canonicalize()
            .unwrap_or_else(|_| scan_path.clone());
        let pruned = cache.prune_under(&root, &seen);
        if pruned > 0 {
            log::debug!("ab1_scan: pruned {pruned} stale disk cache entries");
        }
    }

    let mem_cache_size = AB1_SEQ_CACHE.read().map(|g| g.len()).unwrap_or(0);
    log::debug!(
        "ab1_scan: finished: {} records, AB1_SEQ_CACHE has {} entries",
        records.len(),
        mem_cache_size
    );

    // Reverse-alphabetical by sample_id (highest first)
    records.sort_by(|a, b| b.sample_id.cmp(&a.sample_id));
    records
}

/// Run the full alignment pipeline on one AB1 file: infer the gene from the filename, align the
/// quality-trimmed read against that gene's references, and derive the susceptibility calls.
///
/// Populates [`AB1_SEQ_CACHE`] (with `stamp`, the file's [`file_stamp`]) and, for 16S reads,
/// [`SIXTEEN_S_HITS_CACHE`] as a side effect. Returns the top 10 hits alongside the record,
/// whose `seq_id_hits` keeps only the top 5. Returns `None` if the file can't be read.
fn analyse_ab1_file(
    path: &Path,
    file_created: Option<SystemTime>,
    stamp: (u64, u64),
) -> Option<(Vec<SeqIdHit>, SampleSusceptibilityRecord)> {
    // Canonicalize so the key matches the \\?\ -prefixed paths the file manager uses.
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    let (sample_id, gene) = parse_ab1_filename(&file_name);

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("ab1 analysis: failed to read {}: {e}", path.display());
            return None;
        }
    };

    // Dispatch on the gene `parse_ab1_filename` inferred, so the gene label in the record and
    // the analysis that runs can never disagree (it is the single source of keyword matching).
    let is_16s = gene == Some(Ab1Gene::Rrs16S);

    let ab1_seq = parse_ab1_sequence(&bytes);
    let ab1_qual = parse_ab1_quality(&bytes);

    let mut seq_id_hits = match (ab1_seq.as_ref(), gene) {
        (Some(seq), Some(gene)) => {
            let trimmed: &[u8] = match &ab1_qual {
                Some(qual) => trim_to_min_quality(seq, qual, 20).unwrap_or(seq.as_slice()),
                None => seq.as_slice(),
            };
            match gene {
                Ab1Gene::Erm41 => identify_sequence_erm41(trimmed),
                Ab1Gene::Hsp65 => identify_sequence_hsp65(trimmed),
                Ab1Gene::RpoB(region) => identify_sequence_rpob(trimmed, region),
                Ab1Gene::Rrl => identify_sequence_rrl_ntm(trimmed),
                Ab1Gene::Rrs16S => identify_sequence_16s(trimmed),
                Ab1Gene::Rrs3End => identify_sequence_16s3end(trimmed),
                Ab1Gene::PncA => identify_sequence_pnca(trimmed),
            }
        }
        _ => Vec::new(),
    };
    // Each identify_sequence_* function returns hits already sorted descending by identity;
    // keep only the top 10 per reference source before cloning into the long-lived caches
    // below, since scanning directories with many AB1 files otherwise accumulates one full
    // (unbounded) hit list per file for the life of the process. Per source, so one database
    // can't crowd the other out.
    truncate_per_source(&mut seq_id_hits, 10);
    // pncA calls (~190 catalogue sites per hit) are only ever read from the top hit — here and
    // in the preview's `ab1_susceptibility` — so drop them from the rest before caching.
    for hit in seq_id_hits.iter_mut().skip(1) {
        hit.pnca_snp_calls = Vec::new();
    }

    // Populate the in-memory cache using the canonical path so it matches what item_from_entry() uses.
    log::debug!(
        "ab1_scan: alignment done for {} → {} hits (top: {:?}, canonical={})",
        path.display(),
        seq_id_hits.len(),
        seq_id_hits.first().map(|h| (&h.description, h.identity)),
        canonical_path.display()
    );
    insert_hits(canonical_path, stamp, seq_id_hits.clone());
    if is_16s && let Ok(mut guard) = SIXTEEN_S_HITS_CACHE.write() {
        guard.insert(sample_id.clone(), seq_id_hits.clone());
    }

    let (is_susceptible, susceptibility_calls) = susceptibility_from_hits(&seq_id_hits);

    let ncbi_hits = hits_from(&seq_id_hits, RefSource::Ncbi);
    let gtdb_hits = hits_from(&seq_id_hits, RefSource::Gtdb);
    let record = SampleSusceptibilityRecord {
        sample_id,
        gene: gene.map(|g| g.label().to_string()),
        file_name,
        file_path: path.to_path_buf(),
        file_created,
        susceptibility_calls,
        species: species_call(gene, &ncbi_hits),
        identity: ncbi_hits.first().map(|h| h.identity),
        species_gtdb: species_call(gene, &gtdb_hits),
        identity_gtdb: gtdb_hits.first().map(|h| h.identity),
        is_susceptible,
        seq_id_hits: {
            let mut top = seq_id_hits.clone();
            truncate_per_source(&mut top, 5);
            top
        },
        analysis_version: ANALYSIS_VERSION,
    };

    Some((seq_id_hits, record))
}

/// Put a disk-cached record's hits into the in-memory caches the preview reads from. `stamp`
/// is the stamp the record was stored under (and checked against the file).
fn insert_cached_record(
    canonical_path: PathBuf,
    stamp: (u64, u64),
    record: &SampleSusceptibilityRecord,
) {
    insert_hits(canonical_path, stamp, record.seq_id_hits.clone());
    if record.gene.as_deref() == Some(Ab1Gene::Rrs16S.label())
        && let Ok(mut guard) = SIXTEEN_S_HITS_CACHE.write()
    {
        guard.insert(record.sample_id.clone(), record.seq_id_hits.clone());
    }
}

/// Location of the preview disk cache for the `ab1_cache_path` setting, which (as for the scan)
/// may name either a directory or a cache file; in the latter case its directory is used.
/// Falls back to the user cache directory when the setting is empty.
pub(crate) fn preview_cache_file(ab1_cache_path: &str) -> PathBuf {
    if ab1_cache_path.is_empty() {
        return default_cache_dir().join(PREVIEW_CACHE_FILE_NAME);
    }
    let p = PathBuf::from(ab1_cache_path);
    if p.is_dir() {
        p.join(PREVIEW_CACHE_FILE_NAME)
    } else {
        p.with_file_name(PREVIEW_CACHE_FILE_NAME)
    }
}

/// Loads every still-current row of the scan cache at `cache_file` into [`AB1_SEQ_CACHE`] (and
/// [`SIXTEEN_S_HITS_CACHE`]) in one query, so the preview has the previous scan's results right
/// after startup instead of waiting for the next scan (which may first wait for a Microsynth
/// sync) to walk the tree. A row counts as current when its file still exists with the same
/// mtime and size, and [`cached_record_current`] holds. The database is opened read-only.
/// Returns the number of files loaded. Blocking: call from a worker thread.
pub fn preload_disk_cache(cache_file: &Path) -> usize {
    let Some(cache) = DiskCache::open_existing(cache_file) else {
        return 0;
    };
    let mut loaded = 0;
    for (key, mtime_secs, file_size, record) in cache.load_current() {
        let path = PathBuf::from(&key);
        let meta = std::fs::metadata(&path).ok();
        if meta.is_none()
            || file_stamp(meta.as_ref()) != (mtime_secs, file_size)
            || record.seq_id_hits.is_empty()
            || !cached_record_current(&record)
        {
            continue;
        }
        insert_cached_record(path, (mtime_secs, file_size), &record);
        loaded += 1;
    }
    log::debug!(
        "ab1_preload: {loaded} records from {}",
        cache_file.display()
    );
    loaded
}

/// Results for one AB1 file for the preview panel. Looks them up, in order, in
/// [`AB1_SEQ_CACHE`], the scan caches `scan_cache_files` (opened read-only, only if they
/// exist), and the preview cache `cache_file`, each only while the file's mtime and size are
/// unchanged. Only when none has them does it run [`analyse_ab1_file`] and store all of its
/// hits in `cache_file`. Either way the hits end up in [`AB1_SEQ_CACHE`], keyed by canonical
/// path. Blocking: call from a worker thread.
pub(crate) fn analyse_ab1_for_preview(
    path: &Path,
    cache_file: &Path,
    scan_cache_files: &[PathBuf],
) -> Vec<SeqIdHit> {
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let meta = std::fs::metadata(path).ok();
    if let Some(hits) = meta.as_ref().and_then(|m| cached_hits(&canonical_path, m)) {
        log::debug!("ab1_preview: memory cache hit for {}", path.display());
        return hits;
    }

    let file_created = meta.as_ref().and_then(|m| m.created().ok());
    let (mtime_secs, file_size) = file_stamp(meta.as_ref());
    let stamp = (mtime_secs, file_size);
    let key = canonical_path.to_string_lossy().into_owned();

    for scan_cache_file in scan_cache_files {
        if let Some(cache) = DiskCache::open_existing(scan_cache_file)
            && let Some(record) = cache.get(&key, mtime_secs, file_size)
            && !record.seq_id_hits.is_empty()
            && cached_record_current(&record)
        {
            log::debug!(
                "ab1_preview: scan cache hit for {} in {}",
                path.display(),
                scan_cache_file.display()
            );
            insert_cached_record(canonical_path, stamp, &record);
            return record.seq_id_hits;
        }
    }

    {
        let mut guard = PREVIEW_DISK_CACHE
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if guard.as_ref().is_none_or(|c| c.path() != cache_file) {
            *guard = DiskCache::open(cache_file);
        }
        if let Some(cache) = guard.as_ref()
            && let Some(record) = cache.get(&key, mtime_secs, file_size)
            && cached_record_current(&record)
        {
            log::debug!("ab1_preview: disk cache hit for {}", path.display());
            insert_cached_record(canonical_path, stamp, &record);
            return record.seq_id_hits;
        }
    }

    // Not cached: align without holding the lock, so other previews' cache hits aren't blocked.
    let Some((seq_id_hits, mut record)) = analyse_ab1_file(path, file_created, stamp) else {
        return Vec::new();
    };
    // Unlike the scan record (top 5, for the report), keep every hit the preview displays.
    record.seq_id_hits.clone_from(&seq_id_hits);

    let mut guard = PREVIEW_DISK_CACHE
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(cache) = guard.as_mut()
        && cache.path() == cache_file
    {
        cache.put(&key, mtime_secs, file_size, &record);
    }
    seq_id_hits
}

/// Write `records` to a CSV file at `out_path`.
///
/// Filters the same way [`super::build_report_pdf`] does: `gene` must be known, the best
/// identity of either reference source ([`SampleSusceptibilityRecord::best_identity`]) must
/// meet [`MIN_SEQ_ID_IDENTITY`], and `file_created` (when known) must fall within
/// `report_max_age_days`.
///
/// Columns: `file_name, sample_id, gene, overall_susceptible, species, identity_pct,
/// erm41_position_28, erm41_lof_snp_calls, erm41_susceptible, rrl_position_2058_2059,
/// rrl_snp_calls, rrl_susceptible, rrs_snp_calls, rrs_susceptible, rrs3end_position_1248,
/// rrs3end_snp_calls, rrs3end_susceptible, pnca_snp_calls, pnca_susceptible, file_created,
/// rpob_snp_calls, rpob_susceptible, rpob_species_validated, species_gtdb, identity_gtdb_pct`.
/// `species`/`identity_pct` are the NCBI call; later additions (rpoB, GTDB) are appended so
/// existing column positions stay stable.
pub fn write_ab1_csv(
    records: &[SampleSusceptibilityRecord],
    out_path: &std::path::Path,
    report_max_age_days: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let max_age = Duration::from_secs(u64::from(report_max_age_days) * 24 * 60 * 60);
    let now = SystemTime::now();

    let file = std::fs::File::create(out_path)?;
    let mut wtr = csv::Writer::from_writer(file);

    wtr.write_record([
        "file_name",
        "sample_id",
        "gene",
        "overall_susceptible",
        "species",
        "identity_pct",
        "erm41_position_28",
        "erm41_lof_snp_calls",
        "erm41_susceptible",
        "rrl_position_2058_2059",
        "rrl_snp_calls",
        "rrl_susceptible",
        "rrs_snp_calls",
        "rrs_susceptible",
        "rrs3end_position_1248",
        "rrs3end_snp_calls",
        "rrs3end_susceptible",
        "pnca_snp_calls",
        "pnca_susceptible",
        "file_created",
        "rpob_snp_calls",
        "rpob_susceptible",
        "rpob_species_validated",
        "species_gtdb",
        "identity_gtdb_pct",
    ])?;

    for rec in records {
        if rec.gene.is_none() {
            continue;
        }
        if rec.best_identity().is_none_or(|i| i < MIN_SEQ_ID_IDENTITY) {
            continue;
        }
        if !rec
            .file_created
            .is_none_or(|created| now.duration_since(created).is_ok_and(|age| age <= max_age))
        {
            continue;
        }

        let file_created = rec
            .file_created
            .map(system_time_to_iso8601)
            .unwrap_or_default();

        let erm41_pos = rec
            .susceptibility_calls
            .erm41
            .position_28
            .map(|p| p.to_string())
            .unwrap_or_default();
        let erm41_sus = fmt_susceptible(rec.susceptibility_calls.erm41.is_susceptible);
        let erm41_lof = snp_calls_str(
            rec.susceptibility_calls
                .erm41
                .lof_snp_calls
                .iter()
                .map(|s| (s.ref_pos, s.call_tag())),
        );

        let rrl_pos = rec
            .susceptibility_calls
            .rrl
            .position_2058_2059
            .map(|p| p.to_string())
            .unwrap_or_default();
        let rrl_sus = fmt_susceptible(rec.susceptibility_calls.rrl.is_susceptible);
        let rrl_snps = snp_calls_str(
            rec.susceptibility_calls
                .rrl
                .snp_calls
                .iter()
                .map(|s| (s.ref_pos, s.call_tag())),
        );

        let rrs_sus = fmt_susceptible(rec.susceptibility_calls.rrs.is_susceptible);
        let rrs_snps = snp_calls_str(
            rec.susceptibility_calls
                .rrs
                .snp_calls
                .iter()
                .map(|s| (s.ref_pos, s.call_tag())),
        );

        let rrs3end_pos = rec
            .susceptibility_calls
            .rrs3end
            .position_1248
            .map(|p| p.to_string())
            .unwrap_or_default();
        let rrs3end_sus = fmt_susceptible(rec.susceptibility_calls.rrs3end.is_susceptible);
        let rrs3end_snps = snp_calls_str(
            rec.susceptibility_calls
                .rrs3end
                .snp_calls
                .iter()
                .map(|s| (s.ref_pos, s.call_tag())),
        );

        let pnca_sus = fmt_susceptible(rec.susceptibility_calls.pnca.is_susceptible);
        let pnca_snps = pnca_snp_calls_str(&rec.susceptibility_calls.pnca.snp_calls);

        let rpob = &rec.susceptibility_calls.rpob;
        let rpob_sus = fmt_susceptible(rpob.is_susceptible);
        let rpob_snps = rpob_snp_calls_str(&rpob.snp_calls);
        // Only meaningful when rifampicin calls were made at all.
        let rpob_validated = match (rpob.snp_calls.is_empty(), rpob.species_validated) {
            (true, _) => "",
            (false, true) => "true",
            (false, false) => "false",
        };

        let overall = fmt_susceptible(rec.is_susceptible);

        wtr.write_record([
            rec.file_name.as_str(),
            rec.sample_id.as_str(),
            rec.gene.as_deref().unwrap_or(""),
            overall.as_str(),
            rec.species.as_deref().unwrap_or(""),
            &rec.identity
                .map(|i| format!("{:.1}", i))
                .unwrap_or_default(),
            erm41_pos.as_str(),
            erm41_lof.as_str(),
            erm41_sus.as_str(),
            rrl_pos.as_str(),
            rrl_snps.as_str(),
            rrl_sus.as_str(),
            rrs_snps.as_str(),
            rrs_sus.as_str(),
            rrs3end_pos.as_str(),
            rrs3end_snps.as_str(),
            rrs3end_sus.as_str(),
            pnca_snps.as_str(),
            pnca_sus.as_str(),
            file_created.as_str(),
            rpob_snps.as_str(),
            rpob_sus.as_str(),
            rpob_validated,
            rec.species_gtdb.as_deref().unwrap_or(""),
            &rec.identity_gtdb
                .map(|i| format!("{:.1}", i))
                .unwrap_or_default(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

/// Write records that flag a rare resistance mutation (`is_susceptible_rare == Some(false)` for
/// rrl, rrs or rrs3end) to `out_path`. Same leading columns as `write_ab1_csv` plus
/// `rrl_susceptible_rare` and `rrs_susceptible_rare`, then `file_created, species_gtdb,
/// identity_gtdb_pct, rrs3end_snp_calls, rrs3end_susceptible_rare` (later additions appended so
/// existing column positions stay stable).
///
/// Filters like [`write_ab1_csv`]: known gene, best identity ≥ [`MIN_SEQ_ID_IDENTITY`], and
/// `file_created` (when known) within `report_max_age_days`. When no record qualifies, an
/// existing file at `out_path` is removed, so it never shows an earlier scan's mutations.
pub fn write_rare_mutations_csv(
    records: &[SampleSusceptibilityRecord],
    out_path: &std::path::Path,
    report_max_age_days: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let max_age = Duration::from_secs(u64::from(report_max_age_days) * 24 * 60 * 60);
    let now = SystemTime::now();
    let rare: Vec<&SampleSusceptibilityRecord> = records
        .iter()
        .filter(|rec| {
            let calls = &rec.susceptibility_calls;
            rec.gene.is_some()
                && rec
                    .best_identity()
                    .is_some_and(|i| i >= MIN_SEQ_ID_IDENTITY)
                && rec.file_created.is_none_or(|created| {
                    now.duration_since(created).is_ok_and(|age| age <= max_age)
                })
                && (calls.rrl.is_susceptible_rare == Some(false)
                    || calls.rrs.is_susceptible_rare == Some(false)
                    || calls.rrs3end.is_susceptible_rare == Some(false))
        })
        .collect();

    if rare.is_empty() {
        return match std::fs::remove_file(out_path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        };
    }

    let file = std::fs::File::create(out_path)?;
    let mut wtr = csv::Writer::from_writer(file);

    wtr.write_record([
        "file_name",
        "sample_id",
        "gene",
        "overall_susceptible",
        "species",
        "identity_pct",
        "erm41_position_28",
        "erm41_lof_snp_calls",
        "erm41_susceptible",
        "rrl_position_2058_2059",
        "rrl_snp_calls",
        "rrl_susceptible",
        "rrl_susceptible_rare",
        "rrs_snp_calls",
        "rrs_susceptible",
        "rrs_susceptible_rare",
        "file_created",
        "species_gtdb",
        "identity_gtdb_pct",
        "rrs3end_snp_calls",
        "rrs3end_susceptible_rare",
    ])?;

    for rec in &rare {
        let rrl_rare = rec.susceptibility_calls.rrl.is_susceptible_rare;
        let rrs_rare = rec.susceptibility_calls.rrs.is_susceptible_rare;

        let file_created = rec
            .file_created
            .map(system_time_to_iso8601)
            .unwrap_or_default();

        let erm41_pos = rec
            .susceptibility_calls
            .erm41
            .position_28
            .map(|p| p.to_string())
            .unwrap_or_default();
        let erm41_sus = fmt_susceptible(rec.susceptibility_calls.erm41.is_susceptible);
        let erm41_lof = snp_calls_str(
            rec.susceptibility_calls
                .erm41
                .lof_snp_calls
                .iter()
                .map(|s| (s.ref_pos, s.call_tag())),
        );

        let rrl_pos = rec
            .susceptibility_calls
            .rrl
            .position_2058_2059
            .map(|p| p.to_string())
            .unwrap_or_default();
        let rrl_sus = fmt_susceptible(rec.susceptibility_calls.rrl.is_susceptible);
        let rrl_sus_rare = fmt_susceptible(rrl_rare);
        let rrl_snps = snp_calls_str(
            rec.susceptibility_calls
                .rrl
                .snp_calls
                .iter()
                .map(|s| (s.ref_pos, s.call_tag())),
        );

        let rrs_sus = fmt_susceptible(rec.susceptibility_calls.rrs.is_susceptible);
        let rrs_sus_rare = fmt_susceptible(rrs_rare);
        let rrs_snps = snp_calls_str(
            rec.susceptibility_calls
                .rrs
                .snp_calls
                .iter()
                .map(|s| (s.ref_pos, s.call_tag())),
        );

        let rrs3end_sus_rare =
            fmt_susceptible(rec.susceptibility_calls.rrs3end.is_susceptible_rare);
        let rrs3end_snps = snp_calls_str(
            rec.susceptibility_calls
                .rrs3end
                .snp_calls
                .iter()
                .map(|s| (s.ref_pos, s.call_tag())),
        );

        let overall = fmt_susceptible(rec.is_susceptible);

        wtr.write_record([
            rec.file_name.as_str(),
            rec.sample_id.as_str(),
            rec.gene.as_deref().unwrap_or(""),
            overall.as_str(),
            rec.species.as_deref().unwrap_or(""),
            &rec.identity
                .map(|i| format!("{:.1}", i))
                .unwrap_or_default(),
            erm41_pos.as_str(),
            erm41_lof.as_str(),
            erm41_sus.as_str(),
            rrl_pos.as_str(),
            rrl_snps.as_str(),
            rrl_sus.as_str(),
            rrl_sus_rare.as_str(),
            rrs_snps.as_str(),
            rrs_sus.as_str(),
            rrs_sus_rare.as_str(),
            file_created.as_str(),
            rec.species_gtdb.as_deref().unwrap_or(""),
            &rec.identity_gtdb
                .map(|i| format!("{:.1}", i))
                .unwrap_or_default(),
            rrs3end_snps.as_str(),
            rrs3end_sus_rare.as_str(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

/// Renders a susceptibility verdict for CSV output: `"susceptible"`, `"resistant"`, or empty
/// for `None` (unknown).
fn fmt_susceptible(v: Option<bool>) -> String {
    match v {
        Some(true) => "susceptible".to_string(),
        Some(false) => "resistant".to_string(),
        None => String::new(),
    }
}

/// Joins the call tags of `(ref_pos, call_tag)` pairs into a comma-separated CSV cell, e.g.
/// `"A2059G (clarithromycin, E.coli: A2059G), A2058A (E.coli: A2058A)"`.
fn snp_calls_str(calls: impl Iterator<Item = (usize, String)>) -> String {
    calls.map(|(_, tag)| tag).collect::<Vec<_>>().join(", ")
}

/// Joins pncA calls with a non-empty [`call_tag`](super::pnca::PncaSnpCall::call_tag) into a
/// semicolon-separated CSV cell, e.g. `"p.Ala102Pro: (pyrazinamide, Assoc w R)"`. Sites matching
/// wildtype (empty tag) are omitted.
fn pnca_snp_calls_str(calls: &[super::pnca::PncaSnpCall]) -> String {
    calls
        .iter()
        .filter(|c| !c.call_tag().is_empty())
        .map(|c| format!("{}: {}", c.site_label(), c.call_tag()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn rpob_snp_calls_str(calls: &[super::rpob::RpobSnpCall]) -> String {
    calls
        .iter()
        .filter(|c| !c.call_tag().is_empty())
        .map(|c| format!("{}: {}", c.site_label(), c.call_tag()))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Format a `SystemTime` as `YYYY-MM-DDTHH:MM:SSZ` without any external crate.
fn system_time_to_iso8601(t: std::time::SystemTime) -> String {
    use std::time::UNIX_EPOCH;
    let Ok(dur) = t.duration_since(UNIX_EPOCH) else {
        return String::new();
    };
    let secs = dur.as_secs();

    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = (secs / 86400) as u32;

    // Days since 1970-01-01 → Gregorian date (proleptic, ignoring leap seconds)
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Converts days since the Unix epoch (1970-01-01) to a proleptic Gregorian `(year, month,
/// day)`, ignoring leap seconds, via the standard Julian Day Number algorithm.
fn days_to_ymd(days: u32) -> (u32, u32, u32) {
    // Algorithm: Julian Day Number from Unix epoch, then Gregorian conversion
    // Unix epoch = JDN 2440588
    let jdn = days + 2_440_588;
    let a = jdn + 32044;
    let b = (4 * a + 3) / 146097;
    let c = a - (146097 * b) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;
    let day = e - (153 * m + 2) / 5 + 1;
    let month = m + 3 - 12 * (m / 10);
    let year = 100 * b + d - 4800 + m / 10;
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_time_to_iso8601() {
        use std::time::{Duration, UNIX_EPOCH};
        // 2024-01-15T00:00:00Z = 1705276800 seconds since epoch
        let t = UNIX_EPOCH + Duration::from_secs(1_705_276_800);
        assert_eq!(system_time_to_iso8601(t), "2024-01-15T00:00:00Z");
    }

    fn hit(description: &str, identity: f32) -> SeqIdHit {
        SeqIdHit {
            accession: "X".to_string(),
            description: description.to_string(),
            source: RefSource::Gtdb,
            identity,
            is_reverse: false,
            rrl_snp_calls: Vec::new(),
            rrs_snp_calls: Vec::new(),
            rrs_snp_calls_3end: Vec::new(),
            erm41_snp_calls: Vec::new(),
            pnca_snp_calls: Vec::new(),
            rpob_snp_calls: Vec::new(),
            aligned_query: Vec::new(),
            aligned_ref: Vec::new(),
            ref_start: 0,
            erm41_position_28_opt: None,
            rrs3end_position_1248_opt: None,
            rrl_position_2058_2059_opt: None,
        }
    }

    fn call_16s(hits: &[(&str, f32)]) -> Option<String> {
        let hits: Vec<SeqIdHit> = hits.iter().map(|&(d, i)| hit(d, i)).collect();
        species_from_16s_hits(&hits.iter().collect::<Vec<_>>())
    }

    #[test]
    fn species_16s_named_by_group() {
        assert_eq!(
            call_16s(&[
                ("Mycobacterium gastri", 100.0),
                ("Mycobacterium kansasii", 100.0)
            ]),
            Some("M. kansasii complex".to_string())
        );
        assert_eq!(
            call_16s(&[
                ("Mycobacterium avium", 99.5),
                ("Mycobacterium szulgai", 98.0)
            ]),
            Some("M. avium complex (MAC)".to_string())
        );
        // NCBI subspecies still named as species in old deflines belong to the species' group.
        assert_eq!(
            call_16s(&[
                ("Mycobacterium intracellulare", 99.6),
                ("Mycobacterium chimaera", 99.6)
            ]),
            Some("M. avium complex (MAC)".to_string())
        );
        assert_eq!(
            call_16s(&[("Mycobacterium yongonense", 99.0)]),
            Some("M. avium complex (MAC)".to_string())
        );
        assert_eq!(
            call_16s(&[("Mycobacteroides abscessus subsp. massiliense", 99.0)]),
            Some("M. chelonae / M. abscessus complex".to_string())
        );
    }

    #[test]
    fn species_16s_group_ignores_genus_synonyms() {
        let label = Some("M. chelonae / M. abscessus complex".to_string());
        // NCBI split genus, GTDB genus, and NCBI's bracketed misplaced genus all match.
        for description in [
            "Mycobacteroides stephanolepidis",
            "Mycobacterium stephanolepidis",
            "[Mycobacterium] chelonae subsp. bovistauri",
            "Mycobacteroides chelonae",
        ] {
            assert_eq!(call_16s(&[(description, 99.0)]), label, "{description}");
        }
        // A tie of two spellings of the same species is one group.
        assert_eq!(
            call_16s(&[
                ("Mycobacteroides chelonae", 99.0),
                ("Mycobacterium chelonae", 99.0)
            ]),
            label
        );
        // Split genera without a group keep their own name.
        assert_eq!(
            call_16s(&[("Mycolicibacterium fortuitum", 99.0)]),
            Some("Mycolicibacterium fortuitum".to_string())
        );
    }

    #[test]
    fn species_16s_marinum_ulcerans_group() {
        assert_eq!(
            call_16s(&[
                ("Mycobacterium marinum", 99.0),
                ("Mycobacterium ulcerans", 99.0)
            ]),
            Some("M. marinum/ulcerans group".to_string())
        );
    }

    #[test]
    fn species_16s_ungrouped_and_mixed_ties() {
        assert_eq!(
            call_16s(&[("Mycobacterium szulgai", 99.0)]),
            Some("Mycobacterium szulgai".to_string())
        );
        assert_eq!(
            call_16s(&[
                ("Mycobacterium szulgai", 99.0),
                ("Mycobacterium malmoense", 99.0),
                ("Mycobacterium xenopi", 98.0),
            ]),
            Some("Mycobacterium szulgai/malmoense".to_string())
        );
        assert_eq!(
            call_16s(&[
                ("Mycobacterium kansasii", 99.0),
                ("Mycobacterium szulgai", 99.0),
                ("Mycobacterium persicum", 99.0),
            ]),
            Some("M. kansasii complex / Mycobacterium szulgai".to_string())
        );
        // "abscessus" in another genus is no longer caught by a substring rule.
        assert_eq!(
            call_16s(&[("Nocardia abscessus", 99.0)]),
            Some("Nocardia abscessus".to_string())
        );
        assert_eq!(call_16s(&[]), None);
    }

    fn cached_record(path: &Path) -> SampleSusceptibilityRecord {
        let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
        let (sample_id, gene) = parse_ab1_filename(&file_name);
        SampleSusceptibilityRecord {
            sample_id,
            gene: gene.map(|g| g.label().to_string()),
            file_name,
            file_path: path.to_path_buf(),
            file_created: None,
            susceptibility_calls: SusceptibilityCalls::default(),
            species: None,
            identity: None,
            species_gtdb: None,
            identity_gtdb: None,
            is_susceptible: None,
            seq_id_hits: vec![SeqIdHit {
                accession: "X".to_string(),
                description: "Mycobacterium kansasii".to_string(),
                source: RefSource::Ncbi,
                identity: 99.0,
                is_reverse: false,
                rrl_snp_calls: Vec::new(),
                rrs_snp_calls: Vec::new(),
                rrs_snp_calls_3end: Vec::new(),
                erm41_snp_calls: Vec::new(),
                pnca_snp_calls: Vec::new(),
                rpob_snp_calls: Vec::new(),
                aligned_query: b"ACGT".to_vec(),
                aligned_ref: b"ACGT".to_vec(),
                ref_start: 0,
                erm41_position_28_opt: None,
                rrs3end_position_1248_opt: None,
                rrl_position_2058_2059_opt: None,
            }],
            analysis_version: ANALYSIS_VERSION,
        }
    }

    #[test]
    fn preload_loads_only_rows_matching_the_file_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("24-000001-16S.ab1");
        let changed = dir.path().join("24-000002-16S.ab1");
        let deleted = dir.path().join("24-000003-16S.ab1");
        std::fs::write(&current, b"current").unwrap();
        std::fs::write(&changed, b"changed").unwrap();
        let current = current.canonicalize().unwrap();
        let changed = changed.canonicalize().unwrap();

        let cache_file = dir.path().join("scan.sqlite");
        {
            let mut cache = DiskCache::open(&cache_file).unwrap();
            for path in [&current, &changed] {
                let (mtime, size) = file_stamp(std::fs::metadata(path).ok().as_ref());
                // `changed` is stored with a stale size, as if the file was rewritten since.
                let size = if path == &changed { size + 1 } else { size };
                let key = path.to_string_lossy().into_owned();
                cache.put(&key, mtime, size, &cached_record(path));
            }
            let key = deleted.to_string_lossy().into_owned();
            cache.put(&key, 1, 1, &cached_record(&deleted));
        }

        assert_eq!(preload_disk_cache(&cache_file), 1);
        let guard = AB1_SEQ_CACHE.read().unwrap();
        assert!(guard.get(&current).is_some_and(|e| e.hits.len() == 1));
        assert!(!guard.contains_key(&changed));
        assert!(!guard.contains_key(&deleted));
    }

    #[test]
    fn rrs3end_resistance_enters_the_combined_verdict() {
        use super::super::rrs3end::RrsSnpCall3End;
        let mut h = hit("Mycobacterium abscessus", 99.0);
        h.source = RefSource::Ncbi;
        h.rrs_snp_calls_3end = vec![RrsSnpCall3End {
            ref_pos: 1400,
            query_base: Some(b'G'),
            wt_base: b'A',
            resistance_bases: [(b'G', (vec!["amikacin".to_string()], "A1408G".to_string()))]
                .into_iter()
                .collect(),
        }];
        let (verdict, calls) = susceptibility_from_hits(&[h]);
        assert_eq!(calls.rrs3end.is_susceptible, Some(false));
        assert_eq!(calls.rrs3end.is_susceptible_rare, Some(false));
        assert_eq!(verdict, Some(false));
    }

    #[test]
    fn massiliense_is_susceptible_whatever_position_28_shows() {
        use super::super::erm41::Erm41Position28;
        let mut h = hit(DESC_MASSILIENSE, 99.0);
        h.erm41_position_28_opt = Some(Erm41Position28::T28);
        let (verdict, calls) = susceptibility_from_hits(&[h]);
        assert_eq!(calls.erm41.is_susceptible, Some(true));
        assert_eq!(verdict, Some(true));
        assert_eq!(susceptibility_from_hits(&[]).0, None);
    }

    #[test]
    fn rare_mutations_csv_removed_when_nothing_qualifies() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("rare_mutations.csv");
        let mut rec = cached_record(&dir.path().join("2024000001_rrl.ab1"));
        rec.identity = Some(99.0);
        rec.susceptibility_calls.rrl.is_susceptible_rare = Some(false);

        write_rare_mutations_csv(std::slice::from_ref(&rec), &out, 30).unwrap();
        assert!(
            std::fs::read_to_string(&out)
                .unwrap()
                .contains("2024000001")
        );

        // Outside the age window: the earlier file must not linger.
        rec.file_created = Some(SystemTime::now() - Duration::from_secs(40 * 86_400));
        write_rare_mutations_csv(&[rec], &out, 30).unwrap();
        assert!(!out.exists());
        // Nothing to remove is fine too.
        write_rare_mutations_csv(&[], &out, 30).unwrap();
    }

    #[test]
    fn memory_cache_ignores_hits_of_a_changed_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("2024000009_16S.ab1");
        std::fs::write(&path, b"first").unwrap();
        let path = path.canonicalize().unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        insert_hits(
            path.clone(),
            file_stamp(Some(&meta)),
            cached_record(&path).seq_id_hits,
        );
        assert_eq!(cached_hits(&path, &meta).map(|h| h.len()), Some(1));

        std::fs::write(&path, b"rewritten, longer").unwrap();
        let changed = std::fs::metadata(&path).unwrap();
        assert!(cached_hits(&path, &changed).is_none());
    }

    #[test]
    fn preload_of_a_missing_cache_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cache_file = dir.path().join("none.sqlite");
        assert_eq!(preload_disk_cache(&cache_file), 0);
        assert!(!cache_file.exists());
    }
}
