use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;
use serde::{Deserialize, Serialize};

use super::{
    DESC_MASSILIENSE, MIN_SEQ_ID_IDENTITY, SeqIdHit, SusceptibilityCalls,
    erm41::{Erm41SusceptibilityCalls, identify_sequence_erm41, is_susceptible_erm41},
    hsp65::identify_sequence_hsp65,
    parse_ab1_quality, parse_ab1_sequence,
    pnca::{PncaSusceptibilityCalls, identify_sequence_pnca, is_susceptible_pnca},
    rpob::identify_sequence_rpob,
    rrl::{RrlSusceptibilityCalls, identify_sequence_rrl_ntm, is_susceptible_rrl, is_susceptible_rrl_by_snp_calls_rare},
    rrs::{RrsSusceptibilityCalls, identify_sequence_16s, is_susceptible_rrs, is_susceptible_rrs_by_snp_calls_rare},
    trim_to_min_quality,
};

/// In-memory cache: maps each AB1 file path to the seq_id_hits computed by the last background
/// scan. `item_from_entry()` reads from this cache instead of running alignment on the UI thread.
pub(crate) static AB1_SEQ_CACHE: LazyLock<RwLock<HashMap<PathBuf, Vec<SeqIdHit>>>> =
    LazyLock::new(|| RwLock::new(HashMap::default()));

/// Per-sample susceptibility result produced by the batch AB1 directory scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SampleSusceptibilityRecord {
    pub sample_id: String,
    pub gene: Option<String>,
    pub file_name: String,
    pub file_path: PathBuf,
    #[serde(with = "super::serde_helpers::option_systemtime_secs")]
    pub file_created: Option<SystemTime>,
    pub susceptibility_calls: SusceptibilityCalls,
    pub species: Option<String>,
    pub identity: Option<f32>,
    pub is_susceptible: Option<bool>,
    /// Top alignment hits — stored in disk cache (alignment strings stripped) so the preview
    /// panel can be populated from disk cache without re-running alignment.
    #[serde(default)]
    pub seq_id_hits: Vec<SeqIdHit>,
}

/// Find the first run of exactly 10 consecutive ASCII digits starting with "20"
/// that is not embedded inside a longer digit run.
fn find_sample_id(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 10 <= bytes.len() {
        if bytes[i..i + 2] == *b"20" && bytes[i..i + 10].iter().all(|b| b.is_ascii_digit()) {
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
            let after_ok = i + 10 == bytes.len() || !bytes[i + 10].is_ascii_digit();
            if before_ok && after_ok {
                return Some(&s[i..i + 10]);
            }
        }
        i += 1;
    }
    None
}

/// Extract `(sample_id, gene)` from an AB1 filename.
///
/// `sample_id` is the first token of 10 digits starting with "20", or a
/// fallback of the full stem when no such token is found.
/// Gene is inferred from keywords anywhere in the lowercase filename.
pub fn parse_ab1_filename(name: &str) -> (String, Option<String>) {
    let stem = std::path::Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name);

    let sample_id = find_sample_id(stem).unwrap_or(stem).to_string();

    let lower_name = name.to_ascii_lowercase();
    let gene = if lower_name.contains("erm41") || lower_name.contains("erm") {
        Some("erm(41)".to_string())
    } else if lower_name.contains("hsp65") || lower_name.contains("65kda") {
        Some("hsp65".to_string())
    } else if lower_name.contains("rpob") || lower_name.contains("rpo") {
        Some("rpoB".to_string())
    } else if lower_name.contains("mbak14") {
        Some("16S".to_string())
    } else if lower_name.contains("rrl") || lower_name.contains("mclr") {
        Some("rrl".to_string())
    } else if lower_name.contains("pnca") {
        Some("pncA".to_string())
    } else {
        None
    };

    (sample_id, gene)
}

/// Walk `scan_path` recursively, analyse every `.ab1` file, and return a
/// `SampleSusceptibilityRecord` per file sorted reverse-alphabetically by
/// `sample_id` (highest first).
///
/// `cache_path` — path to the JSON disk cache file; `None` disables disk caching.
/// `max_age_days` — files whose creation time is older than this many days are skipped
/// (mirrors the PDF report window). Pass `0` to disable age filtering.
pub fn scan_ab1_directory(
    scan_path: PathBuf,
    cache_path: Option<PathBuf>,
    max_age_days: u32,
) -> Vec<SampleSusceptibilityRecord> {
    log::debug!("ab1_scan: starting scan of {} (max_age_days={}, cache_path={:?})", scan_path.display(), max_age_days, cache_path);

    // Load disk cache: HashMap<path_string, (mtime_secs, record)>
    type DiskCache = HashMap<String, (u64, SampleSusceptibilityRecord)>;
    let mut disk_cache: DiskCache = cache_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    log::debug!("ab1_scan: loaded {} disk cache entries", disk_cache.len());

    let now = SystemTime::now();
    let max_age = (max_age_days > 0)
        .then(|| Duration::from_secs(u64::from(max_age_days) * 86_400));

    let mut records = Vec::new();
    let mut cache_dirty = false;

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
        if let (Some(max_age), Some(created)) = (&max_age, file_created) {
            if now.duration_since(created).is_ok_and(|age| age > *max_age) {
                log::debug!("ab1_scan: skipping old file: {}", path.display());
                continue;
            }
        }

        let mtime_secs: u64 = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let path_key = path.to_string_lossy().into_owned();

        // Canonicalize so the key matches the \\?\ -prefixed paths the file manager uses.
        let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        // Disk cache hit: mtime unchanged and seq_id_hits stored → reuse previous result.
        if let Some((cached_mtime, cached_record)) = disk_cache.get(&path_key) {
            if *cached_mtime == mtime_secs && !cached_record.seq_id_hits.is_empty() {
                log::debug!("ab1_scan: disk cache hit for {} ({} hits, canonical={})", path.display(), cached_record.seq_id_hits.len(), canonical_path.display());
                if let Ok(mut guard) = AB1_SEQ_CACHE.write() {
                    guard.insert(canonical_path, cached_record.seq_id_hits.clone());
                }
                records.push(cached_record.clone());
                continue;
            } else {
                log::debug!("ab1_scan: disk cache stale/no-hits for {} (mtime_match={}, hits={})", path.display(), *cached_mtime == mtime_secs, cached_record.seq_id_hits.len());
            }
        } else {
            log::debug!("ab1_scan: no disk cache entry for {}", path.display());
        }

        // Cache miss — run full alignment pipeline.
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let lower_name = file_name.to_ascii_lowercase();
        let (sample_id, gene) = parse_ab1_filename(&file_name);

        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("ab1 batch scan: failed to read {}: {e}", path.display());
                continue;
            }
        };

        let is_erm41 = lower_name.contains("erm41") || lower_name.contains("erm");
        let is_hsp65 = lower_name.contains("hsp65") || lower_name.contains("65kda");
        let is_rpob = lower_name.contains("rpob") || lower_name.contains("rpo");
        let is_16s = lower_name.contains("mbak14");
        let is_23s_ntm = lower_name.contains("rrl") || lower_name.contains("mclr");
        let is_pnca = lower_name.contains("pnca");

        let ab1_seq = parse_ab1_sequence(&bytes);
        let ab1_qual = parse_ab1_quality(&bytes);

        let seq_id_hits = if let Some(seq) = ab1_seq.as_ref() {
            let trimmed: &[u8] = match &ab1_qual {
                Some(qual) => trim_to_min_quality(seq, qual, 20).unwrap_or(seq.as_slice()),
                None => seq.as_slice(),
            };
            if is_erm41 {
                identify_sequence_erm41(trimmed)
            } else if is_hsp65 {
                identify_sequence_hsp65(trimmed)
            } else if is_rpob {
                identify_sequence_rpob(trimmed)
            } else if is_23s_ntm {
                identify_sequence_rrl_ntm(trimmed)
            } else if is_16s {
                identify_sequence_16s(trimmed)
            } else if is_pnca {
                identify_sequence_pnca(trimmed)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Populate the in-memory cache using the canonical path so it matches what item_from_entry() uses.
        log::debug!("ab1_scan: alignment done for {} → {} hits (top: {:?}, canonical={})", path.display(), seq_id_hits.len(), seq_id_hits.first().map(|h| (&h.description, h.identity)), canonical_path.display());
        if let Ok(mut guard) = AB1_SEQ_CACHE.write() {
            guard.insert(canonical_path, seq_id_hits.clone());
        }

        let is_susceptible = seq_id_hits.first().and_then(|hit| {
            let erm41_result = if hit.description == DESC_MASSILIENSE {
                Some(true)
            } else {
                is_susceptible_erm41(hit.erm41_position_28_opt.as_ref(), &hit.erm41_snp_calls)
            };
            if erm41_result.is_some() {
                return erm41_result;
            }
            let rrl_result = is_susceptible_rrl(hit.rrl_position_2058_2059_opt.as_ref(), &hit.rrl_snp_calls);
            if rrl_result.is_some() {
                return rrl_result;
            }
            let rrs_result = is_susceptible_rrs(&hit.rrs_snp_calls);
            if rrs_result.is_some() {
                return rrs_result;
            }
            is_susceptible_pnca(&hit.pnca_snp_calls)
        });

        let susceptibility_calls = seq_id_hits
            .first()
            .map(|hit| SusceptibilityCalls {
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
                    snp_calls: hit.rrl_snp_calls.clone(),
                    is_susceptible: is_susceptible_rrl(hit.rrl_position_2058_2059_opt.as_ref(), &hit.rrl_snp_calls),
                    is_susceptible_rare: is_susceptible_rrl_by_snp_calls_rare(hit.rrl_position_2058_2059_opt.as_ref(), &hit.rrl_snp_calls),
                },
                rrs: RrsSusceptibilityCalls {
                    snp_calls: hit.rrs_snp_calls.clone(),
                    is_susceptible: is_susceptible_rrs(&hit.rrs_snp_calls),
                    is_susceptible_rare: is_susceptible_rrs_by_snp_calls_rare(&hit.rrs_snp_calls),
                },
                pnca: PncaSusceptibilityCalls {
                    snp_calls: hit.pnca_snp_calls.clone(),
                    is_susceptible: is_susceptible_pnca(&hit.pnca_snp_calls),
                },
            })
            .unwrap_or_default();

        let record = SampleSusceptibilityRecord {
            sample_id,
            gene,
            file_name,
            file_path: path.to_path_buf(),
            file_created,
            susceptibility_calls,
            species: seq_id_hits.first().map(|h| h.description.clone()),
            identity: seq_id_hits.first().map(|h| h.identity),
            is_susceptible,
            seq_id_hits: seq_id_hits.iter().take(5).cloned().collect(),
        };

        disk_cache.insert(path_key, (mtime_secs, record.clone()));
        cache_dirty = true;
        records.push(record);
    }

    // Persist the updated disk cache.
    if cache_dirty {
        if let Some(cp) = &cache_path {
            match serde_json::to_string(&disk_cache) {
                Ok(json) => {
                    if let Err(e) = std::fs::write(cp, json) {
                        log::warn!("ab1 scan: failed to write disk cache {}: {e}", cp.display());
                    }
                }
                Err(e) => log::warn!("ab1 scan: failed to serialise disk cache: {e}"),
            }
        }
    }

    let mem_cache_size = AB1_SEQ_CACHE.read().map(|g| g.len()).unwrap_or(0);
    log::debug!("ab1_scan: finished: {} records, AB1_SEQ_CACHE has {} entries", records.len(), mem_cache_size);

    // Reverse-alphabetical by sample_id (highest first)
    records.sort_by(|a, b| b.sample_id.cmp(&a.sample_id));
    records
}

/// Write `records` to a CSV file at `out_path`.
///
/// Columns: `file_name, sample_id, gene, overall_susceptible, species, identity_pct,
/// erm41_position_28, erm41_lof_snp_calls, erm41_susceptible, rrl_position_2058_2059,
/// rrl_snp_calls, rrl_susceptible, rrs_snp_calls, rrs_susceptible, file_created`
pub fn write_ab1_csv(
    records: &[SampleSusceptibilityRecord],
    out_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
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
        "pnca_snp_calls",
        "pnca_susceptible",
        "file_created",
    ])?;

    for rec in records {
        if rec.gene.is_none() {
            continue;
        }
        if rec.identity.is_none_or(|i| i < MIN_SEQ_ID_IDENTITY) {
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

        let pnca_sus = fmt_susceptible(rec.susceptibility_calls.pnca.is_susceptible);
        let pnca_snps = pnca_snp_calls_str(&rec.susceptibility_calls.pnca.snp_calls);

        let overall = fmt_susceptible(rec.is_susceptible);

        wtr.write_record([
            rec.file_name.as_str(),
            rec.sample_id.as_str(),
            rec.gene.as_deref().unwrap_or(""),
            overall.as_str(),
            rec.species.as_deref().unwrap_or(""),
            &rec.identity.map(|i| format!("{:.1}", i)).unwrap_or_default(),
            erm41_pos.as_str(),
            erm41_lof.as_str(),
            erm41_sus.as_str(),
            rrl_pos.as_str(),
            rrl_snps.as_str(),
            rrl_sus.as_str(),
            rrs_snps.as_str(),
            rrs_sus.as_str(),
            pnca_snps.as_str(),
            pnca_sus.as_str(),
            file_created.as_str(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

/// Write records that flag a rare resistance mutation (`is_susceptible_rare == Some(false)` for
/// rrl or rrs) to `out_path`. Same columns as `write_ab1_csv` plus `rrl_susceptible_rare` and
/// `rrs_susceptible_rare`.
pub fn write_rare_mutations_csv(
    records: &[SampleSusceptibilityRecord],
    out_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let rare: Vec<&SampleSusceptibilityRecord> = records
        .iter()
        .filter(|rec| {
            rec.gene.is_some()
                && rec.identity.is_some_and(|i| i >= MIN_SEQ_ID_IDENTITY)
                && (rec.susceptibility_calls.rrl.is_susceptible_rare == Some(false)
                    || rec.susceptibility_calls.rrs.is_susceptible_rare == Some(false))
        })
        .collect();

    if rare.is_empty() {
        return Ok(());
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

        let overall = fmt_susceptible(rec.is_susceptible);

        wtr.write_record([
            rec.file_name.as_str(),
            rec.sample_id.as_str(),
            rec.gene.as_deref().unwrap_or(""),
            overall.as_str(),
            rec.species.as_deref().unwrap_or(""),
            &rec.identity.map(|i| format!("{:.1}", i)).unwrap_or_default(),
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
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

fn fmt_susceptible(v: Option<bool>) -> String {
    match v {
        Some(true) => "susceptible".to_string(),
        Some(false) => "resistant".to_string(),
        None => String::new(),
    }
}

fn snp_calls_str(calls: impl Iterator<Item = (usize, String)>) -> String {
    calls
        .map(|(pos, tag)| format!("pos {}: {}", pos + 1, tag))
        .collect::<Vec<_>>()
        .join("; ")
}

fn pnca_snp_calls_str(calls: &[super::pnca::PncaSnpCall]) -> String {
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
    fn test_parse_ab1_filename() {
        let (id, gene) = parse_ab1_filename("2026311072 rrl R 2.4.26_MCLR 21R.ab1");
        assert_eq!(id, "2026311072");
        assert_eq!(gene.as_deref(), Some("rrl"));

        let (id, gene) = parse_ab1_filename("12345.ab1");
        assert_eq!(id, "12345");
        assert_eq!(gene, None);
    }

    #[test]
    fn test_system_time_to_iso8601() {
        use std::time::{Duration, UNIX_EPOCH};
        // 2024-01-15T00:00:00Z = 1705276800 seconds since epoch
        let t = UNIX_EPOCH + Duration::from_secs(1_705_276_800);
        assert_eq!(system_time_to_iso8601(t), "2024-01-15T00:00:00Z");
    }
}
