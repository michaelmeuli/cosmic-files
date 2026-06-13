use std::path::PathBuf;
use walkdir::WalkDir;

use super::{
    SusceptibilityCalls,
    erm41::{Erm41SusceptibilityCalls, identify_sequence_erm41, is_susceptible_erm41},
    hsp65::identify_sequence_hsp65,
    parse_ab1_quality, parse_ab1_sequence,
    rpob::identify_sequence_rpob,
    rrl::{RrlSusceptibilityCalls, identify_sequence_rrl_ntm, is_susceptible_rrl},
    rrs::{RrsSusceptibilityCalls, identify_sequence_16s, is_susceptible_rrs},
    trim_to_min_quality,
};

/// Per-sample susceptibility result produced by the batch AB1 directory scan.
#[derive(Clone, Debug)]
pub struct SampleSusceptibilityRecord {
    pub sample_id: String,
    pub gene: Option<String>,
    pub file_name: String,
    pub file_path: PathBuf,
    pub file_created: Option<std::time::SystemTime>,
    pub susceptibility_calls: SusceptibilityCalls,
    pub species: Option<String>,
    pub identity: Option<f32>,
    pub is_susceptible: Option<bool>,
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
        Some("erm41".to_string())
    } else if lower_name.contains("hsp65") || lower_name.contains("65kda") {
        Some("hsp65".to_string())
    } else if lower_name.contains("rpob") || lower_name.contains("rpo") {
        Some("rpoB".to_string())
    } else if lower_name.contains("mbak14") {
        Some("16s".to_string())
    } else if lower_name.contains("rrl") || lower_name.contains("mclr") {
        Some("rrl".to_string())
    } else {
        None
    };

    (sample_id, gene)
}

/// Walk `scan_path` recursively, analyse every `.ab1` file, and return a
/// `SampleSusceptibilityRecord` per file sorted reverse-alphabetically by
/// `sample_id` (highest first).
pub fn scan_ab1_directory(scan_path: PathBuf) -> Vec<SampleSusceptibilityRecord> {
    let mut records = Vec::new();

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

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let lower_name = file_name.to_ascii_lowercase();
        let (sample_id, gene) = parse_ab1_filename(&file_name);
        let file_created = std::fs::metadata(path).ok().and_then(|m| m.created().ok());

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

        let ab1_seq = parse_ab1_sequence(&bytes);
        let ab1_qual = parse_ab1_quality(&bytes);

        let seq_id_hits = if let Some(seq) = ab1_seq.as_ref() {
            let trimmed: &[u8] = match &ab1_qual {
                Some(qual) => trim_to_min_quality(seq, qual, 10).unwrap_or(seq.as_slice()),
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
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let is_susceptible = seq_id_hits.first().and_then(|hit| {
            let erm41_result = is_susceptible_erm41(hit.erm41_position_28_opt.as_ref(), &hit.erm41_snp_calls);
            if erm41_result.is_some() {
                return erm41_result;
            }
            let rrl_result = is_susceptible_rrl(hit.rrl_position_2058_2059_opt.as_ref(), &hit.rrl_snp_calls);
            if rrl_result.is_some() {
                return rrl_result;
            }
            is_susceptible_rrs(&hit.rrs_snp_calls)
        });

        let susceptibility_calls = seq_id_hits
            .first()
            .map(|hit| SusceptibilityCalls {
                erm41: Erm41SusceptibilityCalls {
                    position_28: hit.erm41_position_28_opt,
                    lof_snp_calls: hit.erm41_snp_calls.clone(),
                    is_susceptible: is_susceptible_erm41(hit.erm41_position_28_opt.as_ref(), &hit.erm41_snp_calls),
                },
                rrl: RrlSusceptibilityCalls {
                    position_2058_2059: hit.rrl_position_2058_2059_opt,
                    snp_calls: hit.rrl_snp_calls.clone(),
                    is_susceptible: is_susceptible_rrl(hit.rrl_position_2058_2059_opt.as_ref(), &hit.rrl_snp_calls),
                },
                rrs: RrsSusceptibilityCalls {
                    snp_calls: hit.rrs_snp_calls.clone(),
                    is_susceptible: is_susceptible_rrs(&hit.rrs_snp_calls),
                },
            })
            .unwrap_or_default();

        records.push(SampleSusceptibilityRecord {
            sample_id,
            gene,
            file_name,
            file_path: path.to_path_buf(),
            file_created,
            susceptibility_calls,
            species: seq_id_hits.first().map(|h| h.description.clone()),
            identity: seq_id_hits.first().map(|h| h.identity),
            is_susceptible,
        });
    }

    // Reverse-alphabetical by sample_id (highest first)
    records.sort_by(|a, b| b.sample_id.cmp(&a.sample_id));
    records
}

/// Write `records` to a CSV file at `out_path`.
///
/// Columns: `sample_id, gene, file_name, file_created, species, identity_pct,
/// erm41_position_28, erm41_susceptible, rrl_position_2058_2059, rrl_susceptible,
/// rrs_susceptible, overall_susceptible`
pub fn write_ab1_csv(
    records: &[SampleSusceptibilityRecord],
    out_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::create(out_path)?;
    let mut wtr = csv::Writer::from_writer(file);

    wtr.write_record([
        "sample_id",
        "gene",
        "file_name",
        "file_created",
        "species",
        "identity_pct",
        "erm41_position_28",
        "erm41_susceptible",
        "erm41_lof_snp_calls",
        "rrl_position_2058_2059",
        "rrl_susceptible",
        "rrl_snp_calls",
        "rrs_susceptible",
        "rrs_snp_calls",
        "overall_susceptible",
    ])?;

    for rec in records {
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

        let overall = fmt_susceptible(rec.is_susceptible);

        wtr.write_record([
            rec.sample_id.as_str(),
            rec.gene.as_deref().unwrap_or(""),
            rec.file_name.as_str(),
            file_created.as_str(),
            rec.species.as_deref().unwrap_or(""),
            &rec.identity.map(|i| format!("{:.1}", i)).unwrap_or_default(),
            erm41_pos.as_str(),
            erm41_sus.as_str(),
            erm41_lof.as_str(),
            rrl_pos.as_str(),
            rrl_sus.as_str(),
            rrl_snps.as_str(),
            rrs_sus.as_str(),
            rrs_snps.as_str(),
            overall.as_str(),
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
