//! Sequence-based species identification for Mycobacteriaceae.
//!
//! ### Generation of species identification databases
//!
//! The database sequences are flagged as type material using the
//! [INSD Collaboration `type_material` qualifier](https://pmc.ncbi.nlm.nih.gov/articles/PMC4383940/).
//! Type material ties formal species names to physical specimens (culture collections for prokaryotes,
//! museum or herbarium specimens for eukaryotes), as annotated in the
//! [NCBI Taxonomy Database](http://www.ncbi.nlm.nih.gov/taxonomy).
//! 
//! See fn fetch_myco_sequences() in build.rs for details on how the sequences were fetched from NCBI at build time.
//! 
//! `myco_erm41.fasta` is generated at build time but unused; erm41 identification uses
//! per-subspecies references (`erm41_abscessus_ATCC_19977.fasta`, `erm41_bolletii_CIP_108541.fasta`, `erm41_massiliense_CCUG_48898.fasta`) instead.

pub mod batch;
pub mod bed;
pub mod erm41;
pub mod hsp65;
pub mod ntfy_notify;
pub mod rpob;
pub mod rrs;
pub mod rrl;
pub mod tb_data;

pub use batch::SampleSusceptibilityRecord;

use erm41::{Erm41LofCall, Erm41Position28, Erm41SusceptibilityCalls};
use hsp65::{KansasiiGastriSnpCall, MarinumUlceransSnpCall};
use rrl::{RrlPosition2058_2059, RrlSnpCall, RrlSusceptibilityCalls};
use rrs::{RrsSnpCall, RrsSusceptibilityCalls};

pub const MIN_SEQ_ID_IDENTITY: f32 = 80.0;

const ERM41_FWD_START: &[u8] = b"gtgtccggccaacggtcgcg";
const ERM41_FWD_END: &[u8] = b"tggtgatcaggcggcgctga";
const ERM41_ANCHOR_L: &[u8] = b"GCCAACGGTCGCGACGCCAG";
const ERM41_ANCHOR_R: &[u8] = b"GGGGCTGGTATCCGCTCACT";

const RRL_FWD_START: &[u8] = b"ctaagttcttaagggcgcat";
const RRL_FWD_END: &[u8] = b"ctaagttcttaagggcgcat";
const RRL_ANCHOR_L: &[u8] = b"CGTTACGCGCGGCAGGACGA";
const RRL_ANCHOR_R: &[u8] = b"AGACCCCGGGACCTTCACTA";

const REF_ERM41_ABSCESSUS: &str =
    include_str!("../../res/sequences/erm41/erm41_abscessus_ATCC_19977.fasta");
const REF_ERM41_BOLLETII: &str =
    include_str!("../../res/sequences/erm41/erm41_bolletii_CIP_108541.fasta");
const REF_ERM41_MASSILENSE: &str =
    include_str!("../../res/sequences/erm41/erm41_massiliense_CCUG_48898.fasta");

const ACC_GASTRI: &str = "AF547836";
const ACC_KANSASII: &str = "AF547849";
const ACC_MARINUM: &str = "AY299134";
const ACC_ULCERANS: &str = "AY299145";
const KANSASII_GASTRI_ACCS: &[&str] = &[ACC_GASTRI, ACC_KANSASII];
const MARINUM_ULCERANS_ACCS: &[&str] = &[ACC_MARINUM, ACC_ULCERANS];

/// 16S rRNA (rrs) reference sequences — Mycobacteriaceae type strains, fetched from NCBI at build time.
const REF_MYCO_RRS: &str = include_str!("../../res/sequences/myco_rrs.fasta");
/// hsp65 / groEL2 reference sequences — Mycobacteriaceae type strains, fetched from NCBI at build time.
const REF_MYCO_HSP65: &str = include_str!("../../res/sequences/myco_hsp65.fasta");
/// rpoB reference sequences — Mycobacteriaceae type strains, fetched from NCBI at build time.
const REF_MYCO_RPOB: &str = include_str!("../../res/sequences/myco_rpob.fasta");
/// 23S rRNA (rrl) reference sequences — Mycobacteriaceae type strains, fetched from NCBI at build time.
const REF_MYCO_RRL: &str = include_str!("../../res/sequences/myco_rrl.fasta");

/// Susceptibility calls derived from AB1 capillary sequencing, keyed by gene target.
#[derive(Debug, Clone, Default)]
pub struct SusceptibilityCalls {
    pub erm41: Erm41SusceptibilityCalls,
    pub rrl: RrlSusceptibilityCalls,
    pub rrs: RrsSusceptibilityCalls,
}

impl std::fmt::Display for SusceptibilityCalls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = Vec::new();

        let mut erm: Vec<String> = Vec::new();
        if let Some(pos) = &self.erm41.position_28 {
            erm.push(pos.to_string());
        }
        for c in &self.erm41.lof_snp_calls {
            erm.push(c.call_tag());
        }
        if !erm.is_empty() {
            parts.push(format!("{}", erm.join(", ")));
        }

        let mut rrl: Vec<String> = Vec::new();
        if let Some(pos) = &self.rrl.position_2058_2059 {
            rrl.push(pos.to_string());
        }
        for c in &self.rrl.snp_calls {
            rrl.push(c.call_tag());
        }
        if !rrl.is_empty() {
            parts.push(format!("{}", rrl.join(", ")));
        }

        let rrs: Vec<String> = self.rrs.snp_calls.iter().map(|c| c.call_tag()).collect();
        if !rrs.is_empty() {
            parts.push(format!("{}", rrs.join(", ")));
        }

        write!(f, "{}", parts.join(" | "))
    }
}

pub fn reverse_complement(seq: &[u8]) -> Vec<u8> {
    seq.iter()
        .rev()
        .map(|&b| match b.to_ascii_uppercase() {
            b'A' => b'T',
            b'T' => b'A',
            b'G' => b'C',
            b'C' => b'G',
            _ => b'N',
        })
        .collect()
}

pub fn trim_start_end<'a>(seq: &'a [u8], fwd_start: &[u8], fwd_end: &[u8]) -> &'a [u8] {
    let rc_start: Vec<u8> = reverse_complement(fwd_end);
    let rc_end: Vec<u8> = reverse_complement(fwd_start);

    let find_start = |p: &[u8]| seq.windows(p.len()).position(|w| w.eq_ignore_ascii_case(p));
    let find_end = |p: &[u8]| {
        seq.windows(p.len())
            .rposition(|w| w.eq_ignore_ascii_case(p))
            .map(|pos| pos + p.len())
    };

    let start = [fwd_start, rc_start.as_slice()]
        .into_iter()
        .filter_map(find_start)
        .min()
        .unwrap_or(0);

    let end = [fwd_end, rc_end.as_slice()]
        .into_iter()
        .filter_map(find_end)
        .max()
        .unwrap_or(seq.len());

    &seq[start..end.min(seq.len())]
}


/// Trim leading and trailing bases whose Phred quality score is below `min_q`.
/// Returns `None` if no base meets the threshold (the caller decides the fallback).
pub fn trim_to_min_quality<'a>(seq: &'a [u8], qual: &[u8], min_q: u8) -> Option<&'a [u8]> {
    let start = seq
        .iter()
        .enumerate()
        .find(|&(i, _)| qual.get(i).copied().unwrap_or(0) >= min_q)
        .map(|(i, _)| i)
        .unwrap_or(seq.len());

    let end = seq
        .iter()
        .enumerate()
        .rev()
        .find(|&(i, _)| qual.get(i).copied().unwrap_or(0) >= min_q)
        .map(|(i, _)| i + 1)
        .unwrap_or(0);

    if start >= end { None } else { Some(&seq[start..end]) }
}

/// Parse a FASTA string, returning just the sequence bytes (ignores header).
pub(crate) fn parse_fasta_seq(fasta: &str) -> Vec<u8> {
    fasta
        .lines()
        .filter(|l| !l.starts_with('>'))
        .flat_map(|l| l.bytes().filter(|b| b.is_ascii_alphabetic()))
        .collect()
}

/// Parse a multi-FASTA string into `(accession, description, sequence)` tuples.
fn parse_multi_fasta(fasta: &str) -> Vec<(String, String, Vec<u8>)> {
    let mut result = Vec::new();
    let mut cur_acc = String::new();
    let mut cur_desc = String::new();
    let mut cur_seq: Vec<u8> = Vec::new();
    for line in fasta.lines() {
        if let Some(rest) = line.strip_prefix('>') {
            if !cur_acc.is_empty() {
                result.push((
                    cur_acc.clone(),
                    cur_desc.clone(),
                    std::mem::take(&mut cur_seq),
                ));
            }
            let mut words = rest.splitn(4, ' ');
            cur_acc = words.next().unwrap_or("").to_string();
            let genus = words.next().unwrap_or("");
            let species = words.next().unwrap_or("");
            cur_desc = format!("{} {}", genus, species).trim().to_string();
        } else {
            cur_seq.extend(line.bytes().filter(|b| b.is_ascii_alphabetic()));
        }
    }
    if !cur_acc.is_empty() {
        result.push((cur_acc, cur_desc, cur_seq));
    }
    result
}

fn format_pairwise_alignment(
    accession: &str,
    description: &str,
    identity: f32,
    is_reverse: bool,
    query: &[u8],
    refseq: &[u8],
    offset: isize,
) -> String {
    let (ref_padded, query_padded): (Vec<u8>, Vec<u8>) = if query.len() <= refseq.len() {
        let start = offset as usize;
        let end = start + query.len();
        let ref_p = refseq.to_vec();
        let query_p: Vec<u8> = (0..refseq.len())
            .map(|i| {
                if i >= start && i < end {
                    query[i - start]
                } else {
                    b'-'
                }
            })
            .collect();
        (ref_p, query_p)
    } else {
        let start = (-offset) as usize;
        let end = start + refseq.len();
        let query_p = query.to_vec();
        let ref_p: Vec<u8> = (0..query.len())
            .map(|i| {
                if i >= start && i < end {
                    refseq[i - start]
                } else {
                    b'-'
                }
            })
            .collect();
        (ref_p, query_p)
    };

    let match_line: Vec<u8> = ref_padded
        .iter()
        .zip(query_padded.iter())
        .map(|(&r, &q)| {
            if r == b'-' || q == b'-' {
                b' '
            } else if r.eq_ignore_ascii_case(&q) {
                b'|'
            } else {
                b'.'
            }
        })
        .collect();

    let orient = if is_reverse {
        "Reverse Complement"
    } else {
        "Forward"
    };
    let mut out = format!(
        "Query vs {} ({}) — {:.1}% identity\n\n",
        accession, description, identity
    );
    out.push_str(&format!("Orientation: {orient}\n\n"));

    let line_width = 60usize;
    let len = ref_padded.len();
    let mut ref_pos = 1usize;
    let mut query_pos = 1usize;
    for chunk_start in (0..len).step_by(line_width) {
        let chunk_end = (chunk_start + line_width).min(len);
        let ref_chunk = std::str::from_utf8(&ref_padded[chunk_start..chunk_end]).unwrap_or("");
        let match_chunk = std::str::from_utf8(&match_line[chunk_start..chunk_end]).unwrap_or("");
        let query_chunk = std::str::from_utf8(&query_padded[chunk_start..chunk_end]).unwrap_or("");

        out.push_str(&format!("Ref   {:5}: {}\n", ref_pos, ref_chunk));
        out.push_str(&format!("             {match_chunk}\n"));
        out.push_str(&format!("Query {:5}: {}\n\n", query_pos, query_chunk));

        ref_pos += ref_chunk.bytes().filter(|&b| b != b'-').count();
        query_pos += query_chunk.bytes().filter(|&b| b != b'-').count();
    }
    out
}

/// FNV-1a hash of a k-mer, case-insensitive.
fn kmer_hash(kmer: &[u8]) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for &b in kmer {
        h ^= b.to_ascii_uppercase() as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

/// Find the best **gapless** alignment between `query` and `reference` and return
/// `(percent_identity, offset)`.
///
/// # What it computes
///
/// The function considers only *diagonal* (shift-only, no-indel) alignments.
/// It picks the starting offset of the shorter sequence inside the longer one
/// that maximises the number of case-insensitive matching bases, then expresses
/// that as a percentage of the shorter sequence's length.
///
/// The signed `offset` tells you how the two sequences are positioned relative
/// to each other:
/// - `offset > 0`: `query` is the shorter sequence and its best match starts
///   `offset` bases into `reference` (reference extends to the left of query).
/// - `offset < 0`: `reference` is the shorter sequence and its best match
///   starts `|offset|` bases into `query` (query extends to the left of
///   reference).
/// - `offset == 0`: both sequences start at the same position, or one is
///   empty.
///
/// # Algorithm (two phases)
///
/// **Phase 1 – Seed.**  A k-mer index (word size 11) is built over the shorter
/// sequence.  The longer sequence is then scanned with a sliding window of the
/// same size.  Every exact k-mer match (verified byte-by-byte to rule out hash
/// collisions) pins a *diagonal*, i.e. a candidate offset.  This drastically
/// reduces the number of offsets that need full scoring and makes the function
/// sub-linear in the common case of high-identity pairs.
///
/// **Phase 2 – Extend.**  Each candidate diagonal is scored by counting all
/// matching positions across the full length of the shorter sequence (not just
/// the seed window).  If Phase 1 produced no seeds — because the sequences are
/// shorter than the word size or share no 11-mer — the fallback is to score
/// every possible offset exhaustively.  The offset with the highest match count
/// wins.
fn best_alignment(query: &[u8], reference: &[u8]) -> (f32, isize) {
    const WORD_SIZE: usize = 11;

    if query.is_empty() || reference.is_empty() {
        return (0.0, 0);
    }

    // Orient so `shorter` fits inside `longer`.
    let (shorter, longer, swapped) = if query.len() <= reference.len() {
        (query, reference, false)
    } else {
        (reference, query, true)
    };

    let max_offset = longer.len() - shorter.len();

    // ── Phase 1: seed ────────────────────────────────────────────────────────
    // Build a k-mer index over the shorter sequence, then scan the longer
    // sequence for matching k-mers.  Each match fixes a diagonal (offset).
    let mut candidates: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();

    if shorter.len() >= WORD_SIZE {
        let mut kmer_index: std::collections::HashMap<u64, Vec<usize>> =
            std::collections::HashMap::new();
        for (i, w) in shorter.windows(WORD_SIZE).enumerate() {
            kmer_index.entry(kmer_hash(w)).or_default().push(i);
        }
        for (j, w) in longer.windows(WORD_SIZE).enumerate() {
            if let Some(positions) = kmer_index.get(&kmer_hash(w)) {
                for &i in positions {
                    if j >= i {
                        let d = j - i;
                        if d <= max_offset
                            // Verify to guard against hash collisions.
                            && shorter[i..i + WORD_SIZE]
                                .iter()
                                .zip(&longer[j..j + WORD_SIZE])
                                .all(|(a, b)| a.eq_ignore_ascii_case(b))
                        {
                            candidates.insert(d);
                        }
                    }
                }
            }
        }
    }

    // ── Phase 2: extend ──────────────────────────────────────────────────────
    // Score each candidate diagonal; fall back to all diagonals when no seeds
    // were found (short sequences or no k-mer overlap).
    let score_offset = |off: usize| -> (usize, usize) {
        let count = shorter
            .iter()
            .zip(&longer[off..off + shorter.len()])
            .filter(|(a, b)| a.eq_ignore_ascii_case(b))
            .count();
        (count, off)
    };

    let (best_count, best_off) = if candidates.is_empty() {
        (0..=max_offset).map(score_offset).max_by_key(|&(c, _)| c)
    } else {
        candidates
            .into_iter()
            .map(score_offset)
            .max_by_key(|&(c, _)| c)
    }
    .unwrap_or((0, 0));

    let identity = best_count as f32 / shorter.len() as f32 * 100.0;
    let offset = if swapped {
        -(best_off as isize)
    } else {
        best_off as isize
    };
    (identity, offset)
}

fn scan_window(
    center: usize,
    left: usize,
    right: usize,
    peak_locs: &[u16],
) -> Option<(u16, u16)> {
    let base_start = center.checked_sub(left)?;
    let base_end = center + right;
    if base_end >= peak_locs.len() {
        return None;
    }
    let start_scan = peak_locs[base_start];
    let end_scan = peak_locs[base_end];
    if start_scan >= end_scan {
        return None;
    }
    Some((start_scan, end_scan))
}

/// Tries the edited basecalls (PBAS tag 2) first, falling back to raw basecalls (PBAS tag 1).
pub fn parse_ab1_sequence(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 34 || &data[0..4] != b"ABIF" {
        return None;
    }

    // Root directory entry sits at byte 6 (28 bytes long).
    // num_elements (i32 BE) at root+12 = byte 18
    // data_offset  (i32 BE) at root+20 = byte 26
    let dir_count = i32::from_be_bytes(data[18..22].try_into().ok()?) as usize;
    let dir_offset = i32::from_be_bytes(data[26..30].try_into().ok()?) as usize;

    let mut pbas1: Option<Vec<u8>> = None;

    for i in 0..dir_count {
        let e = dir_offset + i * 28;
        if e + 28 > data.len() {
            break;
        }
        let tag_name = &data[e..e + 4];
        let tag_number = i32::from_be_bytes(data[e + 4..e + 8].try_into().ok()?);
        // num_elements at e+12, data_size at e+16, data_offset at e+20
        let num_elems = i32::from_be_bytes(data[e + 12..e + 16].try_into().ok()?) as usize;
        let data_size = i32::from_be_bytes(data[e + 16..e + 20].try_into().ok()?) as usize;
        let data_off = i32::from_be_bytes(data[e + 20..e + 24].try_into().ok()?) as usize;

        if tag_name == b"PBAS" {
            // When data fits in 4 bytes it is stored inline at the data_offset field position
            let offset = if data_size <= 4 { e + 20 } else { data_off };
            if offset + num_elems <= data.len() {
                let seq = data[offset..offset + num_elems].to_vec();
                if tag_number == 2 {
                    return Some(seq); // edited basecalls — best quality
                } else if tag_number == 1 {
                    pbas1 = Some(seq); // raw basecalls — keep as fallback
                }
            }
        }
    }

    pbas1
}

/// Tries edited quality scores (PCON tag 2) first, falling back to raw (PCON tag 1).
/// Each byte is a Phred quality score corresponding to the base at the same index in PBAS.
pub fn parse_ab1_quality(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 34 || &data[0..4] != b"ABIF" {
        return None;
    }

    let dir_count = i32::from_be_bytes(data[18..22].try_into().ok()?) as usize;
    let dir_offset = i32::from_be_bytes(data[26..30].try_into().ok()?) as usize;

    let mut pcon1: Option<Vec<u8>> = None;

    for i in 0..dir_count {
        let e = dir_offset + i * 28;
        if e + 28 > data.len() {
            break;
        }
        let tag_name = &data[e..e + 4];
        let tag_number = i32::from_be_bytes(data[e + 4..e + 8].try_into().ok()?);
        let num_elems = i32::from_be_bytes(data[e + 12..e + 16].try_into().ok()?) as usize;
        let data_size = i32::from_be_bytes(data[e + 16..e + 20].try_into().ok()?) as usize;
        let data_off = i32::from_be_bytes(data[e + 20..e + 24].try_into().ok()?) as usize;

        if tag_name == b"PCON" {
            let offset = if data_size <= 4 { e + 20 } else { data_off };
            if offset + num_elems <= data.len() {
                let qual = data[offset..offset + num_elems].to_vec();
                if tag_number == 2 {
                    return Some(qual); // edited quality — best
                } else if tag_number == 1 {
                    pcon1 = Some(qual); // raw quality — keep as fallback
                }
            }
        }
    }

    pcon1
}

impl Ab1Channels {
    /// Parse an AB1 chromatogram from raw file bytes.
    ///
    /// Returns `None` if the data is not a valid ABIF file or required tags are missing.
    /// Prefers edited/analyzed data (PBAS 2, PLOC 2, DATA 9–12) over raw (PBAS 1, PLOC 1, DATA 1–4).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 34 || &data[0..4] != b"ABIF" {
            return None;
        }

        let dir_count = i32::from_be_bytes(data[18..22].try_into().ok()?) as usize;
        let dir_offset = i32::from_be_bytes(data[26..30].try_into().ok()?) as usize;

        // Collect all tag entries we care about
        let mut data_tags: std::collections::HashMap<i32, Vec<i16>> =
            std::collections::HashMap::new();
        let mut pbas1: Option<Vec<u8>> = None;
        let mut pbas2: Option<Vec<u8>> = None;
        let mut ploc1: Option<Vec<u16>> = None;
        let mut ploc2: Option<Vec<u16>> = None;
        let mut fwo: Option<[u8; 4]> = None;

        for i in 0..dir_count {
            let e = dir_offset + i * 28;
            if e + 28 > data.len() {
                break;
            }
            let tag_name = &data[e..e + 4];
            let tag_number = i32::from_be_bytes(data[e + 4..e + 8].try_into().ok()?);
            let num_elems = i32::from_be_bytes(data[e + 12..e + 16].try_into().ok()?) as usize;
            let data_size = i32::from_be_bytes(data[e + 16..e + 20].try_into().ok()?) as usize;
            let data_off = i32::from_be_bytes(data[e + 20..e + 24].try_into().ok()?) as usize;

            let offset = if data_size <= 4 { e + 20 } else { data_off };

            if tag_name == b"DATA" && (1..=12).contains(&tag_number) {
                // Each element is an i16 BE (2 bytes)
                if offset + num_elems * 2 <= data.len() {
                    let values: Vec<i16> = (0..num_elems)
                        .map(|j| {
                            i16::from_be_bytes([data[offset + j * 2], data[offset + j * 2 + 1]])
                        })
                        .collect();
                    data_tags.insert(tag_number, values);
                }
            } else if tag_name == b"PBAS" {
                if offset + num_elems <= data.len() {
                    let seq = data[offset..offset + num_elems].to_vec();
                    match tag_number {
                        2 => pbas2 = Some(seq),
                        1 => pbas1 = Some(seq),
                        _ => {}
                    }
                }
            } else if tag_name == b"PLOC" {
                // i16 BE peak scan positions
                if offset + num_elems * 2 <= data.len() {
                    let locs: Vec<u16> = (0..num_elems)
                        .map(|j| {
                            u16::from_be_bytes([data[offset + j * 2], data[offset + j * 2 + 1]])
                        })
                        .collect();
                    match tag_number {
                        2 => ploc2 = Some(locs),
                        1 => ploc1 = Some(locs),
                        _ => {}
                    }
                }
            } else if tag_name == b"FWO_" && tag_number == 1 {
                // 4 bytes: base letter for each channel in order
                if offset + 4 <= data.len() {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&data[offset..offset + 4]);
                    fwo = Some(arr);
                }
            }
        }

        // Prefer analyzed channels (9-12), fall back to raw (1-4)
        let channel_indices: [(i32, i32); 4] = [(9, 1), (10, 2), (11, 3), (12, 4)];
        let channels: [Vec<i16>; 4] = channel_indices.map(|(preferred, fallback)| {
            data_tags
                .remove(&preferred)
                .or_else(|| data_tags.remove(&fallback))
                .unwrap_or_default()
        });

        let bases = pbas2.or(pbas1)?;
        let peak_locs = ploc2.or(ploc1).unwrap_or_else(|| vec![0u16; bases.len()]);
        let base_order = fwo.unwrap_or(*b"ACGT");

        let erm41_view_state_opt = erm41::find_erm41_display_window(&bases, &peak_locs).map(
            |(start, end, is_reverse, pos28_base_idx)| Erm41ViewState {
                window: (start, end),
                is_reverse,
                pos28_base_idx,
            },
        );

        let rrl_ntm_view_state_opt = rrl::find_rrl_ntm_display_window(&bases, &peak_locs).map(
            |(start, end, is_reverse, snp_base_idx)| RrlNtmViewState {
                window: (start, end),
                is_reverse,
                snp_base_idx,
            },
        );

        Some(Self {
            channels,
            bases,
            peak_locs,
            base_order,
            erm41_view_state_opt,
            rrl_ntm_view_state_opt,
        })
    }
}

/// Chromatogram display parameters for the erm(41) region.
///
/// Built in [`Ab1Channels::parse`] via [`erm41::find_erm41_display_window`]
/// when [`ERM41_ANCHOR_L`] is found in the basecall sequence. Stored inside
/// [`Ab1Channels`] and used by the UI to scroll the chromatogram to the
/// diagnostic position 28 site.
#[derive(Clone, Copy, Debug)]
pub struct Erm41ViewState {
    /// Scan-index range (inclusive start, exclusive end) of the display window.
    pub window: (u16, u16),
    /// `true` when the reverse complement matched the anchor.
    pub is_reverse: bool,
    /// Index into `bases` / `peak_locs` that corresponds to position 28.
    pub pos28_base_idx: u16,
}

/// Chromatogram display parameters for the rrl / NTM macrolide-resistance region.
///
/// Built in [`Ab1Channels::parse`] via [`rrl::find_rrl_ntm_display_window`]
/// when [`RRL_ANCHOR_L`] is found in the basecall sequence. Stored inside
/// [`Ab1Channels`] and used by the UI to scroll the chromatogram to the
/// diagnostic SNP site (positions 2058–2059).
#[derive(Clone, Copy, Debug)]
pub struct RrlNtmViewState {
    /// Scan-index range (inclusive start, exclusive end) of the display window.
    pub window: (u16, u16),
    /// `true` when the reverse complement matched the anchor.
    pub is_reverse: bool,
    /// Index into `bases` / `peak_locs` that corresponds to the SNP site.
    pub snp_base_idx: u16,
}

/// Parsed channel intensity data from an AB1 chromatogram.
#[derive(Clone, Debug)]
pub struct Ab1Channels {
    /// Four intensity arrays in the order given by `base_order`.
    /// Each Vec has the same length (number of scans).
    pub channels: [Vec<i16>; 4],
    /// Called bases (from PBAS tag).
    pub bases: Vec<u8>,
    /// Scan index of each base call (from PLOC tag), same length as `bases`.
    pub peak_locs: Vec<u16>,
    /// Which base each channel corresponds to, e.g. b"ACGT" (from FWO_ tag).
    pub base_order: [u8; 4],
    /// Erm41 view state; `None` when the anchor was not found in the basecall sequence.
    pub erm41_view_state_opt: Option<Erm41ViewState>,
    /// Rrl/NTM view state; `None` when the anchor was not found in the basecall sequence.
    pub rrl_ntm_view_state_opt: Option<RrlNtmViewState>,
}

impl Ab1Channels {
    /// Return the channel index for a given base byte (A/C/G/T).
    pub fn channel_for_base(&self, base: u8) -> Option<usize> {
        self.base_order
            .iter()
            .position(|&b| b.eq_ignore_ascii_case(&base))
    }
}

/// Best-hit result from aligning an AB1 read against the reference sequences.
#[derive(Clone, Debug)]
pub struct SeqIdHit {
    /// Accession of the best-matching reference (e.g. "AF547836").
    pub accession: String,
    /// Species name stripped to genus + species (e.g. "Mycobacterium gastri").
    pub description: String,
    /// Percent identity of the best local alignment window (0.0–100.0).
    pub identity: f32,
    /// `true` when the reverse complement of the query was the better match.
    pub is_reverse: bool,
    /// Calls at each diagnostic kansasii/gastri SNP position.
    pub kansasii_gastri_snp_calls: Vec<KansasiiGastriSnpCall>,
    /// Calls at each diagnostic marinum/ulcerans SNP position.
    pub marinum_ulcerans_snp_calls: Vec<MarinumUlceransSnpCall>,
    /// Calls at each rrl macrolide-resistance SNP position (23S rRNA).
    pub rrl_snp_calls: Vec<RrlSnpCall>,
    /// Calls at each rrs aminoglycoside-resistance SNP position (16S rRNA).
    pub rrs_snp_calls: Vec<RrsSnpCall>,
    /// Calls at each erm(41) loss-of-function variant position.
    pub erm41_snp_calls: Vec<Erm41LofCall>,
    /// The aligned query (forward or reverse-complement, whichever scored best).
    pub aligned_query: Vec<u8>,
    /// Signed offset such that `query_index = ref_index - alignment_offset`.
    pub alignment_offset: isize,
    /// Erm41 position 28 call; `None` for non-erm41 targets.
    pub erm41_position_28_opt: Option<Erm41Position28>,
    /// rrl position 2058 2059 call; `None` for non-rrl targets.
    pub rrl_position_2058_2059_opt: Option<RrlPosition2058_2059>,
    /// Full reference sequence for this hit (used for pairwise display).
    pub ref_seq: Vec<u8>,
}

impl SeqIdHit {
    /// Format the alignment as a human-readable pairwise text (60-column wrapping).
    pub fn format_pairwise_alignment(&self) -> String {
        format_pairwise_alignment(
            &self.accession,
            &self.description,
            self.identity,
            self.is_reverse,
            &self.aligned_query,
            &self.ref_seq,
            self.alignment_offset,
        )
    }

    pub fn is_kansasii(&self) -> bool {
        self.accession == ACC_KANSASII
    }
    pub fn is_gastri(&self) -> bool {
        self.accession == ACC_GASTRI
    }
    pub fn is_marinum(&self) -> bool {
        self.accession == ACC_MARINUM
    }
    pub fn is_ulcerans(&self) -> bool {
        self.accession == ACC_ULCERANS
    }
    pub fn kansasii_gastri_snp_species_call(&self) -> Option<&'static str> {
        let gastri = self
            .kansasii_gastri_snp_calls
            .iter()
            .filter(|c| c.is_gastri())
            .count();
        let kansasii = self
            .kansasii_gastri_snp_calls
            .iter()
            .filter(|c| c.is_kansasii())
            .count();
        match gastri.cmp(&kansasii) {
            std::cmp::Ordering::Greater => Some("M. gastri"),
            std::cmp::Ordering::Less => Some("M. kansasii"),
            std::cmp::Ordering::Equal => None,
        }
    }
    pub fn marinum_ulcerans_snp_species_call(&self) -> Option<&'static str> {
        let marinum = self
            .marinum_ulcerans_snp_calls
            .iter()
            .filter(|c| c.is_marinum())
            .count();
        let ulcerans = self
            .marinum_ulcerans_snp_calls
            .iter()
            .filter(|c| c.is_ulcerans())
            .count();
        match marinum.cmp(&ulcerans) {
            std::cmp::Ordering::Greater => Some("M. marinum"),
            std::cmp::Ordering::Less => Some("M. ulcerans"),
            std::cmp::Ordering::Equal => None,
        }
    }
}


/// Top-level result for a processed AB1 read.
///
/// Owns the raw chromatogram and read-quality statistics, plus all
/// [`SeqIdHit`] entries produced by aligning the read against the reference
/// database. Each [`SeqIdHit`] carries the species identification and all
/// downstream SNP / resistance calls for one reference match.
#[derive(Clone, Debug)]
pub struct SeqData {
    pub chromatogram_opt: Option<Ab1Channels>,
    pub seq_id_hits: Vec<SeqIdHit>,
    pub length: usize,
    pub trimmed_length: usize,
    pub trimmed_avg_quality_opt: Option<f32>,
}

// ── PDF report ───────────────────────────────────────────────────────────────

const PDF_PAGE_W: f32 = 297.0; // A4 landscape mm
const PDF_PAGE_H: f32 = 210.0;
const PDF_MARGIN_L: f32 = 10.0;
const PDF_MARGIN_B: f32 = 12.0;
const PDF_MARGIN_T: f32 = 8.0;
const PDF_ROW_H: f32 = 5.5;

// Column x-offsets from PDF_MARGIN_L (mm)
const PDF_COL_X: [f32; 8] = [0.0, 28.0, 43.0, 103.0, 120.0, 143.0, 208.0, 233.0];
const PDF_TABLE_W: f32 = 270.0; // right edge of last column relative to PDF_MARGIN_L
const PDF_COL_HEADERS: [&str; 8] = [
    "Sample ID", "Gene", "Species", "Identity", "Susceptible", "Calls", "Date", "Filename",
];

/// Build a landscape A4 PDF report from AB1 scan records. Filtered to gene-identified
/// records with identity ≥ `MIN_SEQ_ID_IDENTITY`, same as the CSV output.
pub fn build_report_pdf(records: &[batch::SampleSusceptibilityRecord]) -> Vec<u8> {
    use printpdf::*;

    let filtered: Vec<&batch::SampleSusceptibilityRecord> = records
        .iter()
        .filter(|r| r.gene.is_some() && r.identity.is_some_and(|i| i >= MIN_SEQ_ID_IDENTITY))
        .collect();

    let (doc, page1, layer1) = PdfDocument::new(
        "AB1 Susceptibility Report",
        Mm(PDF_PAGE_W),
        Mm(PDF_PAGE_H),
        "Layer 1",
    );

    let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).unwrap();

    let mut layer = doc.get_page(page1).get_layer(layer1);
    let title_y = PDF_PAGE_H - PDF_MARGIN_T - 2.0;
    let mut y = title_y - PDF_ROW_H * 1.5;

    layer.use_text(
        format!(
            "AB1 Susceptibility Report  -  {}  ({} records)",
            pdf_current_date(),
            filtered.len()
        ),
        10.0_f32,
        Mm(PDF_MARGIN_L),
        Mm(title_y),
        &font_bold,
    );

    pdf_hline(&layer, y + 4.0);
    pdf_write_row(&layer, &font_bold, 7.5_f32, y, &PDF_COL_HEADERS);
    y -= PDF_ROW_H;
    pdf_hline(&layer, y + 4.0);

    let mut layer_n = 2usize;

    for rec in &filtered {
        if y < PDF_MARGIN_B {
            let (new_page, new_layer) =
                doc.add_page(Mm(PDF_PAGE_W), Mm(PDF_PAGE_H), format!("Layer {layer_n}"));
            layer_n += 1;
            layer = doc.get_page(new_page).get_layer(new_layer);
            y = PDF_PAGE_H - PDF_MARGIN_T - PDF_ROW_H * 1.5;
            pdf_hline(&layer, y + 4.0);
            pdf_write_row(&layer, &font_bold, 7.5_f32, y, &PDF_COL_HEADERS);
            y -= PDF_ROW_H;
            pdf_hline(&layer, y + 4.0);
        }

        let species = rec.species.as_deref().unwrap_or("");
        let species_trunc = pdf_truncate(species, 28);
        let date = rec.file_created.map(pdf_system_time_to_date).unwrap_or_default();
        let identity = rec.identity.map(|i| format!("{:.1}%", i)).unwrap_or_default();
        let calls_str = rec.susceptibility_calls.to_string();
        let calls_trunc = pdf_truncate(&calls_str, 50);
        let fname_trunc = pdf_truncate(&rec.file_name, 26);

        let cells: [&str; 8] = [
            rec.sample_id.as_str(),
            rec.gene.as_deref().unwrap_or(""),
            &species_trunc,
            &identity,
            pdf_sus(rec.is_susceptible),
            &calls_trunc,
            &date,
            &fname_trunc,
        ];
        pdf_write_row(&layer, &font, 7.0_f32, y, &cells);
        y -= PDF_ROW_H;
        pdf_hline(&layer, y + 4.0);
    }

    doc.save_to_bytes().unwrap_or_default()
}

fn pdf_write_row(
    layer: &printpdf::PdfLayerReference,
    font: &printpdf::IndirectFontRef,
    size: f32,
    y: f32,
    cells: &[&str],
) {
    use printpdf::Mm;
    for (i, text) in cells.iter().enumerate() {
        layer.use_text(*text, size, Mm(PDF_MARGIN_L + PDF_COL_X[i]), Mm(y), font);
    }
}

fn pdf_sus(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "S",
        Some(false) => "R",
        None => "",
    }
}

fn pdf_hline(layer: &printpdf::PdfLayerReference, y: f32) {
    use printpdf::{Color, Greyscale, Line, Mm, Point};
    layer.set_outline_color(Color::Greyscale(Greyscale::new(0.5, None)));
    layer.set_outline_thickness(0.3_f32);
    layer.add_line(Line::from_iter(vec![
        (Point::new(Mm(PDF_MARGIN_L), Mm(y)), false),
        (Point::new(Mm(PDF_MARGIN_L + PDF_TABLE_W), Mm(y)), false),
    ]));
}

fn pdf_truncate(s: &str, max_chars: usize) -> String {
    if s.len() <= max_chars {
        s.to_string()
    } else {
        format!("{}..", &s[..max_chars])
    }
}

fn pdf_current_date() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, m, d) = pdf_days_to_ymd((secs / 86400) as u32);
    format!("{y:04}-{m:02}-{d:02}")
}

fn pdf_system_time_to_date(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, m, d) = pdf_days_to_ymd((secs / 86400) as u32);
    format!("{y:04}-{m:02}-{d:02}")
}

fn pdf_days_to_ymd(days: u32) -> (u32, u32, u32) {
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
