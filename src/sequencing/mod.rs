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
pub mod pnca;
pub mod rpob;
pub mod rrl;
pub mod rrs;
pub mod rrs3end;
pub mod serde_helpers;
pub mod tb_data;

pub use batch::SampleSusceptibilityRecord;

use serde::{Deserialize, Serialize};

use erm41::{Erm41LofCall, Erm41Position28, Erm41SusceptibilityCalls};
use hsp65::{KansasiiGastriSnpCall, MarinumUlceransSnpCall};
use pnca::{PncaSnpCall, PncaSusceptibilityCalls};
use rrl::{RrlPosition2058_2059, RrlSnpCall, RrlSusceptibilityCalls};
use rrs::{RrsSnpCall, RrsSusceptibilityCalls};
use rrs3end::{Rrs3EndPosition1248, RrsSnpCall3End, RrsSusceptibilityCalls3End};

pub const MIN_SEQ_ID_IDENTITY: f32 = 80.0;

/// Sliding-window size (aligned columns) for [`trim_alignment_ends`].
const ALIGN_TRIM_WINDOW: usize = 15;
/// Minimum per-window match rate for [`trim_alignment_ends`] to accept a window as
/// well-supported. Deliberately looser than `MIN_SEQ_ID_IDENTITY`, which is the final
/// whole-alignment reportability gate, not a per-window trim threshold — trimming should
/// only shave off genuinely bad ends, not chase the reportability bar.
const ALIGN_TRIM_MIN_IDENTITY: f32 = 70.0;

const MIN_RRS_REF_LEN: usize = 1200;
const MIN_RRL_REF_LEN: usize = 1200;
const MIN_RPOB_REF_LEN: usize = 400;
const MIN_PNCA_REF_LEN: usize = 500;

pub const DESC_ABSCESSUS: &str = "M. abscessus subsp. abscessus";
pub const DESC_BOLLETII: &str = "M. abscessus subsp. bolletii";
pub const DESC_MASSILIENSE: &str = "M. abscessus subsp. massiliense";

const ERM41_FWD_START: &[u8] = b"gtgtccggccaacggtcgcg";
const ERM41_FWD_END: &[u8] = b"tggtgatcaggcggcgctga";
const ERM41_ANCHOR_L: &[u8] = b"GCCAACGGTCGCGACGCCAG";
const ERM41_ANCHOR_R: &[u8] = b"GGGGCTGGTATCCGCTCACT";

const RRS3END_ANCHOR_L: &[u8] = b"ACATGCTACAATGGCCGGT";
const RRS3END_ANCHOR_R: &[u8] = b"CAAAGGGCTGCGATGCCGCG";

const RRL_ANCHOR_L: &[u8] = b"CGTTACGCGCGGCAGGACGA";
const RRL_ANCHOR_R: &[u8] = b"AGACCCCGGGACCTTCACTA";

const PNCA_FWD_START: &[u8] = b"GCGTCGGTAGGCAAACTGCC";
const PNCA_FWD_END: &[u8] = b"AGTTGGTTTGCAGCTCCTGA";

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
/// pncA CDS + 50bp upstream promoter flank for each M. tuberculosis complex member with a
/// distinct reference sequence, fetched from NCBI at build time (see `pnca` module docs).
/// Concatenated into one multi-FASTA so `identify_sequence_pnca()` can search all of them via
/// [`parse_multi_fasta`], the same way `identify_sequence_rrl_ntm()` searches `REF_MYCO_RRL`.
const REF_PNCA: &str = concat!(
    include_str!("../../res/sequences/pnca/pnca_h37rv.fasta"),
    include_str!("../../res/sequences/pnca/pnca_bovis_AF2122_97.fasta"),
    include_str!("../../res/sequences/pnca/pnca_canettii_CIPT_140010059.fasta"),
);

/// Susceptibility calls derived from AB1 capillary sequencing, keyed by gene target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SusceptibilityCalls {
    pub erm41: Erm41SusceptibilityCalls,
    pub rrl: RrlSusceptibilityCalls,
    pub rrs: RrsSusceptibilityCalls,
    pub rrs3end: RrsSusceptibilityCalls3End,
    pub pnca: PncaSusceptibilityCalls,
}

impl std::fmt::Display for SusceptibilityCalls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = Vec::new();

        let mut erm: Vec<String> = Vec::new();
        if let Some(pos) = &self.erm41.position_28 {
            erm.push(pos.to_string());
        }
        for c in &self.erm41.lof_snp_calls {
            let tag = c.call_tag();
            if !tag.is_empty() {
                erm.push(tag);
            }
        }
        if !erm.is_empty() {
            parts.push(erm.join(", ").to_string());
        }

        let mut rrl: Vec<String> = Vec::new();
        if let Some(pos) = &self.rrl.position_2058_2059 {
            rrl.push(pos.to_string());
        }
        for c in &self.rrl.snp_calls {
            rrl.push(c.call_tag());
        }
        if !rrl.is_empty() {
            parts.push(rrl.join(", ").to_string());
        }

        let rrs: Vec<String> = self
            .rrs
            .snp_calls
            .iter()
            .map(|c| c.call_tag())
            .filter(|t| !t.is_empty())
            .collect();
        if !rrs.is_empty() {
            parts.push(rrs.join(", ").to_string());
        }

        let mut rrs3end: Vec<String> = Vec::new();
        if let Some(pos) = &self.rrs3end.position_1248 {
            rrs3end.push(pos.to_string());
        }
        for c in &self.rrs3end.snp_calls {
            let tag = c.call_tag();
            if !tag.is_empty() {
                rrs3end.push(tag);
            }
        }
        if !rrs3end.is_empty() {
            parts.push(rrs3end.join(", ").to_string());
        }

        let pnca: Vec<String> = self
            .pnca
            .snp_calls
            .iter()
            .filter(|c| !c.call_tag().is_empty())
            .map(|c| format!("{} {}", c.site_label(), c.call_tag()))
            .collect();
        if !pnca.is_empty() {
            parts.push(pnca.join(", ").to_string());
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

/// Trim a basecall sequence to the amplicon region defined by a primer pair.
///
/// Searches `seq` for `fwd_start` (forward primer) and `fwd_end` (reverse primer) using
/// case-insensitive matching. Both orientations are tried: if the read is reverse-complemented,
/// `rc(fwd_end)` anchors the left boundary and `rc(fwd_start)` anchors the right. The returned
/// slice starts at the earliest primer match and ends just after the latest, so both primers are
/// included. If a boundary primer is not found, the corresponding end of `seq` is used as a
/// fallback, leaving that side untrimmed.
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

/// Trim leading and trailing low-quality bases using a sliding-window average.
///
/// Scans inward from each end with a window of [`WINDOW`] bases; the first
/// window position (from each end) whose mean Phred quality ≥ `min_q` defines
/// the trim boundary. Falls back to single-base scan when `seq` is shorter
/// than the window. Returns `None` when no region meets the threshold.
pub fn trim_to_min_quality<'a>(seq: &'a [u8], qual: &[u8], min_q: u8) -> Option<&'a [u8]> {
    const WINDOW: usize = 15;

    let n = seq.len().min(qual.len());

    // Short read: single-base scan.
    if n < WINDOW {
        let start = (0..n).find(|&i| qual[i] >= min_q).unwrap_or(n);
        let end = (0..n)
            .rev()
            .find(|&i| qual[i] >= min_q)
            .map(|i| i + 1)
            .unwrap_or(0);
        return if start < end {
            Some(&seq[start..end])
        } else {
            None
        };
    }

    let threshold = min_q as u32 * WINDOW as u32;

    // Scan left → right: first window whose average ≥ min_q.
    let start = (0..=(n - WINDOW))
        .find(|&i| qual[i..i + WINDOW].iter().map(|&q| q as u32).sum::<u32>() >= threshold)
        .unwrap_or(n);

    // Scan right → left: last window-end whose average ≥ min_q.
    let end = (WINDOW..=n)
        .rev()
        .find(|&e| qual[e - WINDOW..e].iter().map(|&q| q as u32).sum::<u32>() >= threshold)
        .unwrap_or(0);

    if start < end {
        Some(&seq[start..end])
    } else {
        None
    }
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
            // NCBI deflines for M. tuberculosis complex subspecies and other infrasubspecific
            // taxa spell the subspecies out as "variant bovis"/"subsp. bolletii" right after
            // the binomial (e.g. "Mycobacterium tuberculosis variant bovis AF2122/97 ...",
            // "Mycobacterium avium subsp. paratuberculosis ..."). Without this, every such
            // entry collapses to the same genus+species description as its parent species —
            // e.g. the bovis pncA reference showing up indistinguishably as "Mycobacterium
            // tuberculosis", same as H37Rv — so fold the qualifier + its epithet in too.
            let mut qualifier_words = words.next().unwrap_or("").split_whitespace();
            if let Some(qualifier @ ("variant" | "subsp." | "subspecies")) = qualifier_words.next()
                && let Some(epithet) = qualifier_words.next()
            {
                cur_desc = format!("{cur_desc} {qualifier} {epithet}");
            }
        } else {
            cur_seq.extend(line.bytes().filter(|b| b.is_ascii_alphabetic()));
        }
    }
    if !cur_acc.is_empty() {
        result.push((cur_acc, cur_desc, cur_seq));
    }
    result
}

/// Within each `description` group, remove entries whose sequence (uppercased) is a contiguous
/// substring of a longer entry that shares the same description. Longer entries survive; the
/// shorter entries are redundant for alignment purposes because the aligner will find the same
/// best position inside the longer reference.
fn dedup_substring_same_desc(
    mut entries: Vec<(String, String, Vec<u8>)>,
) -> Vec<(String, String, Vec<u8>)> {
    // Sort longest-first so inner loop only has to check shorter against longer.
    entries.sort_by_key(|(_, _, s)| std::cmp::Reverse(s.len()));
    let upper: Vec<Vec<u8>> = entries
        .iter()
        .map(|(_, _, s)| s.iter().map(|b| b.to_ascii_uppercase()).collect())
        .collect();
    let mut keep = vec![true; entries.len()];
    for i in 0..entries.len() {
        if !keep[i] {
            continue;
        }
        for j in (i + 1)..entries.len() {
            if !keep[j] {
                continue;
            }
            if entries[i].1 == entries[j].1
                && upper[i].windows(upper[j].len()).any(|w| w == upper[j])
            {
                keep[j] = false;
            }
        }
    }
    entries
        .into_iter()
        .zip(keep)
        .filter_map(|(e, k)| k.then_some(e))
        .collect()
}

/// Renders a [`GappedAlignment`] as a human-readable pairwise alignment listing (BLAST-style),
/// wrapped at 60 columns per line with a `|`/`.`/` ` match line between query and reference.
fn format_pairwise_alignment(
    accession: &str,
    description: &str,
    identity: f32,
    is_reverse: bool,
    gapped_query: &[u8],
    gapped_ref: &[u8],
    ref_start: usize,
) -> String {
    let match_line: Vec<u8> = gapped_ref
        .iter()
        .zip(gapped_query.iter())
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
    let len = gapped_ref.len();
    let mut ref_pos = ref_start + 1;
    let mut query_pos = 1usize;
    for chunk_start in (0..len).step_by(line_width) {
        let chunk_end = (chunk_start + line_width).min(len);
        let ref_chunk = std::str::from_utf8(&gapped_ref[chunk_start..chunk_end]).unwrap_or("");
        let match_chunk = std::str::from_utf8(&match_line[chunk_start..chunk_end]).unwrap_or("");
        let query_chunk = std::str::from_utf8(&gapped_query[chunk_start..chunk_end]).unwrap_or("");

        out.push_str(&format!("Ref   {:5}: {}\n", ref_pos, ref_chunk));
        out.push_str(&format!("             {match_chunk}\n"));
        out.push_str(&format!("Query {:5}: {}\n\n", query_pos, query_chunk));

        ref_pos += ref_chunk.bytes().filter(|&b| b != b'-').count();
        query_pos += query_chunk.bytes().filter(|&b| b != b'-').count();
    }
    out
}

/// Alignment result from [`align_to_ref`]: gapped strings plus reference start position.
#[derive(Debug, Clone)]
pub struct GappedAlignment {
    /// Percent identity: matches / reference span × 100.
    pub identity: f32,
    /// Query sequence with `'-'` inserted at each deletion relative to the reference.
    pub gapped_query: Vec<u8>,
    /// Reference slice (aligned region only) with `'-'` inserted at each query insertion.
    /// Always the same length as `gapped_query`.
    pub gapped_ref: Vec<u8>,
    /// 0-based index into the full reference where this alignment starts.
    pub ref_start: usize,
}

/// Align `query` (Sanger read) against `reference` (gene sequence) using semiglobal
/// Smith-Waterman (free reference end-gaps, full query placed within reference).
///
/// Returns a [`GappedAlignment`] with gapped strings for display and SNP calling.
/// Identity is computed as `matches / reference_span × 100`, which naturally penalises
/// deletions in the query.
pub fn align_to_ref(query: &[u8], reference: &[u8]) -> GappedAlignment {
    use bio::alignment::AlignmentOperation::{Del, Ins, Match, Subst, Xclip, Yclip};
    use bio::alignment::pairwise::Aligner;

    if query.is_empty() || reference.is_empty() {
        return GappedAlignment {
            identity: 0.0,
            gapped_query: vec![],
            gapped_ref: vec![],
            ref_start: 0,
        };
    }

    let score_fn = |a: u8, b: u8| -> i32 { if a.eq_ignore_ascii_case(&b) { 1 } else { -1 } };
    let mut aligner = Aligner::new(-5, -1, &score_fn);
    let alignment = aligner.semiglobal(query, reference);

    let mut gapped_query = Vec::new();
    let mut gapped_ref = Vec::new();
    let mut qi = alignment.xstart;
    let mut ri = alignment.ystart;

    for op in &alignment.operations {
        match op {
            Match | Subst => {
                gapped_query.push(query[qi]);
                gapped_ref.push(reference[ri]);
                qi += 1;
                ri += 1;
            }
            Del => {
                gapped_query.push(b'-');
                gapped_ref.push(reference[ri]);
                ri += 1;
            }
            Ins => {
                gapped_query.push(query[qi]);
                gapped_ref.push(b'-');
                qi += 1;
            }
            Xclip(k) => {
                qi += k;
            }
            Yclip(k) => {
                ri += k;
            }
        }
    }

    let ref_span = gapped_ref.iter().filter(|&&b| b != b'-').count();
    let matches = gapped_query
        .iter()
        .zip(gapped_ref.iter())
        .filter(|&(&q, &r)| q != b'-' && r != b'-' && q.eq_ignore_ascii_case(&r))
        .count();
    let identity = if ref_span > 0 {
        matches as f32 / ref_span as f32 * 100.0
    } else {
        0.0
    };

    GappedAlignment {
        identity,
        gapped_query,
        gapped_ref,
        ref_start: alignment.ystart,
    }
}

/// Trim leading and trailing low-identity columns from a gapped alignment.
///
/// `align_to_ref` forces the entire query into the alignment, so non-homologous read ends
/// that quality/primer trimming missed (a noisy-but-technically-passing tail, stray
/// off-target sequence) show up as mismatches/insertions at the ends. Two passes:
///
/// 1. Peel any run of pure query-insertion columns (`gapped_ref == '-'`) off both edges
///    unconditionally. Insertion columns never contribute to `ref_span`/`matches` — e.g. a
///    read that continues past the end of the true amplicon into vector/primer sequence —
///    so removing them can never change `identity`, but left alone they show up as a
///    prominent, misleading run of dashes in the alignment viewer under an unaffected
///    (possibly 100%) identity figure.
/// 2. Scan inward from each remaining edge with a window of [`ALIGN_TRIM_WINDOW`] aligned
///    columns — the first window (from each end) whose match rate ≥
///    [`ALIGN_TRIM_MIN_IDENTITY`] defines the trim boundary — mirroring
///    [`trim_to_min_quality`]'s sliding-window idiom but scored on match/mismatch per column
///    instead of Phred quality. A second insertion-peel pass then strips any residual pure
///    insertion columns the window's match-rate slack left sitting at the boundary.
///
/// `ref_start` and `identity` are recomputed for the retained slice.
///
/// Note: this trims purely by local match rate, with no awareness of where any
/// gene's diagnostic SNP positions fall — a genuine mutation sitting in a noisy edge region
/// could in principle be trimmed away along with the junk. Never returns an alignment with
/// lower identity than `ga`'s original identity; falls back to returning `ga` unchanged
/// whenever trimming would not help.
fn trim_alignment_ends(ga: GappedAlignment) -> GappedAlignment {
    let n = ga.gapped_query.len();
    if n == 0 {
        return ga;
    }

    let is_match = |i: usize| -> bool {
        let (q, r) = (ga.gapped_query[i], ga.gapped_ref[i]);
        q != b'-' && r != b'-' && q.eq_ignore_ascii_case(&r)
    };

    let mut lo = 0;
    let mut hi = n;
    while lo < hi && ga.gapped_ref[lo] == b'-' {
        lo += 1;
    }
    while hi > lo && ga.gapped_ref[hi - 1] == b'-' {
        hi -= 1;
    }
    if lo >= hi {
        return ga;
    }
    let window_n = hi - lo;

    let (mut start, mut end) = if window_n < ALIGN_TRIM_WINDOW {
        let start = (lo..hi).find(|&i| is_match(i));
        let end = (lo..hi).rev().find(|&i| is_match(i)).map(|i| i + 1);
        match (start, end) {
            (Some(s), Some(e)) if s < e => (s, e),
            _ => (lo, hi),
        }
    } else {
        let threshold = (ALIGN_TRIM_MIN_IDENTITY / 100.0 * ALIGN_TRIM_WINDOW as f32).round() as u32;

        let window_matches = |from: usize| -> u32 {
            (from..from + ALIGN_TRIM_WINDOW)
                .filter(|&i| is_match(i))
                .count() as u32
        };

        let start = (lo..=(hi - ALIGN_TRIM_WINDOW)).find(|&i| window_matches(i) >= threshold);
        let end = (lo + ALIGN_TRIM_WINDOW..=hi)
            .rev()
            .find(|&e| window_matches(e - ALIGN_TRIM_WINDOW) >= threshold);
        match (start, end) {
            (Some(s), Some(e)) if s < e => (s, e),
            _ => (lo, hi),
        }
    };

    while start < end && ga.gapped_ref[start] == b'-' {
        start += 1;
    }
    while end > start && ga.gapped_ref[end - 1] == b'-' {
        end -= 1;
    }

    if start == 0 && end == n {
        return ga;
    }

    let removed_prefix_ref_bases = ga.gapped_ref[..start]
        .iter()
        .filter(|&&b| b != b'-')
        .count();

    let trimmed_query = ga.gapped_query[start..end].to_vec();
    let trimmed_ref = ga.gapped_ref[start..end].to_vec();

    let ref_span = trimmed_ref.iter().filter(|&&b| b != b'-').count();
    let matches = trimmed_query
        .iter()
        .zip(trimmed_ref.iter())
        .filter(|&(&q, &r)| q != b'-' && r != b'-' && q.eq_ignore_ascii_case(&r))
        .count();
    let identity = if ref_span > 0 {
        matches as f32 / ref_span as f32 * 100.0
    } else {
        0.0
    };

    // Defensive safety net: the windowed heuristic only removes columns that fail a
    // minimum-match-rate window, which should not pull the average down, but guard
    // explicitly rather than rely on that holding in every rounding edge case.
    if identity < ga.identity {
        return ga;
    }

    GappedAlignment {
        identity,
        gapped_query: trimmed_query,
        gapped_ref: trimmed_ref,
        ref_start: ga.ref_start + removed_prefix_ref_bases,
    }
}

/// Return the query base at a given reference position, or `None` if the position is outside
/// the aligned region or the query has a deletion (`'-'`) there.
pub fn base_at_ref_pos(
    gapped_query: &[u8],
    gapped_ref: &[u8],
    ref_start: usize,
    ref_pos: usize,
) -> Option<u8> {
    if ref_pos < ref_start {
        return None;
    }
    let mut current = ref_start;
    for (&q, &r) in gapped_query.iter().zip(gapped_ref.iter()) {
        if r != b'-' {
            if current == ref_pos {
                return if q == b'-' {
                    None
                } else {
                    Some(q.to_ascii_uppercase())
                };
            }
            current += 1;
        }
    }
    None
}

/// Converts a base-index window (`center - left` .. `center + right`) to a scan-index (peak
/// position) window via `peak_locs`, for scrolling a chromatogram viewer to a diagnostic site.
/// Returns `None` if the window falls outside `peak_locs`, or (defensively) if the resulting
/// scan range is empty/inverted.
fn scan_window(center: usize, left: usize, right: usize, peak_locs: &[u16]) -> Option<(u16, u16)> {
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

        let rrs3end_view_state_opt = rrs3end::find_16s3end_display_window(&bases, &peak_locs).map(
            |(start, end, is_reverse, pos28_base_idx)| Rrs3EndViewState {
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
            rrs3end_view_state_opt,
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

/// Chromatogram display parameters for the 16S 3-End region.
///
/// Built in [`Ab1Channels::parse`] via [`rrs3end::find_16s3end_display_window`]
/// when [`RRS3END_ANCHOR_L`] is found in the basecall sequence. Stored inside
/// [`Ab1Channels`] and used by the UI to scroll the chromatogram to the
/// diagnostic position 1248 site.
#[derive(Clone, Copy, Debug)]
pub struct Rrs3EndViewState {
    /// Scan-index range (inclusive start, exclusive end) of the display window.
    pub window: (u16, u16),
    /// `true` when the reverse complement matched the anchor.
    pub is_reverse: bool,
    /// Index into `bases` / `peak_locs` that corresponds to position 1248.
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
    /// 16S 3-End marinum/ulcerans view state; `None` when the anchor was not found in the basecall sequence.
    pub rrs3end_view_state_opt: Option<Rrs3EndViewState>,
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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    /// Calls at each rrs aminoglycoside-resistance SNP position from the 16S 3' end amplicon
    /// (see [`rrs3end`]), populated instead of `rrs_snp_calls` for that target.
    pub rrs_snp_calls_3end: Vec<RrsSnpCall3End>,
    /// Calls at each erm(41) loss-of-function variant position.
    pub erm41_snp_calls: Vec<Erm41LofCall>,
    /// Calls at each pncA pyrazinamide-resistance nucleotide/codon position.
    pub pnca_snp_calls: Vec<PncaSnpCall>,
    /// Gapped query sequence (forward or RC, whichever scored best). `'-'` marks deletions.
    pub aligned_query: Vec<u8>,
    /// Gapped reference sequence for the aligned span. Same length as `aligned_query`.
    pub aligned_ref: Vec<u8>,
    /// 0-based position in the full reference where the alignment starts.
    pub ref_start: usize,
    /// Erm41 position 28 call; `None` for non-erm41 targets.
    pub erm41_position_28_opt: Option<Erm41Position28>,
    /// 16S 3'-End position 1248 call (marinum/ulcerans discrimination); `None` for non-rrs3end
    /// targets.
    pub rrs3end_position_1248_opt: Option<Rrs3EndPosition1248>,
    /// rrl position 2058/2059 call; `None` for non-rrl targets.
    pub rrl_position_2058_2059_opt: Option<RrlPosition2058_2059>,
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
            &self.aligned_ref,
            self.ref_start,
        )
    }

    /// Whether this hit's reference is the *M. kansasii* hsp65 accession.
    pub fn is_kansasii(&self) -> bool {
        self.accession == ACC_KANSASII
    }
    /// Whether this hit's reference is the *M. gastri* hsp65 accession.
    pub fn is_gastri(&self) -> bool {
        self.accession == ACC_GASTRI
    }
    /// Whether this hit's reference is the *M. marinum* hsp65 accession.
    pub fn is_marinum(&self) -> bool {
        self.accession == ACC_MARINUM
    }
    /// Whether this hit's reference is the *M. ulcerans* hsp65 accession.
    pub fn is_ulcerans(&self) -> bool {
        self.accession == ACC_ULCERANS
    }
    /// Majority vote across `kansasii_gastri_snp_calls`: whichever species more of the SNP
    /// calls agree with, or `None` on a tie (including no calls at all).
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
    /// Majority vote across `marinum_ulcerans_snp_calls`: whichever species more of the SNP
    /// calls agree with, or `None` on a tie (including no calls at all).
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
    /// Parsed chromatogram traces and basecalls; `None` if the file wasn't a valid AB1.
    pub chromatogram_opt: Option<Ab1Channels>,
    pub seq_id_hits: Vec<SeqIdHit>,
    /// Full basecall sequence length, before quality trimming.
    pub length: usize,
    /// Basecall sequence length after [`trim_to_min_quality`].
    pub trimmed_length: usize,
    /// Mean Phred quality of the trimmed region; `None` if quality scores weren't available.
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
const PDF_COL_X: [f32; 6] = [0.0, 24.0, 39.0, 110.0, 130.0, 200.0];
const PDF_TABLE_W: f32 = 270.0; // right edge of last column relative to PDF_MARGIN_L
const PDF_COL_HEADERS: [&str; 6] = [
    "Sample ID",
    "Gene",
    "Species",
    "Susceptible",
    "Calls",
    "Filename",
];

/// Build a landscape A4 PDF report from AB1 scan records. Filtered to gene-identified
/// records with identity ≥ `MIN_SEQ_ID_IDENTITY`, same as the CSV output, and to
/// samples no older than `report_max_age_days` (see `TBConfig::report_max_age_days`).
pub fn build_report_pdf(
    records: &[batch::SampleSusceptibilityRecord],
    report_max_age_days: u32,
) -> Vec<u8> {
    use printpdf::*;

    let max_age = std::time::Duration::from_secs(u64::from(report_max_age_days) * 24 * 60 * 60);
    let now = std::time::SystemTime::now();

    let filtered: Vec<&batch::SampleSusceptibilityRecord> = records
        .iter()
        .filter(|r| r.gene.is_some() && r.identity.is_some_and(|i| i >= MIN_SEQ_ID_IDENTITY))
        .filter(|r| {
            r.file_created
                .is_none_or(|created| now.duration_since(created).is_ok_and(|age| age <= max_age))
        })
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
        let species_trunc = pdf_truncate(species, 50);
        let calls_str = rec.susceptibility_calls.to_string();
        let calls_trunc = pdf_truncate(&calls_str, 50);
        let fname_trunc = pdf_truncate(&rec.file_name, 50);

        let cells: [&str; 6] = [
            rec.sample_id.as_str(),
            rec.gene.as_deref().unwrap_or(""),
            &species_trunc,
            pdf_sus(rec.is_susceptible),
            &calls_trunc,
            &fname_trunc,
        ];
        pdf_write_row(&layer, &font, 7.0_f32, y, &cells);
        y -= PDF_ROW_H;
        pdf_hline(&layer, y + 4.0);
    }

    doc.save_to_bytes().unwrap_or_default()
}

/// Draws one row of table cells at fixed column x-offsets ([`PDF_COL_X`]).
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

/// Renders a susceptibility verdict as a single-letter PDF table cell: `"S"`, `"R"`, or empty.
fn pdf_sus(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "S",
        Some(false) => "R",
        None => "",
    }
}

/// Draws a horizontal separator line spanning the table width at height `y`.
fn pdf_hline(layer: &printpdf::PdfLayerReference, y: f32) {
    use printpdf::{Color, Greyscale, Line, Mm, Point};
    layer.set_outline_color(Color::Greyscale(Greyscale::new(0.5, None)));
    layer.set_outline_thickness(0.3_f32);
    layer.add_line(Line::from_iter(vec![
        (Point::new(Mm(PDF_MARGIN_L), Mm(y)), false),
        (Point::new(Mm(PDF_MARGIN_L + PDF_TABLE_W), Mm(y)), false),
    ]));
}

/// Truncates `s` to `max_chars` bytes, appending `".."` if it was cut. Byte-based, not
/// char-aware — table cell contents here are ASCII (species names, filenames, call tags).
fn pdf_truncate(s: &str, max_chars: usize) -> String {
    if s.len() <= max_chars {
        s.to_string()
    } else {
        format!("{}..", &s[..max_chars])
    }
}

/// Today's date as `YYYY-MM-DD`, for the report header.
fn pdf_current_date() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, m, d) = pdf_days_to_ymd((secs / 86400) as u32);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Converts days since the Unix epoch (1970-01-01) to a proleptic Gregorian `(year, month,
/// day)`, ignoring leap seconds, via the standard Julian Day Number algorithm. Duplicates
/// `batch::days_to_ymd` rather than sharing it, since that one is private to `batch`.
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

#[cfg(test)]
mod tests {
    use super::{
        GappedAlignment, align_to_ref, base_at_ref_pos, parse_multi_fasta, trim_alignment_ends,
    };

    #[test]
    fn test_trim_alignment_ends_strips_unmatched_insertion_tail() {
        // A read that continues past the end of the true amplicon (e.g. into vector/primer
        // sequence) aligns as a pure insertion tail (`gapped_ref == '-'`), which never lowers
        // `identity` (matches / ref_span excludes insertion columns) even though it's a
        // visibly unaligned run of dashes in the alignment viewer.
        let refseq: Vec<u8> = b"ACGTACGTACGTACGTACGTACGTACGTAC".to_vec();
        let mut query = refseq.clone();
        query.extend(b"TTTTTTTTTTTTTTTTTTTT");
        let ga = align_to_ref(&query, &refseq);
        assert!((ga.identity - 100.0).abs() < f32::EPSILON); // already 100% before trimming
        assert_eq!(ga.gapped_query.len(), 50);

        let trimmed = trim_alignment_ends(ga);

        assert_eq!(trimmed.gapped_query, refseq);
        assert_eq!(trimmed.gapped_ref, refseq);
        assert!(!trimmed.gapped_ref.contains(&b'-'));
        assert!((trimmed.identity - 100.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_parse_multi_fasta_distinguishes_infrasubspecific_descriptions() {
        // The bovis and H37Rv pncA references share a binomial name, differing only in the
        // "variant bovis" qualifier NCBI tucks into the defline after the species — without
        // surfacing it, both entries describe themselves identically as "Mycobacterium
        // tuberculosis" in the UI (see res/sequences/pnca/pnca_bovis_AF2122_97.fasta).
        let fasta = "\
>NC_000962.3:c2289291-2288681 Mycobacterium tuberculosis H37Rv, complete genome
ACGT
>NC_002945.4:c2277615-2277005 Mycobacterium tuberculosis variant bovis AF2122/97 chromosome, complete sequence
ACGT
>HM007606.1 Mycobacterium avium subsp. paratuberculosis strain DSM 44133 23S ribosomal RNA gene, partial sequence
ACGT
>NC_xxx:1-4 Mycobacterium abscessus rrl
ACGT
";
        let entries = parse_multi_fasta(fasta);
        let descs: Vec<&str> = entries.iter().map(|(_, d, _)| d.as_str()).collect();
        assert_eq!(
            descs,
            vec![
                "Mycobacterium tuberculosis",
                "Mycobacterium tuberculosis variant bovis",
                "Mycobacterium avium subsp. paratuberculosis",
                // ntm-db colon-accession entries keep their plain genus+species description —
                // the word after species here is the gene tag ("rrl"), not a qualifier, so the
                // RRL/RRS_RESISTANCE_SNPS lookups keyed on it (see rrl.rs, rrs.rs) still match.
                "Mycobacterium abscessus",
            ]
        );
    }

    /// Build a `GappedAlignment` from raw gapped strings, computing `identity` with the same
    /// `matches / ref_span * 100` formula `align_to_ref` uses.
    fn make_ga(gapped_query: &[u8], gapped_ref: &[u8], ref_start: usize) -> GappedAlignment {
        let ref_span = gapped_ref.iter().filter(|&&b| b != b'-').count();
        let matches = gapped_query
            .iter()
            .zip(gapped_ref.iter())
            .filter(|&(&q, &r)| q != b'-' && r != b'-' && q.eq_ignore_ascii_case(&r))
            .count();
        let identity = if ref_span > 0 {
            matches as f32 / ref_span as f32 * 100.0
        } else {
            0.0
        };
        GappedAlignment {
            identity,
            gapped_query: gapped_query.to_vec(),
            gapped_ref: gapped_ref.to_vec(),
            ref_start,
        }
    }

    #[test]
    fn test_trim_alignment_ends_junk_tail() {
        let query = [vec![b'A'; 20], vec![b'T'; 15]].concat();
        let refseq = vec![b'A'; 35];
        let ga = make_ga(&query, &refseq, 100);

        let trimmed = trim_alignment_ends(ga);

        assert_eq!(trimmed.gapped_query.len(), 24);
        assert_eq!(trimmed.gapped_ref.len(), 24);
        assert_eq!(trimmed.ref_start, 100); // nothing trimmed from the front
        assert!((trimmed.identity - 83.333_336).abs() < 0.01);
    }

    #[test]
    fn test_trim_alignment_ends_junk_head() {
        let query = [vec![b'T'; 15], vec![b'A'; 20]].concat();
        let refseq = vec![b'A'; 35];
        let ga = make_ga(&query, &refseq, 100);

        let trimmed = trim_alignment_ends(ga);

        assert_eq!(trimmed.gapped_query.len(), 24);
        assert_eq!(trimmed.gapped_ref.len(), 24);
        assert_eq!(trimmed.ref_start, 111); // 11 non-gap ref bases trimmed off the front
        assert!((trimmed.identity - 83.333_336).abs() < 0.01);
    }

    #[test]
    fn test_trim_alignment_ends_fully_clean_no_trim() {
        let seq = vec![b'A'; 30];
        let ga = make_ga(&seq, &seq, 50);

        let trimmed = trim_alignment_ends(ga);

        assert_eq!(trimmed.gapped_query, seq);
        assert_eq!(trimmed.gapped_ref, seq);
        assert_eq!(trimmed.ref_start, 50);
        assert!((trimmed.identity - 100.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_trim_alignment_ends_fully_junk_unchanged() {
        let query = vec![b'T'; 30];
        let refseq = vec![b'A'; 30];
        let ga = make_ga(&query, &refseq, 7);

        let trimmed = trim_alignment_ends(ga);

        assert_eq!(trimmed.gapped_query, query);
        assert_eq!(trimmed.gapped_ref, refseq);
        assert_eq!(trimmed.ref_start, 7);
        assert!((trimmed.identity - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_trim_alignment_ends_shorter_than_window_unchanged() {
        // n < ALIGN_TRIM_WINDOW exercises the short-alignment fallback path.
        let query = vec![b'T'; 5];
        let refseq = vec![b'A'; 5];
        let ga = make_ga(&query, &refseq, 3);

        let trimmed = trim_alignment_ends(ga);

        assert_eq!(trimmed.gapped_query, query);
        assert_eq!(trimmed.gapped_ref, refseq);
        assert_eq!(trimmed.ref_start, 3);
    }

    #[test]
    fn test_trim_alignment_ends_empty_no_panic() {
        let ga = make_ga(&[], &[], 0);
        let trimmed = trim_alignment_ends(ga);
        assert!(trimmed.gapped_query.is_empty());
        assert!(trimmed.gapped_ref.is_empty());
    }

    #[test]
    fn test_trim_alignment_ends_ref_start_excludes_insertions_in_removed_prefix() {
        // 15-column junk prefix containing one query-insertion column (gapped_ref == '-')
        // at index 5, followed by a 20-column clean matching core.
        let mut query = vec![b'T'; 15];
        let mut refseq = vec![b'A'; 15];
        query[5] = b'G';
        refseq[5] = b'-';
        query.extend(vec![b'A'; 20]);
        refseq.extend(vec![b'A'; 20]);
        let ga = make_ga(&query, &refseq, 200);

        let trimmed = trim_alignment_ends(ga);

        assert_eq!(trimmed.gapped_query.len(), 24);
        // 11 columns removed from the front, only 10 of which advance the reference
        // (index 5 is a query insertion and consumes no reference coordinate).
        assert_eq!(trimmed.ref_start, 210);
        assert_eq!(
            base_at_ref_pos(
                &trimmed.gapped_query,
                &trimmed.gapped_ref,
                trimmed.ref_start,
                trimmed.ref_start
            ),
            Some(trimmed.gapped_query[0].to_ascii_uppercase())
        );
    }

    #[test]
    fn test_trim_alignment_ends_never_decreases_identity() {
        let fixtures: Vec<GappedAlignment> = vec![
            make_ga(&[vec![b'A'; 20], vec![b'T'; 15]].concat(), &[b'A'; 35], 0),
            make_ga(&[vec![b'T'; 15], vec![b'A'; 20]].concat(), &[b'A'; 35], 0),
            make_ga(&[b'A'; 30], &[b'A'; 30], 0),
            make_ga(&[b'T'; 30], &[b'A'; 30], 0),
        ];
        for ga in fixtures {
            let original_identity = ga.identity;
            let trimmed = trim_alignment_ends(ga);
            assert!(trimmed.identity >= original_identity);
        }
    }
}
