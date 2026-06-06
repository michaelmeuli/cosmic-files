use super::reverse_complement;
use super::{
    RRL_ANCHOR_L,
    RRL_ANCHOR_R,
    RRL_FWD_END,
    RRL_FWD_START,
    REF_MYCO_RRL,
};
use super::{SeqIdHit, best_alignment, parse_multi_fasta};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// Maps a reference position to `(wt_base, alts)` where `alts` maps each resistance alt to
/// `(drugs, E.coli nomenclature)`.
type RrlSnpMap = BTreeMap<usize, (u8, BTreeMap<u8, (Vec<String>, String)>)>;


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RrlPosition2058_2059 {
    SusceptibleWildtype, // A2058 and A2059
    ResistanceConferringMutation, // Any mutation at 2058 or 2059 that is not wildtype.
    Undetermined,
}


impl RrlPosition2058_2059 {
    /// Returns `Some(true)` for wildtype (susceptible), `Some(false)` for a
    /// resistance-conferring mutation, and `None` when the call is undetermined.
    pub fn is_susceptible(&self) -> Option<bool> {
        match self {
            Self::SusceptibleWildtype => Some(true),
            Self::ResistanceConferringMutation => Some(false),
            Self::Undetermined => None,
        }
    }

    fn call_position_2058_2059(read: &[u8]) -> Option<(u8, u8)> {
        let anchor_len = RRL_ANCHOR_L.len();
        let hit = read
            .windows(anchor_len)
            .position(|w| w.eq_ignore_ascii_case(RRL_ANCHOR_L))?;
        let pos2058 = hit + anchor_len;
        let base2058 = read.get(pos2058).copied()?.to_ascii_uppercase();
        let pos2059 = pos2058 + 1;
        let base2059 = read.get(pos2059).copied()?.to_ascii_uppercase();
        let right_start = pos2059 + 1;
        let right_end = right_start + RRL_ANCHOR_R.len();
        if right_end > read.len() {
            return None;
        }
        let right_ok = read[right_start..right_end].eq_ignore_ascii_case(RRL_ANCHOR_R);
        if !right_ok {
            return None;
        }
        Some((base2058, base2059))
    }

    fn from_bases(bases: Option<(u8, u8)>) -> Option<Self> {
        match bases {
            Some((b'A', b'A')) => Some(Self::SusceptibleWildtype),
            Some((_, _)) => Some(Self::ResistanceConferringMutation),
            None => None,
        }
    }

    pub fn from_single_read(read: &[u8]) -> Self {
        if let Some(call) = Self::from_bases(Self::call_position_2058_2059(read)) {
            return call;
        }
        let rc = reverse_complement(read);
        Self::from_bases(Self::call_position_2058_2059(&rc)).unwrap_or(Self::Undetermined)
    }
}

/// Returns `Some(true)` for wildtype (susceptible), `Some(false)` for a resistance-conferring
/// mutation, and `None` when the call is undetermined.
///
/// If any `snp_calls` entry shows a resistance-conferring alt base, returns `Some(false)`
/// regardless of `pos`. Otherwise delegates to the position-based call.
pub fn is_susceptible_rrl(pos: &RrlPosition2058_2059, snp_calls: &[RrlSnpCall]) -> Option<bool> {
    let has_resistance = snp_calls
        .iter()
        .any(|c| c.query_base.is_some_and(|b| c.resistance_bases.contains_key(&b)));
    if has_resistance {
        Some(false)
    } else {
        pos.is_susceptible()
    }
}

/// Returns `Some(false)` if any observed SNP base is a resistance-conferring alt, or `None` if
/// no resistance alt is observed.
pub fn is_susceptible_rrl_by_snp_calls(snp_calls: &[RrlSnpCall]) -> Option<bool> {
    if snp_calls
        .iter()
        .any(|c| c.query_base.is_some_and(|b| c.resistance_bases.contains_key(&b)))
    {
        Some(false)
    } else {
        None
    }
}

/// Returns susceptibility based on position 2058/2059 alone, without considering SNP calls.
pub fn is_susceptible_rrl_by_position(pos: &RrlPosition2058_2059) -> Option<bool> {
    pos.is_susceptible()
}

/// All rrl susceptibility evidence for one sample, ready for UI display.
#[derive(Debug, Clone, Default)]
pub struct RrlSusceptibilityCalls {
    pub position_2058_2059: Option<RrlPosition2058_2059>,
    pub snp_calls: Vec<RrlSnpCall>,
    pub is_susceptible: Option<bool>,
}


#[derive(Debug, Deserialize, Clone)]
struct ResistanceVariant {
    #[serde(rename = "Gene")]
    gene: String,
    #[serde(rename = "Mutation")]
    mutation: String,
    #[serde(rename = "drug")]
    drug: String,
    #[serde(rename = "type")]
    confers: String,
    #[serde(rename = "E.coli-nomenclature", default)]
    ecoli_nomenclature: String,
}

fn parse_rrl_resistance_snps(csv: &str) -> RrlSnpMap {
    let mut rdr = csv::Reader::from_reader(csv.as_bytes());
    let mut map: RrlSnpMap = BTreeMap::new();
    for row in rdr.deserialize::<ResistanceVariant>() {
        let row = row.unwrap();
        if row.gene.trim() != "rrl" {
            continue;
        }
        if row.confers.trim() != "drug_resistance" {
            continue;
        }
        let drug = row.drug.trim().to_string();
        let ecoli = row.ecoli_nomenclature.trim().to_string();
        let m = row.mutation.trim();
        if let Some(rest) = m.strip_prefix("n.") {
            let digits_end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            if let Ok(pos1) = rest[..digits_end].parse::<usize>() {
                let after_pos = &rest[digits_end..];
                if let (Some(wt), Some(alt)) = (
                    after_pos.bytes().next(),
                    after_pos
                        .strip_prefix(|_: char| true)
                        .and_then(|s| s.strip_prefix('>'))
                        .and_then(|s| s.bytes().next()),
                ) {
                    let entry = map.entry(pos1 - 1).or_insert_with(|| (wt, BTreeMap::new()));
                    let variant = entry.1.entry(alt).or_insert_with(|| (Vec::new(), ecoli.clone()));
                    if !variant.0.contains(&drug) {
                        variant.0.push(drug);
                    }
                }
            }
        }
    }
    map
}

static RRL_RESISTANCE_SNPS: LazyLock<BTreeMap<&'static str, RrlSnpMap>> = LazyLock::new(|| {
    [
        ("Mycobacterium abscessus", include_str!("../../res/sequences/ntm-db/db/Mycobacterium_abscessus/variants.csv")),
        ("Mycobacterium avium",          include_str!("../../res/sequences/ntm-db/db/Mycobacterium_avium/variants.csv")),
        ("Mycobacterium fortuitum",      include_str!("../../res/sequences/ntm-db/db/Mycobacterium_fortuitum/variants.csv")),
        ("Mycobacterium intracellulare", include_str!("../../res/sequences/ntm-db/db/Mycobacterium_intracellulare/variants.csv")),
        ("Mycobacterium leprae",         include_str!("../../res/sequences/ntm-db/db/Mycobacterium_leprae/variants.csv")),
    ]
    .into_iter()
    .map(|(species, csv)| (species, parse_rrl_resistance_snps(csv)))
    .collect()
});


#[derive(Clone, Debug)]
pub struct RrlSnpCall {
    /// 0-based position in the rrl reference sequence.
    pub ref_pos: usize,
    /// Base observed in the query at this position, or `None` if not covered.
    pub query_base: Option<u8>,
    /// Wild-type base at this position.
    pub wt_base: u8,
    /// Maps each resistance-conferring alt base to `(drugs, E.coli nomenclature)`.
    pub resistance_bases: BTreeMap<u8, (Vec<String>, String)>,
}

impl RrlSnpCall {
    pub fn call_tag(&self) -> String {
        // E.coli position prefix shared by all alts at this position (e.g. "A2059").
        let ecoli_prefix: Option<&str> = self.resistance_bases.values()
            .next()
            .map(|(_, nom)| &nom[..nom.len().saturating_sub(1)]);

        match self.query_base {
            None => "NA".to_string(),
            Some(b) if b == self.wt_base => match ecoli_prefix {
                Some(p) => format!("{} (wt, E.coli {})", b as char, p),
                None    => format!("{} (wt)", b as char),
            },
            Some(b) if self.resistance_bases.contains_key(&b) => {
                let (drugs, ecoli) = &self.resistance_bases[&b];
                format!("{} ({}, E.coli {})", b as char, drugs.join(", "), ecoli)
            }
            Some(b) => match ecoli_prefix {
                Some(p) => format!("{} (mutation, E.coli {}{})", b as char, p, b as char),
                None    => format!("{} (mutation)", b as char),
            },
        }
    }
}

fn call_rrl_snps(
    snps: &RrlSnpMap,
    query: &[u8],
    alignment_offset: isize,
) -> Vec<RrlSnpCall> {
    snps.iter()
        .map(|(&ref_pos, (wt_base, alt_to_drugs))| {
            let query_pos = ref_pos as isize - alignment_offset;
            let query_base = if query_pos >= 0 && (query_pos as usize) < query.len() {
                Some(query[query_pos as usize].to_ascii_uppercase())
            } else {
                None
            };
            RrlSnpCall {
                ref_pos,
                query_base,
                wt_base: *wt_base,
                resistance_bases: alt_to_drugs.clone(),
            }
        })
        .collect()
}


/// Locate the SNP site in a Sanger read and return the scan-coordinate window
/// to display around it.
///
/// Returns `Some((start_scan, end_scan, is_reverse_complement, snp_base_idx))`
/// or `None` if the anchor sequence cannot be found or the window falls
/// outside the trace.
///
/// # How it works
///
/// The rrl SNP of interest sits at a fixed position relative to two flanking
/// anchor sequences (`RRL_ANCHOR_L` on the left, `RRL_ANCHOR_R` on the right).
/// The function tries both read orientations:
///
/// 1. **Forward** — searches `bases` for `RRL_ANCHOR_L`.  If found, the SNP
///    position is the base immediately after the anchor.  A display window of
///    9 bases to the left and 10 to the right is converted to scan coordinates
///    via [`super::scan_window`], and `is_reverse_complement` is set to
///    `false`.
///
/// 2. **Reverse-complement** — searches `bases` for the reverse complement of
///    `RRL_ANCHOR_R`.  If found, the SNP position is again the base
///    immediately after that match (which corresponds to the SNP on the
///    complementary strand).  The left/right margins are swapped (10 left, 9
///    right) so the displayed window covers the same biological region.
///    `is_reverse_complement` is set to `true`.
///
/// The forward orientation is tried first; the reverse-complement is only
/// attempted if the forward search fails.
pub(super) fn find_rrl_ntm_display_window(
    bases: &[u8],
    peak_locs: &[u16],
) -> Option<(u16, u16, bool, u16)> {
    const LEFT: usize = 9;
    const RIGHT: usize = 10;

    let anchor_len: u16 = RRL_ANCHOR_L.len() as u16;

    if let Some(hit) = bases
        .windows(anchor_len as usize)
        .position(|w| w.eq_ignore_ascii_case(RRL_ANCHOR_L))
    {
        let snp_pos = hit + anchor_len as usize;
        if let Some(window) = super::scan_window(snp_pos, LEFT, RIGHT, peak_locs) {
            return Some((window.0, window.1, false, snp_pos as u16));
        }
    }

    let rc_anchor_r: Vec<u8> = reverse_complement(RRL_ANCHOR_R);
    if let Some(hit) = bases
        .windows(rc_anchor_r.len())
        .position(|w| w.eq_ignore_ascii_case(&rc_anchor_r))
    {
        let snp_pos_comp = hit + rc_anchor_r.len();
        if let Some(window) = super::scan_window(snp_pos_comp, RIGHT, LEFT, peak_locs) {
            return Some((window.0, window.1, true, snp_pos_comp as u16));
        }
    }

    None
}

/// Database was generated by filtering NCBI Nucleotide for Mycobacteriaceae[Organism] AND (23S ribosomal RNA[Title] OR rrl[Gene Name]) AND 400:3000[SLEN] AND type_material[Filter] (via fetch_myco_sequences() in build.rs).  
/// Added to this database are the rrl sequences found in [ntm-db](https://github.com/pathogen-profiler/ntm-db) (via extract_ntm_db_sequences() in build.rs).  
pub fn identify_sequence_rrl_ntm(query: &[u8]) -> Vec<SeqIdHit> {
    let query = super::trim_start_end(query, RRL_FWD_START, RRL_FWD_END);
    let rc = reverse_complement(query);
    let rrl_position_2058_2059 = RrlPosition2058_2059::from_single_read(query);

    let mut hits: Vec<SeqIdHit> = parse_multi_fasta(REF_MYCO_RRL)
        .into_iter()
        .map(|(accession, description, refseq)| {
            let (fwd_id, fwd_off) = best_alignment(query, &refseq);
            let (rev_id, rev_off) = best_alignment(&rc, &refseq);
            let (identity, is_reverse, aligned_query, offset) = if rev_id > fwd_id {
                (rev_id, true, rc.as_slice(), rev_off)
            } else {
                (fwd_id, false, query, fwd_off)
            };
            let rrl_snp_calls = RRL_RESISTANCE_SNPS
                .get(description.as_str())
                .map(|snps| call_rrl_snps(snps, aligned_query, offset))
                .unwrap_or_default();
            SeqIdHit {
                accession,
                description,
                identity,
                is_reverse,
                kansasii_gastri_snp_calls: vec![],
                marinum_ulcerans_snp_calls: vec![],
                rrl_snp_calls,
                erm41_snp_calls: vec![],
                aligned_query: aligned_query.to_vec(),
                alignment_offset: offset,
                erm41_position_28_opt: None,
                rrl_position_2058_2059_opt: Some(rrl_position_2058_2059),
                ref_seq: refseq,
            }
        })
        .collect();

    hits.sort_by(|a, b| {
        b.identity
            .partial_cmp(&a.identity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hits
}
