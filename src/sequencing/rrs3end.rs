use super::{
    GappedAlignment, REF_MYCO_RRS, SeqIdHit, align_to_ref, base_at_ref_pos,
    dedup_substring_same_desc, parse_multi_fasta, reverse_complement,
    RRS3END_ANCHOR_L, RRS3END_ANCHOR_R,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// Maps a reference position to `(wt_base, alts)` where `alts` maps each resistance alt to
/// `(drugs, E.coli nomenclature)`.
type RrsSnpMap = BTreeMap<usize, (u8, BTreeMap<u8, (Vec<String>, String)>)>;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Rrs3EndPosition1248 {
    A1248,        // M. marinum
    G1248,         // M. ulcerans
    C1248,         
    T1248,         
    Undetermined, // Anchor not found in read
}

impl std::fmt::Display for Rrs3EndPosition1248 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A1248 => write!(f, "A1248 (M. marinum)"),
            Self::G1248 => write!(f, "G1248 (M. ulcerans)"),
            Self::C1248 => write!(f, "C1248"),
            Self::T1248 => write!(f, "T1248"),
            Self::Undetermined => write!(f, "Position 1248 not found"),
        }
    }
}

impl Rrs3EndPosition1248 {
    fn call_position_1248(read: &[u8]) -> Option<u8> {
        let anchor_len = RRS3END_ANCHOR_L.len();
        let hit = read
            .windows(anchor_len)
            .position(|w| w.eq_ignore_ascii_case(RRS3END_ANCHOR_L))?;
        let pos1248 = hit + anchor_len;
        let base = read.get(pos1248).copied()?.to_ascii_uppercase();
        let right_start = pos1248 + 1;
        let right_end = right_start + RRS3END_ANCHOR_R.len();
        if right_end > read.len() {
            return None;
        }
        let right_ok = read[right_start..right_end].eq_ignore_ascii_case(RRS3END_ANCHOR_R);
        if !right_ok {
            return None;
        }
        Some(base)
    }

    fn from_base(base: Option<u8>) -> Option<Self> {
        match base {
            Some(b'A') => Some(Self::A1248),
            Some(b'G') => Some(Self::G1248),
            Some(b'C') => Some(Self::C1248),
            Some(b'T') => Some(Self::T1248),
            _ => None,
        }
    }

    pub fn from_single_read(read: &[u8]) -> Option<Self> {
        if let Some(call) = Self::from_base(Self::call_position_1248(read)) {
            return Some(call);
        }
        let rc = reverse_complement(read);
        Self::from_base(Self::call_position_1248(&rc))
    }
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

fn parse_rrs_resistance_snps(csv: &str) -> RrsSnpMap {
    let mut rdr = csv::Reader::from_reader(csv.as_bytes());
    let mut map: RrsSnpMap = BTreeMap::new();
    for row in rdr.deserialize::<ResistanceVariant>() {
        let row = row.unwrap();
        if row.gene.trim() != "rrs" {
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

static RRS_RESISTANCE_SNPS: LazyLock<BTreeMap<&'static str, RrsSnpMap>> = LazyLock::new(|| {
    [
        ("Mycobacterium abscessus",      include_str!("../../res/sequences/ntm-db/db/Mycobacterium_abscessus/variants.csv")),
        ("Mycobacterium avium",          include_str!("../../res/sequences/ntm-db/db/Mycobacterium_avium/variants.csv")),
        ("Mycobacterium intracellulare", include_str!("../../res/sequences/ntm-db/db/Mycobacterium_intracellulare/variants.csv")),
    ]
    .into_iter()
    .map(|(species, csv)| (species, parse_rrs_resistance_snps(csv)))
    .collect()
});

/// Parsed and substring-deduplicated rrs reference sequences, initialised once.
static RRS_REFS: LazyLock<Vec<(String, String, Vec<u8>)>> =
    LazyLock::new(|| dedup_substring_same_desc(parse_multi_fasta(REF_MYCO_RRS)));

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RrsSnpCall3End {
    /// 0-based position in the rrs reference sequence.
    pub ref_pos: usize,
    /// Base observed in the query at this position, or `None` if not covered.
    pub query_base: Option<u8>,
    /// Wild-type base at this position.
    pub wt_base: u8,
    /// Maps each resistance-conferring alt base to `(drugs, E.coli nomenclature)`.
    #[serde(with = "super::serde_helpers::u8_btree_map")]
    pub resistance_bases: BTreeMap<u8, (Vec<String>, String)>,
}

impl RrsSnpCall3End {
    pub fn call_tag(&self) -> String {
        let ecoli_prefix: Option<&str> = self.resistance_bases.values()
            .next()
            .map(|(_, nom)| &nom[..nom.len().saturating_sub(1)]);

        match self.query_base {
            None => {
                format!("{}{}{}", self.wt_base as char, self.ref_pos + 1, "?")
            },
            Some(b) if b == self.wt_base => match ecoli_prefix {
                Some(p) => format!("{}{}{} (E.coli: {}{})", self.wt_base as char, self.ref_pos + 1, b as char, p, b as char),
                None    => format!("{}{}{}", self.wt_base as char, self.ref_pos + 1, b as char),
            },
            Some(b) if self.resistance_bases.contains_key(&b) => {
                let (drugs, ecoli) = &self.resistance_bases[&b];
                format!("{}{}{} ({}, E.coli: {})", self.wt_base as char, self.ref_pos + 1, b as char, drugs.join(", "), ecoli)
            }
            Some(b) => match ecoli_prefix {
                Some(p) => format!("{}{}{} (E.coli: {}{})", self.wt_base as char, self.ref_pos + 1, b as char, p, b as char),
                None    => format!("{}{}{}", self.wt_base as char, self.ref_pos + 1, b as char),
            },
        }
    }
}

/// All rrs susceptibility evidence for one sample, ready for UI display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RrsSusceptibilityCalls3End {
    pub position_1248: Option<Rrs3EndPosition1248>,
    pub snp_calls: Vec<RrsSnpCall3End>,
    pub is_susceptible: Option<bool>,
    pub is_susceptible_rare: Option<bool>,
}

/// Returns `Some(false)` if any observed SNP base is a resistance-conferring alt, or `None` if
/// no resistance alt is observed.
pub fn is_susceptible_rrs_3end(snp_calls: &[RrsSnpCall3End]) -> Option<bool> {
    if snp_calls
        .iter()
        .any(|c| c.query_base.is_some_and(|b| c.resistance_bases.contains_key(&b)))
    {
        Some(false)
    } else {
        None
    }
}

/// Returns `Some(false)` if any observed SNP base is a resistance-conferring alt, or `None`
/// otherwise. Parallel to `is_susceptible_rrl_by_snp_calls_rare`: rrs has no position-based
/// anchor call, so all SNP resistance here is inherently not explained by a position mutation.
pub fn is_susceptible_rrs_by_snp_calls_rare_3end(snp_calls: &[RrsSnpCall3End]) -> Option<bool> {
    is_susceptible_rrs_3end(snp_calls)
}

fn call_rrs_snps_3end(snps: &RrsSnpMap, ga: &GappedAlignment) -> Vec<RrsSnpCall3End> {
    snps.iter()
        .map(|(&ref_pos, (wt_base, alt_to_drugs))| {
            let query_base =
                base_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos);
            RrsSnpCall3End {
                ref_pos,
                query_base,
                wt_base: *wt_base,
                resistance_bases: alt_to_drugs.clone(),
            }
        })
        .collect()
}

pub(super) fn find_16s3end_display_window(
    bases: &[u8],
    peak_locs: &[u16],
) -> Option<(u16, u16, bool, u16)> {
    // Flanking bases to show: 9 before pos28, 11 after (pos28 is the first of the 11)
    const LEFT: usize = 10;
    const RIGHT: usize = 10;

    let anchor_len: u16 = RRS3END_ANCHOR_L.len() as u16;

    // --- Forward orientation: ANCHOR_L directly in PBAS ---
    if let Some(hit) = bases
        .windows(anchor_len as usize)
        .position(|w| w.eq_ignore_ascii_case(RRS3END_ANCHOR_L))
    {
        let pos28 = hit + anchor_len as usize;
        if let Some(window) = super::scan_window(pos28, LEFT, RIGHT, peak_locs) {
            return Some((window.0, window.1, false, pos28 as u16));
        }
    }

    let rc_anchor_r: Vec<u8> = reverse_complement(RRS3END_ANCHOR_R);
    if let Some(hit) = bases
        .windows(rc_anchor_r.len())
        .position(|w| w.eq_ignore_ascii_case(&rc_anchor_r))
    {
        let pos28_comp = hit + rc_anchor_r.len();
        if let Some(window) = super::scan_window(pos28_comp, RIGHT, LEFT, peak_locs) {
            return Some((window.0, window.1, true, pos28_comp as u16));
        }
    }

    None
}

/// Align `query` against every Mycobacteriaceae 16S rRNA reference in [`REF_MYCO_RRS`] and
/// return all hits sorted by identity (highest first).
///
/// # Algorithm
///
/// For each reference sequence (filtered to ≥ [`MIN_RRS_REF_LEN`] bp to avoid inflated scores
/// from truncated entries):
///
/// 1. **Strand**: both forward and reverse-complement alignments are scored via [`best_alignment`];
///    the strand with the higher identity wins.
/// 2. **Identity**: gapless (shift-only) alignment — the shorter sequence is slid along the longer
///    and the best-matching offset is chosen. Identity = matching bases / shorter length.
/// 3. **SNP calls**: for species that have an entry in [`RRS_RESISTANCE_SNPS`] (accession
///    contains `':'`), aminoglycoside-resistance SNPs are mapped from reference coordinates to
///    query coordinates using the alignment offset.
pub fn identify_sequence_16s3end(query: &[u8]) -> Vec<SeqIdHit> {
    let rc = reverse_complement(query);
    let rrs3end_position_1248_opt = Rrs3EndPosition1248::from_single_read(query);

    let mut hits: Vec<SeqIdHit> = RRS_REFS
        .iter()
        .filter(|(_, _, refseq)| refseq.len() >= super::MIN_RRS_REF_LEN)
        .map(|(accession, description, refseq)| {
            let fwd = align_to_ref(query, refseq);
            let rev = align_to_ref(&rc, refseq);
            let (ga, is_reverse) = if rev.identity > fwd.identity {
                (rev, true)
            } else {
                (fwd, false)
            };
            let rrs_snp_calls_3end = if accession.contains(':') {
                RRS_RESISTANCE_SNPS
                    .get(description.as_str())
                    .map(|snps| call_rrs_snps_3end(snps, &ga))
                    .unwrap_or_default()
            } else {
                vec![]
            };
            SeqIdHit {
                accession: accession.clone(),
                description: description.clone(),
                identity: ga.identity,
                is_reverse,
                kansasii_gastri_snp_calls: vec![],
                marinum_ulcerans_snp_calls: vec![],
                rrl_snp_calls: vec![],
                rrs_snp_calls: vec![],
                rrs_snp_calls_3end,
                erm41_snp_calls: vec![],
                pnca_snp_calls: vec![],
                aligned_query: ga.gapped_query,
                aligned_ref: ga.gapped_ref,
                ref_start: ga.ref_start,
                erm41_position_28_opt: None,
                rrs3end_position_1248_opt,
                rrl_position_2058_2059_opt: None,
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
