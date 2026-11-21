//! 16S rRNA (rrs) species identification and aminoglycoside resistance calling for
//! *M. abscessus*, *M. avium*, and *M. intracellulare*.
//!
//! Unlike [`rrl`](super::rrl) and [`erm41`](super::erm41), rrs has no single well-characterized
//! diagnostic position — resistance is called purely from the SNP catalogue
//! ([`RRS_RESISTANCE_SNPS`], [`RrsSnpCall`]) parsed from ntm-db's per-species `variants.csv`.
//! See [`rrs3end`](super::rrs3end) for the companion module covering the 3' end of the gene
//! (position 1248).

use super::{
    GappedAlignment, REF_AMPLICON_RRS, REF_MYCO_RRS, RefPool, SeqIdHit, align_to_ref,
    base_at_ref_pos, ref_pool, reverse_complement, trim_alignment_ends,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// Maps a reference position to `(wt_base, alts)` where `alts` maps each resistance alt to
/// `(drugs, E.coli nomenclature)`.
type RrsSnpMap = BTreeMap<usize, (u8, BTreeMap<u8, (Vec<String>, String)>)>;

/// One row of the ntm-db `variants.csv` resistance catalogue.
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

/// Parses rrs resistance SNPs (`gene == "rrs"`, `type == "drug_resistance"`) out of an ntm-db
/// `variants.csv`, keyed by **0-based nucleotide position** in the rrs reference sequence.
/// Mutations are expected in `n.<pos><wt>><alt>` HGVS nucleotide notation (e.g. `n.1401A>G`);
/// rows that don't parse in that form are skipped.
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
                    let variant = entry
                        .1
                        .entry(alt)
                        .or_insert_with(|| (Vec::new(), ecoli.clone()));
                    if !variant.0.contains(&drug) {
                        variant.0.push(drug);
                    }
                }
            }
        }
    }
    map
}

/// Resistance SNP maps per species description, parsed once from each species' ntm-db
/// `variants.csv`.
static RRS_RESISTANCE_SNPS: LazyLock<BTreeMap<&'static str, RrsSnpMap>> = LazyLock::new(|| {
    [
        (
            "Mycobacterium abscessus",
            include_str!("../../res/sequences/ntm-db/db/Mycobacterium_abscessus/variants.csv"),
        ),
        (
            "Mycobacterium avium",
            include_str!("../../res/sequences/ntm-db/db/Mycobacterium_avium/variants.csv"),
        ),
        (
            "Mycobacterium intracellulare",
            include_str!("../../res/sequences/ntm-db/db/Mycobacterium_intracellulare/variants.csv"),
        ),
    ]
    .into_iter()
    .map(|(species, csv)| (species, parse_rrs_resistance_snps(csv)))
    .collect()
});

/// Parsed and substring-deduplicated rrs reference sequences, initialised once.
static RRS_REFS: LazyLock<RefPool> =
    LazyLock::new(|| ref_pool(&[REF_MYCO_RRS], &[REF_AMPLICON_RRS], |_| true));

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RrsSnpCall {
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

impl RrsSnpCall {
    /// Human-readable tag, e.g. `A1401G (amikacin, E.coli: A1401G)` for a resistance alt, or
    /// `A1401A (E.coli: A1401A)`/`A1401?` otherwise — always includes the *E. coli*-numbered
    /// equivalent when known, since that's the numbering most aminoglycoside-resistance
    /// literature uses.
    pub fn call_tag(&self) -> String {
        let ecoli_prefix: Option<&str> = self
            .resistance_bases
            .values()
            .next()
            .map(|(_, nom)| &nom[..nom.len().saturating_sub(1)]);

        match self.query_base {
            None => {
                format!("{}{}{}", self.wt_base as char, self.ref_pos + 1, "?")
            }
            Some(b) if b == self.wt_base => match ecoli_prefix {
                Some(p) => format!(
                    "{}{}{} (E.coli: {}{})",
                    self.wt_base as char,
                    self.ref_pos + 1,
                    b as char,
                    p,
                    b as char
                ),
                None => format!("{}{}{}", self.wt_base as char, self.ref_pos + 1, b as char),
            },
            Some(b) if self.resistance_bases.contains_key(&b) => {
                let (drugs, ecoli) = &self.resistance_bases[&b];
                format!(
                    "{}{}{} ({}, E.coli: {})",
                    self.wt_base as char,
                    self.ref_pos + 1,
                    b as char,
                    drugs.join(", "),
                    ecoli
                )
            }
            Some(b) => match ecoli_prefix {
                Some(p) => format!(
                    "{}{}{} (E.coli: {}{})",
                    self.wt_base as char,
                    self.ref_pos + 1,
                    b as char,
                    p,
                    b as char
                ),
                None => format!("{}{}{}", self.wt_base as char, self.ref_pos + 1, b as char),
            },
        }
    }
}

/// All rrs susceptibility evidence for one sample, ready for UI display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RrsSusceptibilityCalls {
    /// Every known resistance-conferring SNP position, with whatever base (if any) was observed.
    pub snp_calls: Vec<RrsSnpCall>,
    /// Verdict from [`is_susceptible_rrs`].
    pub is_susceptible: Option<bool>,
    /// Verdict from [`is_susceptible_rrs_by_snp_calls_rare`] — identical to `is_susceptible` for
    /// rrs (see that function's docs for why).
    pub is_susceptible_rare: Option<bool>,
}

/// Returns `Some(false)` if any observed SNP base is a resistance-conferring alt, or `None` if
/// no resistance alt is observed.
pub fn is_susceptible_rrs(snp_calls: &[RrsSnpCall]) -> Option<bool> {
    if snp_calls.iter().any(|c| {
        c.query_base
            .is_some_and(|b| c.resistance_bases.contains_key(&b))
    }) {
        Some(false)
    } else {
        None
    }
}

/// Returns `Some(false)` if any observed SNP base is a resistance-conferring alt, or `None`
/// otherwise. Parallel to `is_susceptible_rrl_by_snp_calls_rare`: rrs has no position-based
/// anchor call, so all SNP resistance here is inherently not explained by a position mutation.
pub fn is_susceptible_rrs_by_snp_calls_rare(snp_calls: &[RrsSnpCall]) -> Option<bool> {
    is_susceptible_rrs(snp_calls)
}

/// Maps each known resistance SNP position to the query base aligned to it in `ga`
/// (via [`base_at_ref_pos`]).
fn call_rrs_snps(snps: &RrsSnpMap, ga: &GappedAlignment) -> Vec<RrsSnpCall> {
    snps.iter()
        .map(|(&ref_pos, (wt_base, alt_to_drugs))| {
            let query_base =
                base_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos);
            RrsSnpCall {
                ref_pos,
                query_base,
                wt_base: *wt_base,
                resistance_bases: alt_to_drugs.clone(),
            }
        })
        .collect()
}

/// Align `query` against every Mycobacteriaceae 16S rRNA reference in [`REF_MYCO_RRS`] and
/// return all hits sorted by identity (highest first).
///
/// # Algorithm
///
/// For each reference sequence (full-length NCBI/ntm-db entries plus short amplicon
/// references; ties on identity go to the longer reference):
///
/// 1. **Strand**: both forward and reverse-complement alignments are scored via
///    [`align_to_ref`]; the strand with the higher identity wins.
/// 2. **Identity**: semiglobal gapped alignment (see [`align_to_ref`]), then low-identity ends
///    are removed by [`trim_alignment_ends`]. Identity = matching bases / aligned reference
///    span.
/// 3. **SNP calls**: for species that have an entry in [`RRS_RESISTANCE_SNPS`] (accession
///    contains `':'`), each aminoglycoside-resistance SNP's reference position is looked up in
///    the gapped alignment via [`base_at_ref_pos`] to get the query base aligned there.
pub fn identify_sequence_16s(query: &[u8]) -> Vec<SeqIdHit> {
    let rc = reverse_complement(query);
    let mut hits: Vec<SeqIdHit> = RRS_REFS
        .iter()
        .map(|(source, accession, description, refseq)| {
            let fwd = align_to_ref(query, refseq);
            let rev = align_to_ref(&rc, refseq);
            let (ga, is_reverse) = if rev.identity > fwd.identity {
                (rev, true)
            } else {
                (fwd, false)
            };
            let ga = trim_alignment_ends(ga);
            let rrs_snp_calls = if accession.contains(':') {
                RRS_RESISTANCE_SNPS
                    .get(description.as_str())
                    .map(|snps| call_rrs_snps(snps, &ga))
                    .unwrap_or_default()
            } else {
                vec![]
            };
            SeqIdHit {
                accession: accession.clone(),
                description: description.clone(),
                source: *source,
                identity: ga.identity,
                is_reverse,
                rrl_snp_calls: vec![],
                rrs_snp_calls,
                rrs_snp_calls_3end: vec![],
                erm41_snp_calls: vec![],
                pnca_snp_calls: vec![],
                rpob_snp_calls: vec![],
                aligned_query: ga.gapped_query,
                aligned_ref: ga.gapped_ref,
                ref_start: ga.ref_start,
                erm41_position_28_opt: None,
                rrs3end_position_1248_opt: None,
                rrl_position_2058_2059_opt: None,
            }
        })
        .collect();
    super::sort_hits_by_identity(&mut hits);
    hits
}
