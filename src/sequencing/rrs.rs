use super::{REF_MYCO_RRS, SeqIdHit, best_alignment, parse_multi_fasta, reverse_complement};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// Maps a reference position to `(wt_base, alts)` where `alts` maps each resistance alt to
/// `(drugs, E.coli nomenclature)`.
type RrsSnpMap = BTreeMap<usize, (u8, BTreeMap<u8, (Vec<String>, String)>)>;

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

#[derive(Clone, Debug)]
pub struct RrsSnpCall {
    /// 0-based position in the rrs reference sequence.
    pub ref_pos: usize,
    /// Base observed in the query at this position, or `None` if not covered.
    pub query_base: Option<u8>,
    /// Wild-type base at this position.
    pub wt_base: u8,
    /// Maps each resistance-conferring alt base to `(drugs, E.coli nomenclature)`.
    pub resistance_bases: BTreeMap<u8, (Vec<String>, String)>,
}

impl RrsSnpCall {
    pub fn call_tag(&self) -> String {
        let ecoli_prefix: Option<&str> = self.resistance_bases.values()
            .next()
            .map(|(_, nom)| &nom[..nom.len().saturating_sub(1)]);

        match self.query_base {
            None => "".to_string(),
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

/// All rrs susceptibility evidence for one sample, ready for UI display.
#[derive(Debug, Clone, Default)]
pub struct RrsSusceptibilityCalls {
    pub snp_calls: Vec<RrsSnpCall>,
    pub is_susceptible: Option<bool>,
    pub is_susceptible_rare: Option<bool>,
}

/// Returns `Some(false)` if any observed SNP base is a resistance-conferring alt, or `None` if
/// no resistance alt is observed.
pub fn is_susceptible_rrs(snp_calls: &[RrsSnpCall]) -> Option<bool> {
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
pub fn is_susceptible_rrs_by_snp_calls_rare(snp_calls: &[RrsSnpCall]) -> Option<bool> {
    is_susceptible_rrs(snp_calls)
}

fn call_rrs_snps(
    snps: &RrsSnpMap,
    query: &[u8],
    alignment_offset: isize,
) -> Vec<RrsSnpCall> {
    snps.iter()
        .map(|(&ref_pos, (wt_base, alt_to_drugs))| {
            let query_pos = ref_pos as isize - alignment_offset;
            let query_base = if query_pos >= 0 && (query_pos as usize) < query.len() {
                Some(query[query_pos as usize].to_ascii_uppercase())
            } else {
                None
            };
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
///
/// The returned [`SeqIdHit`] list is sorted descending by identity; callers typically take the
/// top hit or apply a [`MIN_SEQ_ID_IDENTITY`] threshold.
pub fn identify_sequence_16s(query: &[u8]) -> Vec<SeqIdHit> {
    let rc = reverse_complement(query);
    let mut hits: Vec<SeqIdHit> = parse_multi_fasta(REF_MYCO_RRS)
        .into_iter()
        .filter(|(_, _, refseq)| refseq.len() >= super::MIN_RRS_REF_LEN)
        .map(|(accession, description, refseq)| {
            let (fwd_id, fwd_off) = best_alignment(query, &refseq);
            let (rev_id, rev_off) = best_alignment(&rc, &refseq);
            let (identity, is_reverse, aligned_query, alignment_offset) = if rev_id > fwd_id {
                (rev_id, true, rc.clone(), rev_off)
            } else {
                (fwd_id, false, query.to_vec(), fwd_off)
            };
            let rrs_snp_calls = if accession.contains(':') {
                RRS_RESISTANCE_SNPS
                    .get(description.as_str())
                    .map(|snps| call_rrs_snps(snps, &aligned_query, alignment_offset))
                    .unwrap_or_default()
            } else {
                vec![]
            };
            SeqIdHit {
                accession,
                description,
                identity,
                is_reverse,
                aligned_query,
                alignment_offset,
                ref_seq: refseq,
                kansasii_gastri_snp_calls: vec![],
                marinum_ulcerans_snp_calls: vec![],
                rrl_snp_calls: vec![],
                rrs_snp_calls,
                erm41_snp_calls: vec![],
                erm41_position_28_opt: None,
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
