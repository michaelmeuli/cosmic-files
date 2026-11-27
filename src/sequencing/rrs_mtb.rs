//! *Mycobacterium tuberculosis* complex rrs sequencing (primers #289 / #261, protocol 32.43613):
//! amikacin, kanamycin and capreomycin resistance.
//!
//! The read is aligned to the H37Rv rrs gene ([`REF_RRS_H37RV`]) and the bases at the protocol's
//! positions ([`SITES`]) are read there. Resistance alleles are the WHO catalogue rows at
//! "Assoc w R" or "Assoc w R - Interim". The calls only ever mean resistant or undetermined: a
//! wild-type read gets no susceptible verdict. The streptomycin positions of rrs lie outside the
//! amplicon.

use super::pnca::MutationRow;
use super::tb_data::confidence_rank;
use super::{
    REF_AMPLICON_RRS_MTB, REF_MYCO_RRS, REF_RRS_H37RV, RefPool, SeqIdHit, align_to_ref,
    base_at_ref_pos, canonical_binomial, parse_fasta_seq, ref_pool, reverse_complement,
    sort_hits_by_identity, trim_alignment_ends,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// The positions of protocol 32.43613 as `(H37Rv position, E. coli position)`, both 1-based.
const SITES: [(usize, usize); 5] = [
    (1401, 1408),
    (1402, 1409),
    (1403, 1410),
    (1483, 1490),
    (1484, 1491),
];

/// Minimum identity of the read to H37Rv rrs for calls to be made at all.
const MIN_H37RV_IDENTITY: f32 = 80.0;

/// Species epithets of the *M. tuberculosis* complex as the references write them.
const MTBC_EPITHETS: &[&str] = &[
    "tuberculosis",
    "africanum",
    "bovis",
    "canetti",
    "canettii",
    "caprae",
    "microti",
    "mungi",
    "orygis",
    "pinnipedii",
    "suricattae",
];

/// The call at one *M. tuberculosis* rrs site, with what the catalogue says about it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RrsMtbSnpCall {
    /// 0-based position in H37Rv rrs.
    pub ref_pos: usize,
    /// Base observed in the query at this position, or `None` if not covered.
    pub query_base: Option<u8>,
    /// H37Rv base at this position.
    pub wt_base: u8,
    /// The equivalent 1-based *E. coli* position.
    pub ecoli_pos: usize,
    /// Maps each resistance-conferring alt base to its drugs.
    #[serde(with = "super::serde_helpers::u8_btree_map")]
    pub resistance_bases: BTreeMap<u8, Vec<String>>,
    /// Alleles the catalogue lists as "Uncertain significance" (and for no drug as resistance).
    pub uncertain_alts: Vec<u8>,
}

impl RrsMtbSnpCall {
    /// Human-readable tag in H37Rv numbering, e.g.
    /// `A1401G (amikacin, kanamycin, E.coli: A1408G)`, or `A1401?` if not covered.
    pub fn call_tag(&self) -> String {
        let wt = self.wt_base as char;
        let pos = self.ref_pos + 1;
        let Some(base) = self.query_base else {
            return format!("{wt}{pos}?");
        };
        let note = if let Some(drugs) = self.resistance_bases.get(&base) {
            format!("{}, ", drugs.join(", "))
        } else if self.uncertain_alts.contains(&base) {
            "uncertain significance, ".to_string()
        } else {
            String::new()
        };
        let base = base as char;
        format!(
            "{wt}{pos}{base} ({note}E.coli: {wt}{}{base})",
            self.ecoli_pos
        )
    }
}

/// H37Rv rrs bytes (uppercase).
static RRS_H37RV: LazyLock<Vec<u8>> = LazyLock::new(|| {
    parse_fasta_seq(REF_RRS_H37RV)
        .into_iter()
        .map(|b| b.to_ascii_uppercase())
        .collect()
});

/// All *M. tuberculosis* rrs susceptibility evidence for one sample, ready for UI display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RrsMtbSusceptibilityCalls {
    /// One call per entry of [`SITES`]; empty for other reads.
    pub snp_calls: Vec<RrsMtbSnpCall>,
    /// Verdict from [`is_susceptible_rrs_mtb`].
    pub is_susceptible: Option<bool>,
    /// Whether a top hit is of the *M. tuberculosis* complex, the only one the WHO catalogue
    /// applies to. `false` when there are no calls.
    pub species_validated: bool,
}

/// Returns `Some(false)` if any observed base is a resistance-conferring alt, or `None`
/// otherwise: a wild-type read gets no susceptible verdict.
pub fn is_susceptible_rrs_mtb(snp_calls: &[RrsMtbSnpCall]) -> Option<bool> {
    snp_calls
        .iter()
        .any(|c| {
            c.query_base
                .is_some_and(|b| c.resistance_bases.contains_key(&b))
        })
        .then_some(false)
}

/// One uncalled [`RrsMtbSnpCall`] per entry of [`SITES`], with its catalogue alleles.
static CATALOGUE: LazyLock<Vec<RrsMtbSnpCall>> =
    LazyLock::new(|| parse_catalogue(include_str!("../../tbprofiler/mutations.csv"), &RRS_H37RV));

fn parse_catalogue(csv: &str, h37rv: &[u8]) -> Vec<RrsMtbSnpCall> {
    // `(position, alt)` → drugs at resistance confidence; empty: only uncertain.
    let mut alts: BTreeMap<(usize, u8), Vec<String>> = BTreeMap::new();
    let mut rdr = csv::Reader::from_reader(csv.as_bytes());
    for row in rdr.deserialize::<MutationRow>() {
        let Ok(row) = row else { continue };
        let rank = confidence_rank(row.confidence.trim());
        if row.gene.trim() != "rrs" || rank > 2 {
            continue;
        }
        // Single substitutions only: `n.1401A>G`.
        let Some(rest) = row.mutation.trim().strip_prefix("n.") else {
            continue;
        };
        let Some((from, to)) = rest.split_once('>') else {
            continue;
        };
        let digits = from.len().saturating_sub(1);
        let (Some(Ok(pos)), &[alt]) = (from.get(..digits).map(str::parse), to.as_bytes()) else {
            continue;
        };
        let drugs = alts.entry((pos, alt)).or_default();
        let drug = row.drug.trim().to_string();
        if rank < 2 && !drugs.contains(&drug) {
            drugs.push(drug);
        }
    }

    SITES
        .iter()
        .filter_map(|&(pos, ecoli_pos)| {
            let wt_base = *h37rv.get(pos - 1)?;
            let mut resistance_bases = BTreeMap::new();
            let mut uncertain_alts = Vec::new();
            for (&(_, alt), drugs) in alts.range((pos, 0)..=(pos, u8::MAX)) {
                if drugs.is_empty() {
                    uncertain_alts.push(alt);
                } else {
                    resistance_bases.insert(alt, drugs.clone());
                }
            }
            Some(RrsMtbSnpCall {
                ref_pos: pos - 1,
                query_base: None,
                wt_base,
                ecoli_pos,
                resistance_bases,
                uncertain_alts,
            })
        })
        .collect()
}

/// `true` if a hit description names a member of the *M. tuberculosis* complex.
pub(crate) fn is_mtbc(description: &str) -> bool {
    canonical_binomial(description).is_some_and(|name| {
        name.strip_prefix("Mycobacterium ")
            .is_some_and(|epithet| MTBC_EPITHETS.contains(&epithet))
    })
}

/// Align `query` (either strand) to H37Rv rrs and call every site of [`SITES`]. Returns no
/// calls when the read doesn't align to rrs at [`MIN_H37RV_IDENTITY`].
pub fn call_rrs_mtb(query: &[u8]) -> Vec<RrsMtbSnpCall> {
    let reference = &*RRS_H37RV;
    let fwd = align_to_ref(query, reference);
    let rev = align_to_ref(&reverse_complement(query), reference);
    let ga = trim_alignment_ends(if rev.identity > fwd.identity {
        rev
    } else {
        fwd
    });
    if ga.identity < MIN_H37RV_IDENTITY {
        return Vec::new();
    }
    CATALOGUE
        .iter()
        .map(|site| RrsMtbSnpCall {
            query_base: base_at_ref_pos(
                &ga.gapped_query,
                &ga.gapped_ref,
                ga.ref_start,
                site.ref_pos,
            ),
            ..site.clone()
        })
        .collect()
}

/// NCBI 16S references plus the GTDB #289/#261 amplicons.
static RRS_MTB_REFS: LazyLock<RefPool> =
    LazyLock::new(|| ref_pool(&[REF_MYCO_RRS], &[REF_AMPLICON_RRS_MTB], |_| true));

/// Align an rrs #289/#261 read against the 16S references and return all hits sorted by
/// identity, with the resistance calls ([`call_rrs_mtb`]) on the top hit.
pub fn identify_sequence_rrs_mtb(query: &[u8]) -> Vec<SeqIdHit> {
    let rc = reverse_complement(query);
    let mut hits: Vec<SeqIdHit> = RRS_MTB_REFS
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
            SeqIdHit {
                accession: accession.clone(),
                description: description.clone(),
                source: *source,
                identity: ga.identity,
                is_reverse,
                rrl_snp_calls: vec![],
                rrs_snp_calls: vec![],
                rrs_snp_calls_3end: vec![],
                rrs_mtb_snp_calls: vec![],
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
    sort_hits_by_identity(&mut hits);
    if let Some(top) = hits.first_mut() {
        top.rrs_mtb_snp_calls = call_rrs_mtb(query);
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sequencing::batch::susceptibility_from_hits;

    /// The 212 bp #289/#261 product of H37Rv (positions 1324–1535).
    fn amplicon() -> Vec<u8> {
        RRS_H37RV[1323..1535].to_vec()
    }

    /// Catching wrong reference coordinates: every catalogued wild type must match H37Rv.
    #[test]
    fn h37rv_wild_type_matches_the_catalogue() {
        assert_eq!(RRS_H37RV.len(), 1537);
        let wt: Vec<u8> = CATALOGUE.iter().map(|c| c.wt_base).collect();
        assert_eq!(wt, b"ACGCG");
        let resistance: Vec<(usize, Vec<u8>)> = CATALOGUE
            .iter()
            .map(|c| (c.ref_pos + 1, c.resistance_bases.keys().copied().collect()))
            .collect();
        assert_eq!(
            resistance,
            [
                (1401, b"G".to_vec()),
                (1402, b"T".to_vec()),
                (1403, vec![]),
                (1483, vec![]),
                (1484, b"T".to_vec()),
            ]
        );
    }

    #[test]
    fn wild_type_read_has_no_verdict_on_both_strands() {
        for read in [amplicon(), reverse_complement(&amplicon())] {
            let hits = identify_sequence_rrs_mtb(&read);
            let (verdict, calls) = susceptibility_from_hits(&hits);
            assert_eq!(verdict, None);
            assert_eq!(calls.rrs_mtb.snp_calls.len(), 5);
            assert!(calls.rrs3end.snp_calls.is_empty());
            assert!(
                calls
                    .rrs_mtb
                    .snp_calls
                    .iter()
                    .all(|c| c.query_base == Some(c.wt_base))
            );
            assert!(calls.rrs_mtb.species_validated);
        }
    }

    #[test]
    fn a1401g_read_is_resistant() {
        let mut read = amplicon();
        read[1400 - 1323] = b'G';
        let (verdict, calls) = susceptibility_from_hits(&identify_sequence_rrs_mtb(&read));
        assert_eq!(verdict, Some(false));
        assert_eq!(calls.rrs_mtb.is_susceptible, Some(false));
        assert!(calls.rrs3end.snp_calls.is_empty());
        let tag = calls.rrs_mtb.snp_calls[0].call_tag();
        assert!(
            tag.starts_with("A1401G (") && tag.contains("amikacin"),
            "{tag}"
        );
        assert!(tag.ends_with("E.coli: A1408G)"), "{tag}");
    }

    #[test]
    fn uncovered_sites_are_reported_as_such() {
        // Ends at position 1450, before 1483 / 1484.
        let calls = call_rrs_mtb(&RRS_H37RV[1323..1450]);
        let tags: Vec<String> = calls.iter().map(RrsMtbSnpCall::call_tag).collect();
        assert_eq!(tags[3], "C1483?");
        assert_eq!(tags[4], "G1484?");
    }

    #[test]
    fn mtb_calls_survive_serialisation() {
        let calls = call_rrs_mtb(&amplicon());
        let json = serde_json::to_string(&calls).unwrap();
        let back: Vec<RrsMtbSnpCall> = serde_json::from_str(&json).unwrap();
        assert_eq!(back[0].call_tag(), calls[0].call_tag());
        assert_eq!(back[0].ecoli_pos, 1408);
    }

    #[test]
    fn mtbc_names() {
        assert!(is_mtbc("Mycobacterium tuberculosis variant bovis"));
        assert!(is_mtbc("Mycobacterium canettii"));
        assert!(!is_mtbc("Mycobacterium kansasii"));
        assert!(!is_mtbc("Corynebacterium bovis"));
    }
}
