//! *Mycobacterium tuberculosis* complex 23S sequencing (primers SP1 F / SP2 R mod, protocol
//! 32.43604): linezolid resistance.
//!
//! The read is aligned to the H37Rv rrl gene ([`REF_RRL_H37RV`]) and the bases at [`SITES`] are
//! read there. A read is resistant for a WHO-catalogue allele at "Assoc w R" or "Assoc w R -
//! Interim", or for a mutation (single or double) named in the protocol ([`SITES`],
//! [`PROTOCOL_PAIRS`]); [`rrl_mtb_findings`] lists them with their source. The calls only ever
//! mean resistant or undetermined: a wild-type read gets no susceptible verdict. Linezolid
//! resistance through rplC is a separate assay.

use super::pnca::MutationRow;
use super::tb_data::confidence_rank;
use super::{
    GappedAlignment, REF_AMPLICON_RRL_MTB, REF_MYCO_RRL, REF_RRL_H37RV, RefPool, SeqIdHit,
    align_to_ref, base_at_ref_pos, parse_fasta_seq, ref_pool, reverse_complement,
    sort_hits_by_identity, trim_alignment_ends,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// The called positions as `(H37Rv position, E. coli position, protocol allele)`, 1-based. The
/// third value is the allele protocol 32.43604 names as resistance-conferring on its own
/// (U2504 is written T here).
const SITES: [(usize, usize, Option<u8>); 11] = [
    (2270, 2032, None),
    (2293, 2055, None),
    (2299, 2061, None),
    (2689, 2451, None),
    (2737, 2499, None),
    (2741, 2503, Some(b'G')),
    (2742, 2504, Some(b'G')),
    (2743, 2505, Some(b'A')),
    (2746, 2508, None),
    (2810, 2572, None),
    (2814, 2576, Some(b'T')),
];

/// The protocol's double mutations as pairs of `(H37Rv position, allele)`: G2032A + C2499A and
/// C2055A + A2572U. Its other pairs contain U2504G, which counts on its own.
const PROTOCOL_PAIRS: [[(usize, u8); 2]; 2] =
    [[(2270, b'A'), (2737, b'A')], [(2293, b'A'), (2810, b'T')]];

/// The catalogued insertion `n.2269_2270insT`: a `T` before this 0-based reference index.
const INSERTION_BEFORE: usize = 2269;

/// Minimum identity of the read to H37Rv rrl for calls to be made at all.
const MIN_H37RV_IDENTITY: f32 = 80.0;

/// The call at one *M. tuberculosis* rrl site.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RrlMtbSnpCall {
    /// 0-based position in H37Rv rrl.
    pub ref_pos: usize,
    /// Base observed in the query at this position, or `None` if not covered.
    pub query_base: Option<u8>,
    /// H37Rv base at this position.
    pub wt_base: u8,
    /// The equivalent 1-based *E. coli* position.
    pub ecoli_pos: usize,
    /// Alleles the WHO catalogue associates with linezolid resistance.
    pub who_alts: Vec<u8>,
    /// Alleles the catalogue lists as "Uncertain significance".
    pub uncertain_alts: Vec<u8>,
    /// Allele the protocol names as resistance-conferring on its own.
    pub protocol_alt: Option<u8>,
    /// `true` when the read carries `n.2269_2270insT` (set on the 2270 call only).
    pub insertion_t: bool,
}

impl RrlMtbSnpCall {
    /// `true` if `base` is one half of a [`PROTOCOL_PAIRS`] entry at this site.
    fn is_pair_half(&self, base: u8) -> bool {
        PROTOCOL_PAIRS
            .iter()
            .flatten()
            .any(|&(pos, alt)| pos == self.ref_pos + 1 && alt == base)
    }

    /// Human-readable tag in H37Rv numbering, e.g.
    /// `G2814T (WHO, protocol 32.43604; E.coli: G2576T)`, or `G2814?` if not covered.
    pub fn call_tag(&self) -> String {
        let wt = self.wt_base as char;
        let pos = self.ref_pos + 1;
        let insertion = if self.insertion_t {
            "n.2269_2270insT (WHO), "
        } else {
            ""
        };
        let Some(base) = self.query_base else {
            return format!("{insertion}{wt}{pos}?");
        };
        let mut notes: Vec<&str> = Vec::new();
        if self.who_alts.contains(&base) {
            notes.push("WHO");
        }
        if self.protocol_alt == Some(base) {
            notes.push("protocol 32.43604");
        }
        if self.is_pair_half(base) {
            notes.push("part of a double mutation in protocol 32.43604");
        }
        if notes.is_empty() && self.uncertain_alts.contains(&base) {
            notes.push("uncertain significance");
        }
        let note = if notes.is_empty() {
            String::new()
        } else {
            format!("{}; ", notes.join(", "))
        };
        let base = base as char;
        format!(
            "{insertion}{wt}{pos}{base} ({note}E.coli: {wt}{}{base})",
            self.ecoli_pos
        )
    }
}

/// All *M. tuberculosis* rrl susceptibility evidence for one sample, ready for UI display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RrlMtbSusceptibilityCalls {
    /// One call per entry of [`SITES`]; empty for other reads.
    pub snp_calls: Vec<RrlMtbSnpCall>,
    /// Verdict from [`is_susceptible_rrl_mtb`].
    pub is_susceptible: Option<bool>,
    /// Whether a top hit is of the *M. tuberculosis* complex, the only one the catalogue and
    /// protocol apply to. `false` when there are no calls.
    pub species_validated: bool,
}

/// Every resistance-conferring mutation in `calls`, each with its source, e.g.
/// `"G2814T (WHO, protocol 32.43604)"`. A single half of a protocol pair is not one.
pub fn rrl_mtb_findings(calls: &[RrlMtbSnpCall]) -> Vec<String> {
    let mut findings = Vec::new();
    for call in calls {
        if call.insertion_t {
            findings.push("n.2269_2270insT (WHO)".to_string());
        }
        let Some(base) = call.query_base else {
            continue;
        };
        let mut sources = Vec::new();
        if call.who_alts.contains(&base) {
            sources.push("WHO");
        }
        if call.protocol_alt == Some(base) {
            sources.push("protocol 32.43604");
        }
        if !sources.is_empty() {
            findings.push(format!(
                "{}{}{} ({})",
                call.wt_base as char,
                call.ref_pos + 1,
                base as char,
                sources.join(", ")
            ));
        }
    }
    for pair in PROTOCOL_PAIRS {
        let observed: Vec<String> = pair
            .iter()
            .filter_map(|&(pos, alt)| {
                let call = calls.iter().find(|c| c.ref_pos + 1 == pos)?;
                (call.query_base == Some(alt))
                    .then(|| format!("{}{pos}{}", call.wt_base as char, alt as char))
            })
            .collect();
        if observed.len() == pair.len() {
            findings.push(format!(
                "{} (protocol 32.43604, double mutation)",
                observed.join(" + ")
            ));
        }
    }
    findings
}

/// Returns `Some(false)` if [`rrl_mtb_findings`] finds a mutation, or `None` otherwise: a
/// wild-type read gets no susceptible verdict.
pub fn is_susceptible_rrl_mtb(calls: &[RrlMtbSnpCall]) -> Option<bool> {
    (!rrl_mtb_findings(calls).is_empty()).then_some(false)
}

/// H37Rv rrl bytes (uppercase).
static RRL_H37RV: LazyLock<Vec<u8>> = LazyLock::new(|| {
    parse_fasta_seq(REF_RRL_H37RV)
        .into_iter()
        .map(|b| b.to_ascii_uppercase())
        .collect()
});

/// One uncalled [`RrlMtbSnpCall`] per entry of [`SITES`], with its catalogue alleles.
static CATALOGUE: LazyLock<Vec<RrlMtbSnpCall>> =
    LazyLock::new(|| parse_catalogue(include_str!("../../tbprofiler/mutations.csv"), &RRL_H37RV));

fn parse_catalogue(csv: &str, h37rv: &[u8]) -> Vec<RrlMtbSnpCall> {
    // `(position, alt)` → whether the catalogue associates it with resistance (else uncertain).
    let mut alts: BTreeMap<(usize, u8), bool> = BTreeMap::new();
    let mut rdr = csv::Reader::from_reader(csv.as_bytes());
    for row in rdr.deserialize::<MutationRow>() {
        let Ok(row) = row else { continue };
        let rank = confidence_rank(row.confidence.trim());
        if row.gene.trim() != "rrl" || row.drug.trim() != "linezolid" || rank > 2 {
            continue;
        }
        // Single substitutions only: `n.2814G>T`.
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
        *alts.entry((pos, alt)).or_default() |= rank < 2;
    }

    SITES
        .iter()
        .filter_map(|&(pos, ecoli_pos, protocol_alt)| {
            let wt_base = *h37rv.get(pos - 1)?;
            let mut who_alts = Vec::new();
            let mut uncertain_alts = Vec::new();
            for (&(_, alt), &associated) in alts.range((pos, 0)..=(pos, u8::MAX)) {
                if associated {
                    who_alts.push(alt);
                } else {
                    uncertain_alts.push(alt);
                }
            }
            Some(RrlMtbSnpCall {
                ref_pos: pos - 1,
                query_base: None,
                wt_base,
                ecoli_pos,
                who_alts,
                uncertain_alts,
                protocol_alt,
                insertion_t: false,
            })
        })
        .collect()
}

/// `true` if the alignment has a single inserted `T` equivalent to `n.2269_2270insT`. Inside a
/// run of `T`s the aligner may place the insertion anywhere in the run, all the same variant.
fn has_insertion_t(ga: &GappedAlignment, reference: &[u8]) -> bool {
    let mut first = INSERTION_BEFORE;
    while first > 0 && reference[first - 1] == b'T' {
        first -= 1;
    }
    let mut last = INSERTION_BEFORE;
    while reference.get(last) == Some(&b'T') {
        last += 1;
    }

    // Inserted bases, grouped by the reference index they precede.
    let mut inserted: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    let mut ref_pos = ga.ref_start;
    for (&q, &r) in ga.gapped_query.iter().zip(&ga.gapped_ref) {
        if r == b'-' {
            inserted
                .entry(ref_pos)
                .or_default()
                .push(q.to_ascii_uppercase());
        } else {
            ref_pos += 1;
        }
    }
    inserted.range(first..=last).any(|(_, bases)| bases == b"T")
}

/// Align `query` (either strand) to H37Rv rrl and call every site of [`SITES`]. Returns no
/// calls when the read doesn't align to rrl at [`MIN_H37RV_IDENTITY`].
pub fn call_rrl_mtb(query: &[u8]) -> Vec<RrlMtbSnpCall> {
    let reference = &*RRL_H37RV;
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
    let insertion = has_insertion_t(&ga, reference);
    CATALOGUE
        .iter()
        .map(|site| RrlMtbSnpCall {
            query_base: base_at_ref_pos(
                &ga.gapped_query,
                &ga.gapped_ref,
                ga.ref_start,
                site.ref_pos,
            ),
            insertion_t: insertion && site.ref_pos == INSERTION_BEFORE,
            ..site.clone()
        })
        .collect()
}

/// NCBI 23S references plus the GTDB SP1 F / SP2 R mod amplicons.
static RRL_MTB_REFS: LazyLock<RefPool> =
    LazyLock::new(|| ref_pool(&[REF_MYCO_RRL], &[REF_AMPLICON_RRL_MTB], |_| true));

/// Align an SP1 F / SP2 R mod read against the 23S references and return all hits sorted by
/// identity, with the resistance calls ([`call_rrl_mtb`]) on the top hit.
pub fn identify_sequence_rrl_mtb(query: &[u8]) -> Vec<SeqIdHit> {
    let rc = reverse_complement(query);
    let mut hits: Vec<SeqIdHit> = RRL_MTB_REFS
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
                rrl_mtb_snp_calls: vec![],
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
        top.rrl_mtb_snp_calls = call_rrl_mtb(query);
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sequencing::batch::susceptibility_from_hits;

    /// The 728 bp SP1 F / SP2 R mod product of H37Rv (positions 2199–2926).
    const START: usize = 2198;

    fn amplicon() -> Vec<u8> {
        RRL_H37RV[START..2926].to_vec()
    }

    /// The amplicon with `(H37Rv position, base)` substitutions.
    fn mutated(changes: &[(usize, u8)]) -> Vec<u8> {
        let mut read = amplicon();
        for &(pos, base) in changes {
            read[pos - 1 - START] = base;
        }
        read
    }

    /// Catching wrong reference coordinates.
    #[test]
    fn h37rv_wild_types_and_catalogue_alleles() {
        assert_eq!(RRL_H37RV.len(), 3138);
        let wt: Vec<u8> = CATALOGUE.iter().map(|c| c.wt_base).collect();
        assert_eq!(wt, b"GCGACATGGAG");
        let who: Vec<(usize, &[u8])> = CATALOGUE
            .iter()
            .filter(|c| !c.who_alts.is_empty())
            .map(|c| (c.ref_pos + 1, c.who_alts.as_slice()))
            .collect();
        assert_eq!(
            who,
            [
                (2270, b"CT".as_slice()),
                (2299, b"T"),
                (2689, b"T"),
                (2746, b"A"),
                (2814, b"T"),
            ]
        );
    }

    #[test]
    fn wild_type_read_has_no_verdict_on_both_strands() {
        for read in [amplicon(), reverse_complement(&amplicon())] {
            let (verdict, calls) = susceptibility_from_hits(&identify_sequence_rrl_mtb(&read));
            assert_eq!(verdict, None);
            assert_eq!(calls.rrl_mtb.snp_calls.len(), SITES.len());
            assert!(
                calls
                    .rrl_mtb
                    .snp_calls
                    .iter()
                    .all(|c| c.query_base == Some(c.wt_base) && !c.insertion_t)
            );
            // No macrolide call for an Mtb read.
            assert!(calls.rrl.position_2058_2059.is_none() && calls.rrl.snp_calls.is_empty());
            assert!(calls.rrl_mtb.species_validated);
        }
    }

    #[test]
    fn who_and_protocol_mutations_are_resistant() {
        for change in [
            (2270, b'C'),
            (2270, b'T'),
            (2299, b'T'),
            (2689, b'T'),
            (2741, b'G'),
            (2742, b'G'),
            (2743, b'A'),
            (2746, b'A'),
            (2814, b'T'),
        ] {
            let calls = call_rrl_mtb(&mutated(&[change]));
            assert_eq!(is_susceptible_rrl_mtb(&calls), Some(false), "{change:?}");
        }
        let (verdict, calls) =
            susceptibility_from_hits(&identify_sequence_rrl_mtb(&mutated(&[(2814, b'T')])));
        assert_eq!(verdict, Some(false));
        assert_eq!(
            rrl_mtb_findings(&calls.rrl_mtb.snp_calls),
            ["G2814T (WHO, protocol 32.43604)"]
        );
    }

    #[test]
    fn protocol_pairs_need_both_halves() {
        for pair in PROTOCOL_PAIRS {
            let both = call_rrl_mtb(&mutated(&pair));
            assert_eq!(is_susceptible_rrl_mtb(&both), Some(false), "{pair:?}");
            for half in pair {
                let calls = call_rrl_mtb(&mutated(&[half]));
                assert_eq!(is_susceptible_rrl_mtb(&calls), None, "{half:?}");
                assert!(
                    calls
                        .iter()
                        .any(|c| c.call_tag().contains("part of a double mutation")),
                    "{half:?}"
                );
            }
        }
    }

    #[test]
    fn catalogued_insertion_is_resistant() {
        let mut read = amplicon();
        read.insert(INSERTION_BEFORE - START, b'T');
        for read in [read.clone(), reverse_complement(&read)] {
            assert_eq!(
                rrl_mtb_findings(&call_rrl_mtb(&read)),
                ["n.2269_2270insT (WHO)"]
            );
        }
    }

    #[test]
    fn uncovered_sites_are_reported_and_calls_survive_serialisation() {
        // Ends at position 2760, before 2810 / 2814.
        let calls = call_rrl_mtb(&RRL_H37RV[START..2760]);
        assert_eq!(calls[9].call_tag(), "A2810?");
        assert_eq!(calls[10].call_tag(), "G2814?");
        let json = serde_json::to_string(&calls).unwrap();
        let back: Vec<RrlMtbSnpCall> = serde_json::from_str(&json).unwrap();
        assert_eq!(back[0].call_tag(), calls[0].call_tag());
    }
}
