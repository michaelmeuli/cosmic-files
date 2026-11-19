//! hsp65/groEL2 species identification and discrimination.
//!
//! Aligns a trimmed hsp65 read against the pooled hsp65 references ([`REF_MYCO_HSP65`]: NCBI
//! type material + [ntm-db](https://github.com/pathogen-profiler/ntm-db), built at compile
//! time; plus the [`REF_AMPLICON_HSP65`] TB11/TB12 amplicons) to find the best-matching
//! mycobacterial reference (see [`identify_sequence_hsp65`]). hsp65 alone cannot always separate
//! two closely related species pairs, so once a hit is identified as one of those pairs, a small
//! fixed set of diagnostic SNP positions is checked against the alignment to call the specific
//! species:
//!
//! - *M. kansasii* vs *M. gastri* ([`KANSASII_GASTRI`], [`KansasiiGastriSnpCall`])
//! - *M. marinum* vs *M. ulcerans* ([`MARINUM_ULCERANS`], [`MarinumUlceransSnpCall`])
//!
//! The SNP positions are offsets into four specific GenBank partial-cds entries, not into the
//! full-length or amplicon references. Only hits on exactly those accessions get SNP calls, and
//! they are exempt from substring dedup (see [`super::hsp65_snp_refs`]). `build.rs`
//! (`check_hsp65_integrity`) checks each entry's length and its alleles at build time.

use super::hsp65_snp_refs::{HSP65_SNP_PAIRS, KANSASII_GASTRI, MARINUM_ULCERANS};
use super::reverse_complement;
use super::{
    GappedAlignment, REF_AMPLICON_HSP65, REF_MYCO_HSP65, SeqIdHit, align_to_ref, base_at_ref_pos,
    dedup_substring_same_desc, parse_multi_fasta, trim_alignment_ends,
};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// Diagnostic positions distinguishing *M. kansasii* from *M. gastri*, as
/// `(0-based ref pos, gastri_base, kansasii_base)`.
const KANSASII_GASTRI_SNPS: &[(usize, u8, u8)] = KANSASII_GASTRI.snps;

/// Diagnostic positions distinguishing *M. marinum* from *M. ulcerans*, as
/// `(0-based ref pos, marinum_base, ulcerans_base)`.
const MARINUM_ULCERANS_SNPS: &[(usize, u8, u8)] = MARINUM_ULCERANS.snps;

/// Whether `accession` (version suffix stripped) is one of `pair`'s SNP coordinate references.
fn is_ref_of(pair: &super::hsp65_snp_refs::Hsp65SnpPair, accession: &str) -> bool {
    pair.refs.iter().any(|r| r.accession == accession)
}

/// Whether `raw_accession` (with or without version suffix) is any hsp65 SNP reference.
fn is_snp_ref_accession(raw_accession: &str) -> bool {
    let acc = raw_accession.split('.').next().unwrap_or(raw_accession);
    HSP65_SNP_PAIRS.iter().any(|pair| is_ref_of(pair, acc))
}

/// Reads the query base at each [`KANSASII_GASTRI_SNPS`] position out of an existing alignment.
/// Positions that fall outside the aligned region (or land on a gap) are silently dropped.
fn call_kansasii_gastri_snps(ga: &GappedAlignment) -> Vec<KansasiiGastriSnpCall> {
    KANSASII_GASTRI_SNPS
        .iter()
        .filter_map(|&(ref_pos, gastri_base, kansasii_base)| {
            let query_base =
                base_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos)?;
            Some(KansasiiGastriSnpCall {
                ref_pos,
                query_base,
                gastri_base,
                kansasii_base,
            })
        })
        .collect()
}

/// Reads the query base at each [`MARINUM_ULCERANS_SNPS`] position out of an existing alignment.
/// Positions that fall outside the aligned region (or land on a gap) are silently dropped.
fn call_marinum_ulcerans_snps(ga: &GappedAlignment) -> Vec<MarinumUlceransSnpCall> {
    MARINUM_ULCERANS_SNPS
        .iter()
        .filter_map(|&(ref_pos, marinum_base, ulcerans_base)| {
            let query_base =
                base_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos)?;
            Some(MarinumUlceransSnpCall {
                ref_pos,
                query_base,
                marinum_base,
                ulcerans_base,
            })
        })
        .collect()
}

/// Parsed and substring-deduplicated hsp65 reference sequences, initialised once.
///
/// The SNP coordinate references are kept out of dedup. A longer same-species entry that
/// contains one of them (e.g. a 441 bp TB11/TB12 amplicon around a 424 bp GenBank entry) would
/// otherwise remove it, and SNP calls would silently disappear.
static HSP65_REFS: LazyLock<Vec<(String, String, Vec<u8>)>> = LazyLock::new(|| {
    let mut refs = parse_multi_fasta(REF_MYCO_HSP65);
    refs.extend(parse_multi_fasta(REF_AMPLICON_HSP65));
    let (mut snp_refs, others): (Vec<_>, Vec<_>) = refs
        .into_iter()
        .partition(|(acc, _, _)| is_snp_ref_accession(acc));
    snp_refs.extend(dedup_substring_same_desc(others));
    snp_refs
});

/// Trim hsp65 amplification primers from a sequencing read.
///
/// Unlike [`trim_start_end`](super::trim_start_end), which takes a single primer per boundary,
/// hsp65 amplification uses two alternative primer pairs (Telenti and Patel sets), so each
/// boundary is defined by a *set* of candidates — the earliest match wins for the start and the
/// latest for the end.
pub fn trim_hsp65_primers(seq: &[u8]) -> Vec<u8> {
    const FWD_START: &[&[u8]] = &[b"ATGGTGTGTCCATCGCCAAG", b"GAGGACCCGTACGAGAAGATCGGCGCTGA"];
    const FWD_END: &[&[u8]] = &[b"GAGCTCACCGAGGGTATGCG", b"CGCTGTCCACCCTGGTCGTC"];

    // On an RC-strand query the start primers appear as RC(end primers) and vice versa,
    // so we search both orientations for each boundary.
    let rc_start: Vec<Vec<u8>> = FWD_END.iter().map(|p| reverse_complement(p)).collect();
    let rc_end: Vec<Vec<u8>> = FWD_START.iter().map(|p| reverse_complement(p)).collect();

    let find_start = |p: &[u8]| seq.windows(p.len()).position(|w| w.eq_ignore_ascii_case(p));
    let find_end = |p: &[u8]| {
        seq.windows(p.len())
            .rposition(|w| w.eq_ignore_ascii_case(p))
            .map(|pos| pos + p.len())
    };

    let start = FWD_START
        .iter()
        .map(|p| p as &[u8])
        .chain(rc_start.iter().map(|p| p.as_slice()))
        .filter_map(find_start)
        .min()
        .unwrap_or(0);

    let end = FWD_END
        .iter()
        .map(|p| p as &[u8])
        .chain(rc_end.iter().map(|p| p.as_slice()))
        .filter_map(find_end)
        .max()
        .unwrap_or(seq.len());

    seq[start..end.min(seq.len())].to_vec()
}

/// Identifies the closest-matching mycobacterial species for an hsp65 read.
///
/// Trims amplification primers, aligns both strands of `query` against every reference in
/// [`HSP65_REFS`], and returns one [`SeqIdHit`] per reference sorted by descending identity so
/// the caller can inspect the best match (and runners-up/ties). For hits on the
/// kansasii/gastri or marinum/ulcerans reference pairs, the corresponding diagnostic SNP calls
/// are populated ([`KansasiiGastriSnpCall`] / [`MarinumUlceransSnpCall`]); all other `SeqIdHit`
/// SNP fields are left empty.
///
/// The reference database is generated at build time by filtering NCBI Nucleotide for
/// `Mycobacteriaceae[Organism] AND (hsp65[Gene Name] OR groEL2[Gene Name]) AND 400:3000[SLEN]
/// AND type_material[Filter]` (`fetch_myco_sequences()` in `build.rs`), plus the hsp65
/// sequences found in [ntm-db](https://github.com/pathogen-profiler/ntm-db)
/// (`extract_species_gff_sequences()` in `build.rs`), plus the committed TB11/TB12 amplicons
/// ([`REF_AMPLICON_HSP65`]).
pub fn identify_sequence_hsp65(query: &[u8]) -> Vec<SeqIdHit> {
    let query = trim_hsp65_primers(query);
    let query = query.as_slice();
    let rc = reverse_complement(query);

    let mut hits: Vec<SeqIdHit> = HSP65_REFS
        .iter()
        .map(|(raw_acc, description, refseq)| {
            // Strip version suffix so SNP dispatch and is_kansasii() etc. work correctly.
            let accession = raw_acc
                .rsplit_once('.')
                .map(|(base, _)| base.to_string())
                .unwrap_or_else(|| raw_acc.clone());
            let fwd = align_to_ref(query, refseq);
            let rev = align_to_ref(&rc, refseq);
            let (ga, is_reverse) = if rev.identity > fwd.identity {
                (rev, true)
            } else {
                (fwd, false)
            };
            let ga = trim_alignment_ends(ga);
            let kansasii_gastri_snp_calls = if is_ref_of(&KANSASII_GASTRI, &accession) {
                call_kansasii_gastri_snps(&ga)
            } else {
                vec![]
            };
            let marinum_ulcerans_snp_calls = if is_ref_of(&MARINUM_ULCERANS, &accession) {
                call_marinum_ulcerans_snps(&ga)
            } else {
                vec![]
            };
            SeqIdHit {
                accession,
                description: description.clone(),
                identity: ga.identity,
                is_reverse,
                kansasii_gastri_snp_calls,
                marinum_ulcerans_snp_calls,
                rrl_snp_calls: vec![],
                rrs_snp_calls: vec![],
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

    hits.sort_by(|a, b| {
        b.identity
            .partial_cmp(&a.identity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hits
}

/// A single diagnostic SNP position in the kansasii/gastri comparison.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KansasiiGastriSnpCall {
    /// 0-based position in the reference sequence.
    pub ref_pos: usize,
    /// Base observed in the query at this position (uppercase ASCII).
    pub query_base: u8,
    /// Expected base for M. gastri (uppercase ASCII).
    pub gastri_base: u8,
    /// Expected base for M. kansasii (uppercase ASCII).
    pub kansasii_base: u8,
}

impl KansasiiGastriSnpCall {
    /// Whether the query base at this position matches the *M. gastri* allele.
    pub fn is_gastri(&self) -> bool {
        self.query_base == self.gastri_base
    }
    /// Whether the query base at this position matches the *M. kansasii* allele.
    pub fn is_kansasii(&self) -> bool {
        self.query_base == self.kansasii_base
    }
    /// Human-readable species tag: "M. gastri", "M. kansasii", or "?".
    pub fn species_tag(&self) -> &'static str {
        if self.is_gastri() {
            "M. gastri"
        } else if self.is_kansasii() {
            "M. kansasii"
        } else {
            "?"
        }
    }
}

/// A single diagnostic SNP position in the marinum/ulcerans comparison.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarinumUlceransSnpCall {
    /// 0-based position in the reference sequence.
    pub ref_pos: usize,
    /// Base observed in the query at this position (uppercase ASCII).
    pub query_base: u8,
    /// Expected base for M. marinum (uppercase ASCII).
    pub marinum_base: u8,
    /// Expected base for M. ulcerans (uppercase ASCII).
    pub ulcerans_base: u8,
}

impl MarinumUlceransSnpCall {
    /// Whether the query base at this position matches the *M. marinum* allele.
    pub fn is_marinum(&self) -> bool {
        self.query_base == self.marinum_base
    }
    /// Whether the query base at this position matches the *M. ulcerans* allele.
    pub fn is_ulcerans(&self) -> bool {
        self.query_base == self.ulcerans_base
    }
    /// Human-readable species tag: "M. marinum", "M. ulcerans", or "?".
    pub fn species_tag(&self) -> &'static str {
        if self.is_marinum() {
            "M. marinum"
        } else if self.is_ulcerans() {
            "M. ulcerans"
        } else {
            "?"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every SNP coordinate reference must survive into `HSP65_REFS` (i.e. not be removed by
    /// substring dedup), with the expected length and the expected allele at every position.
    #[test]
    fn snp_refs_survive_dedup_and_match_alleles() {
        for pair in HSP65_SNP_PAIRS {
            for (i, snp_ref) in pair.refs.iter().enumerate() {
                let (_, desc, seq) = HSP65_REFS
                    .iter()
                    .find(|(acc, _, _)| acc.split('.').next() == Some(snp_ref.accession))
                    .unwrap_or_else(|| panic!("{} missing from HSP65_REFS", snp_ref.accession));
                assert_eq!(desc, snp_ref.species, "{}", snp_ref.accession);
                assert_eq!(seq.len(), snp_ref.len, "{}", snp_ref.accession);
                for &(pos, a0, a1) in pair.snps {
                    let expected = if i == 0 { a0 } else { a1 };
                    assert_eq!(
                        seq[pos].to_ascii_uppercase(),
                        expected,
                        "{} pos {pos}",
                        snp_ref.accession
                    );
                }
            }
        }
    }

    /// Each reference, aligned against itself, must call its own species at every position.
    #[test]
    fn snp_refs_call_their_own_species() {
        let seq_of = |acc: &str| {
            HSP65_REFS
                .iter()
                .find(|(a, _, _)| a.split('.').next() == Some(acc))
                .map(|(_, _, s)| s.clone())
                .unwrap()
        };
        let gastri = seq_of(KANSASII_GASTRI.refs[0].accession);
        let ga = align_to_ref(&gastri, &gastri);
        let calls = call_kansasii_gastri_snps(&ga);
        assert_eq!(calls.len(), KANSASII_GASTRI_SNPS.len());
        assert!(calls.iter().all(KansasiiGastriSnpCall::is_gastri));

        let ulcerans = seq_of(MARINUM_ULCERANS.refs[1].accession);
        let ga = align_to_ref(&ulcerans, &ulcerans);
        let calls = call_marinum_ulcerans_snps(&ga);
        assert_eq!(calls.len(), MARINUM_ULCERANS_SNPS.len());
        assert!(calls.iter().all(MarinumUlceransSnpCall::is_ulcerans));
    }
}
