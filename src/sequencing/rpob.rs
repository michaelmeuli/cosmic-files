//! rpoB species identification.
//!
//! rpoB is used purely for species-level identification here (unlike hsp65, erm41, rrl, and
//! rrs, it carries no diagnostic SNP calls in [`SeqIdHit`] — those fields are always left empty).
//!
//! The lab sequences four non-overlapping rpoB regions (see kansasii-docs
//! [`SANGER_RPOB.md`](https://github.com/michaelmeuli/kansasii-docs/blob/master/docs/SANGER_RPOB.md)),
//! so each [`RpoBRegion`] is aligned only against references for that region.

use super::{
    REF_AMPLICON_RPOB, REF_AMPLICON_RPOB_5PRIME, REF_AMPLICON_RPOB_RRDR, REF_AMPLICON_RPOB_XPERT,
    REF_MYCO_RPOB, SeqIdHit, align_to_ref, dedup_substring_same_desc, parse_multi_fasta,
    reverse_complement, sort_hits_by_identity, trim_alignment_ends,
};
use std::sync::LazyLock;

/// rpoB region a read covers, inferred from its filename (see
/// [`parse_ab1_filename`](super::ab1_filename::parse_ab1_filename)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RpoBRegion {
    /// NTM species-ID region, rpoB-2573f / rpoB-3337r (protocol 32.43504).
    Ntm,
    /// Mtb 81-bp core region (RRDR), TR1 / TR2b (protocol 32.43612).
    MtbRrdr,
    /// Mtb 5' region outside the RRDR, Tb176-f / Tb176-r (protocol 32.43619).
    Mtb5Prime,
    /// GeneXpert MTB/RIF region, rpoB-F1/F2 + rpoB-R/R2 (research protocol NZM 21).
    MtbXpert,
}

impl RpoBRegion {
    /// Gene label stored in the scan record (and therefore in the disk cache, CSV and PDF).
    /// The NTM region keeps the plain `"rpoB"` label used before regions were distinguished.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ntm => "rpoB",
            Self::MtbRrdr => "rpoB RRDR",
            Self::Mtb5Prime => "rpoB 5'",
            Self::MtbXpert => "rpoB Xpert",
        }
    }

    /// Lab protocol the region is sequenced with, shown as the preview heading.
    pub fn protocol(self) -> &'static str {
        match self {
            Self::Ntm => "32.43504-3-Mykobakterien NTM rpob-seq",
            Self::MtbRrdr => "32.43612-2-Mtb-Komplex rpoB-81bp-Coreregion Rifampicin",
            Self::Mtb5Prime => "32.43619-2-Mtb-Komplex rpoB-5'End-Region",
            Self::MtbXpert => "NZM 21-MTB-Komplex rpoB-seq aus MTB-RIF GeneXpert",
        }
    }
}

type Refs = Vec<(String, String, Vec<u8>)>;

/// NTM region: NCBI type material (≥ [`super::MIN_RPOB_REF_LEN`], which drops partial
/// sequences too short to separate species) plus the 2573f/3337r amplicon references.
static RPOB_REFS_NTM: LazyLock<Refs> = LazyLock::new(|| {
    let mut refs = parse_multi_fasta(REF_MYCO_RPOB);
    refs.extend(parse_multi_fasta(REF_AMPLICON_RPOB));
    refs.retain(|(_, _, seq)| seq.len() >= super::MIN_RPOB_REF_LEN);
    dedup_substring_same_desc(refs)
});

/// Mtb regions: only the amplicon references for that region. Most NCBI rpoB entries are
/// partial sequences of the NTM region and don't cover these, and the amplicons are shorter
/// than `MIN_RPOB_REF_LEN` by design (Xpert 146–192 bp, Tb176 365 bp), so no length filter.
static RPOB_REFS_RRDR: LazyLock<Refs> =
    LazyLock::new(|| dedup_substring_same_desc(parse_multi_fasta(REF_AMPLICON_RPOB_RRDR)));
static RPOB_REFS_5PRIME: LazyLock<Refs> =
    LazyLock::new(|| dedup_substring_same_desc(parse_multi_fasta(REF_AMPLICON_RPOB_5PRIME)));
static RPOB_REFS_XPERT: LazyLock<Refs> =
    LazyLock::new(|| dedup_substring_same_desc(parse_multi_fasta(REF_AMPLICON_RPOB_XPERT)));

fn refs_for(region: RpoBRegion) -> &'static Refs {
    match region {
        RpoBRegion::Ntm => &RPOB_REFS_NTM,
        RpoBRegion::MtbRrdr => &RPOB_REFS_RRDR,
        RpoBRegion::Mtb5Prime => &RPOB_REFS_5PRIME,
        RpoBRegion::MtbXpert => &RPOB_REFS_XPERT,
    }
}

/// Identifies the closest-matching mycobacterial species for an rpoB read of `region`.
///
/// Aligns both strands of `query` against every reference for that region and returns one
/// [`SeqIdHit`] per reference sorted by descending identity (ties: longer reference first).
pub fn identify_sequence_rpob(query: &[u8], region: RpoBRegion) -> Vec<SeqIdHit> {
    let rc = reverse_complement(query);
    let mut hits: Vec<SeqIdHit> = refs_for(region)
        .iter()
        .map(|(accession, description, refseq)| {
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
                identity: ga.identity,
                is_reverse,
                kansasii_gastri_snp_calls: vec![],
                marinum_ulcerans_snp_calls: vec![],
                rrl_snp_calls: vec![],
                rrs_snp_calls: vec![],
                rrs_snp_calls_3end: vec![],
                erm41_snp_calls: vec![],
                pnca_snp_calls: vec![],
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
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_region_has_mtb_references() {
        for region in [
            RpoBRegion::Ntm,
            RpoBRegion::MtbRrdr,
            RpoBRegion::Mtb5Prime,
            RpoBRegion::MtbXpert,
        ] {
            let refs = refs_for(region);
            assert!(!refs.is_empty(), "{region:?} has no references");
            assert!(
                refs.iter()
                    .any(|(_, desc, _)| desc.starts_with("Mycobacterium tuberculosis")),
                "{region:?} has no M. tuberculosis reference"
            );
        }
    }

    #[test]
    fn mtb_xpert_read_identifies_tuberculosis() {
        let (_, _, mtb) = RPOB_REFS_XPERT
            .iter()
            .find(|(_, desc, _)| desc.starts_with("Mycobacterium tuberculosis"))
            .expect("Mtb Xpert reference");
        let hits = identify_sequence_rpob(&reverse_complement(mtb), RpoBRegion::MtbXpert);
        // MTBC members can share the amplicon exactly, so look among all top-identity ties.
        let top = hits[0].identity;
        assert!((top - 100.0).abs() < f32::EPSILON, "top identity {top}");
        assert!(
            hits.iter()
                .take_while(|h| (h.identity - top).abs() < f32::EPSILON)
                .any(|h| h.is_reverse && h.description.starts_with("Mycobacterium tuberculosis")),
            "no reverse-strand M. tuberculosis hit among the top ties"
        );
    }
}
