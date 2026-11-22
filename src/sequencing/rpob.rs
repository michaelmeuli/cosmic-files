//! rpoB species identification and *M. tuberculosis* rifampicin-resistance calls.
//!
//! The lab sequences four non-overlapping rpoB regions (see kansasii-docs
//! [`SANGER_RPOB.md`](https://github.com/michaelmeuli/kansasii-docs/blob/master/docs/SANGER_RPOB.md)),
//! so each [`RpoBRegion`] is aligned only against references for that region for species ID.
//!
//! For the three Mtb regions the read is additionally aligned to the H37Rv rpoB CDS and called
//! against the WHO catalogue (`tbprofiler/mutations.csv`, see [`RPOB_RIF_SITES`]): every codon
//! of the rifampicin-resistance-determining region (RRDR, codons 426–452, where the catalogue
//! rule `missense_variant_p.426_452` makes any missense change a resistance call), the
//! catalogued resistance codons outside it (V170F, I491F), and in-frame RRDR indels.
//! See [`is_susceptible_rpob`] for the verdict.

use super::pnca::{AA3, MutationRow, codon_at_ref_pos, translate_codon};
use super::tb_data::confidence_rank;
use super::{
    GappedAlignment, REF_AMPLICON_RPOB, REF_AMPLICON_RPOB_5PRIME, REF_AMPLICON_RPOB_RRDR,
    REF_AMPLICON_RPOB_XPERT, REF_MYCO_RPOB, REF_RPOB_H37RV, RefPool, SeqIdHit, align_to_ref,
    parse_fasta_seq, ref_pool, reverse_complement, sort_hits_by_identity, trim_alignment_ends,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
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

    /// `true` for the Mtb rifampicin regions, which get WHO-catalogue resistance calls.
    pub fn is_mtb(self) -> bool {
        !matches!(self, Self::Ntm)
    }
}

// ---------------------------------------------------------------------------------------------
// Rifampicin resistance (WHO catalogue)
// ---------------------------------------------------------------------------------------------

/// RRDR codons (WHO catalogue v2 numbering on H37Rv); matches the catalogue rule row
/// `missense_variant_p.426_452`.
pub const RRDR_CODONS: RangeInclusive<usize> = 426..=452;

/// The RRDR as 0-based nucleotide indices into the H37Rv rpoB CDS (c.1276–c.1356).
const RRDR_NT: RangeInclusive<usize> = (426 - 1) * 3..=452 * 3 - 1;

/// Confidence used when neither catalogue rule row can be read.
const RRDR_RULE_FALLBACK: &str = "Assoc w R - Interim";

/// Minimum identity of the read to the H37Rv rpoB CDS for calls to be made at all — below
/// this the read is not rpoB (or not this region) and codon positions would be meaningless.
/// NTM rpoB reads align at ~85–92 % and are still called (flagged via `species_validated`).
const MIN_H37RV_IDENTITY: f32 = 80.0;

/// H37Rv rpoB CDS bytes (uppercase).
static RPOB_H37RV: LazyLock<Vec<u8>> = LazyLock::new(|| {
    parse_fasta_seq(REF_RPOB_H37RV)
        .into_iter()
        .map(|b| b.to_ascii_uppercase())
        .collect()
});

/// Resistance alts per codon: alt amino acid (3-letter or `"*"`) → `(drugs, WHO confidence)`.
type AltMap = BTreeMap<String, (Vec<String>, String)>;

/// One codon the caller looks at.
#[derive(Debug, Clone)]
struct RifSite {
    codon: usize,
    /// Wild-type amino acid, translated from H37Rv.
    wt_aa: String,
    /// Catalogued alts at resistance confidence (rank < 2).
    resistance_alts: AltMap,
    /// `Some(confidence)` for RRDR codons, where any missense change is resistance.
    rrdr_rule: Option<String>,
}

/// Parsed catalogue data for rpoB.
#[derive(Debug)]
struct RifCatalogue {
    sites: Vec<RifSite>,
    /// Confidence of the in-frame RRDR indel rule rows.
    indel_confidence: String,
}

/// Parse the rpoB rows of the WHO catalogue into the sites to call: every RRDR codon, plus
/// every codon outside it with a single-substitution row at resistance confidence (rank < 2).
fn parse_rpob_catalogue(csv: &str, h37rv: &[u8]) -> RifCatalogue {
    static CODON_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^p\.([A-Za-z]{3})(\d+)([A-Za-z]{3}|\*)$").unwrap());

    let mut alts: BTreeMap<usize, AltMap> = BTreeMap::new();
    let mut rule_confidence: Option<String> = None;
    let mut indel_confidence: Option<String> = None;

    let mut rdr = csv::Reader::from_reader(csv.as_bytes());
    for row in rdr.deserialize::<MutationRow>() {
        let Ok(row) = row else { continue };
        if row.gene.trim() != "rpoB" {
            continue;
        }
        let confidence = row.confidence.trim().to_string();
        if confidence_rank(&confidence) >= 2 {
            continue;
        }
        let m = row.mutation.trim();
        if m == "missense_variant_p.426_452" {
            rule_confidence = Some(confidence);
            continue;
        }
        if m.starts_with("conservative_inframe_") && m.ends_with("c.1276_1356") {
            indel_confidence = Some(confidence);
            continue;
        }
        let Some(caps) = CODON_RE.captures(m) else {
            continue;
        };
        let alt = caps[3].to_string();
        if !AA3.contains(&&caps[1]) || (alt != "*" && !AA3.contains(&alt.as_str())) {
            continue;
        }
        let Some(codon) = caps[2].parse::<usize>().ok().filter(|&c| c > 0) else {
            continue;
        };
        let drug = row.drug.trim().to_string();
        let variant = alts
            .entry(codon)
            .or_default()
            .entry(alt)
            .or_insert_with(|| (Vec::new(), confidence.clone()));
        if !variant.0.contains(&drug) {
            variant.0.push(drug);
        }
        if confidence_rank(&confidence) < confidence_rank(&variant.1) {
            variant.1 = confidence;
        }
    }

    let rule = rule_confidence.unwrap_or_else(|| RRDR_RULE_FALLBACK.to_string());
    let wt_at = |codon: usize| {
        let i = (codon - 1) * 3;
        h37rv
            .get(i..i + 3)
            .and_then(translate_codon)
            .unwrap_or("?")
            .to_string()
    };
    let mut codons: Vec<usize> = RRDR_CODONS.collect();
    codons.extend(alts.keys().filter(|c| !RRDR_CODONS.contains(c)));
    codons.sort_unstable();
    let sites = codons
        .into_iter()
        .map(|codon| RifSite {
            codon,
            wt_aa: wt_at(codon),
            resistance_alts: alts.remove(&codon).unwrap_or_default(),
            rrdr_rule: RRDR_CODONS.contains(&codon).then(|| rule.clone()),
        })
        .collect();
    RifCatalogue {
        sites,
        indel_confidence: indel_confidence.unwrap_or(rule),
    }
}

static RPOB_RIF_SITES: LazyLock<RifCatalogue> = LazyLock::new(|| {
    parse_rpob_catalogue(include_str!("../../tbprofiler/mutations.csv"), &RPOB_H37RV)
});

/// What kind of rpoB site a [`RpobSnpCall`] is.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpobCallKind {
    /// A catalogued codon (all RRDR codons, plus V170 / I491).
    Codon {
        /// 1-based codon number (H37Rv / WHO numbering).
        codon: usize,
        /// Wild-type amino acid (3-letter code).
        wt_aa: String,
        /// Amino acid translated from the read, or `None` if the codon isn't fully covered.
        query_aa: Option<String>,
        /// `Some(confidence)` for RRDR codons: any missense change there is resistance.
        rrdr_rule: Option<String>,
    },
    /// An insertion or deletion inside the RRDR (c.1276–c.1356).
    RrdrIndel {
        /// `true` for a deletion (bases missing from the read), `false` for an insertion.
        deletion: bool,
        /// The deleted reference bases, or the inserted read bases.
        bases: String,
        /// Catalogue confidence for an in-frame RRDR indel.
        confidence: String,
    },
}

/// One rifampicin-resistance call on an rpoB read.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpobSnpCall {
    /// 0-based position in the H37Rv rpoB CDS: first base of the codon, first deleted base, or
    /// the base an insertion precedes.
    pub ref_pos: usize,
    pub kind: RpobCallKind,
    /// Catalogued resistance alts for this codon (empty for indels).
    pub resistance_alts: AltMap,
}

/// What the read showed at one site, for [`is_susceptible_rpob`].
enum RpobEvidence {
    Wildtype,
    /// Covered, differs from wildtype, but neither catalogued nor covered by a rule (or a
    /// probable read error such as a stop codon or frameshift).
    Unknown,
    /// Resistance at this confidence rank.
    Resistant(u8),
}

impl RpobSnpCall {
    /// HGVS-style label, e.g. `"p.Ser450Leu"`, `"c.1303_1305del"` or `"c.1296_1297insTTC"`.
    pub fn site_label(&self) -> String {
        match &self.kind {
            RpobCallKind::Codon {
                codon,
                wt_aa,
                query_aa,
                ..
            } => format!("p.{wt_aa}{codon}{}", query_aa.as_deref().unwrap_or("?")),
            RpobCallKind::RrdrIndel {
                deletion: true,
                bases,
                ..
            } => {
                let start = self.ref_pos + 1;
                let end = self.ref_pos + bases.len();
                if start == end {
                    format!("c.{start}del")
                } else {
                    format!("c.{start}_{end}del")
                }
            }
            RpobCallKind::RrdrIndel {
                deletion: false,
                bases,
                ..
            } => format!("c.{}_{}ins{bases}", self.ref_pos, self.ref_pos + 1),
        }
    }

    /// Annotation for the observed allele: empty for wildtype / uncovered codons.
    pub fn call_tag(&self) -> String {
        match &self.kind {
            RpobCallKind::Codon {
                wt_aa,
                query_aa,
                rrdr_rule,
                ..
            } => match query_aa {
                None => String::new(),
                Some(aa) if aa == wt_aa => String::new(),
                Some(aa) if aa == "*" => "stop codon (check read)".to_string(),
                Some(aa) => match (self.resistance_alts.get(aa), rrdr_rule) {
                    (Some((drugs, conf)), _) => format!("({}, {conf})", drugs.join(", ")),
                    (None, Some(conf)) => format!("(rifampicin, {conf}, RRDR rule)"),
                    (None, None) => format!("{aa} (mutation, untested)"),
                },
            },
            RpobCallKind::RrdrIndel {
                bases, confidence, ..
            } => {
                if bases.len() % 3 == 0 {
                    format!("(rifampicin, {confidence}, in-frame RRDR indel)")
                } else {
                    "frameshift (check read)".to_string()
                }
            }
        }
    }

    /// `None` when the read doesn't cover this codon.
    fn evidence(&self) -> Option<RpobEvidence> {
        match &self.kind {
            RpobCallKind::Codon {
                wt_aa,
                query_aa,
                rrdr_rule,
                ..
            } => {
                let aa = query_aa.as_ref()?;
                Some(if aa == wt_aa {
                    RpobEvidence::Wildtype
                } else if aa == "*" {
                    RpobEvidence::Unknown
                } else if let Some((_, conf)) = self.resistance_alts.get(aa) {
                    RpobEvidence::Resistant(confidence_rank(conf))
                } else if let Some(conf) = rrdr_rule {
                    RpobEvidence::Resistant(confidence_rank(conf))
                } else {
                    RpobEvidence::Unknown
                })
            }
            RpobCallKind::RrdrIndel {
                bases, confidence, ..
            } => Some(if bases.len() % 3 == 0 {
                RpobEvidence::Resistant(confidence_rank(confidence))
            } else {
                RpobEvidence::Unknown
            }),
        }
    }

    fn is_rrdr_codon(&self) -> bool {
        matches!(
            &self.kind,
            RpobCallKind::Codon {
                rrdr_rule: Some(_),
                ..
            }
        )
    }
}

/// Rifampicin calls for one sample, ready for UI display and export.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RpobSusceptibilityCalls {
    /// Every site the caller looked at (uncovered codons included), plus RRDR indels.
    pub snp_calls: Vec<RpobSnpCall>,
    /// Verdict from [`is_susceptible_rpob`].
    pub is_susceptible: Option<bool>,
    /// `false` when the read's best species hit isn't *M. tuberculosis*: the WHO catalogue
    /// applies only to the *M. tuberculosis* complex, so the calls are indicative only.
    pub species_validated: bool,
}

/// `Some(false)` when any site shows resistance at confidence rank < 2 (a catalogued alt, any
/// missense change in the RRDR, or an in-frame RRDR indel). `Some(true)` only when all 27
/// RRDR codons are covered and wildtype (synonymous changes allowed) and nothing else unclear
/// was seen. Otherwise `None` — e.g. a 5'-region (Tb176) read, which doesn't reach the RRDR.
pub fn is_susceptible_rpob(calls: &[RpobSnpCall]) -> Option<bool> {
    let mut rrdr_wildtype = 0usize;
    let mut unknown = false;
    for call in calls {
        match call.evidence() {
            Some(RpobEvidence::Resistant(rank)) if rank < 2 => return Some(false),
            Some(RpobEvidence::Resistant(_) | RpobEvidence::Unknown) => unknown = true,
            Some(RpobEvidence::Wildtype) if call.is_rrdr_codon() => rrdr_wildtype += 1,
            Some(RpobEvidence::Wildtype) | None => {}
        }
    }
    (rrdr_wildtype == RRDR_CODONS.count() && !unknown).then_some(true)
}

/// Collect indels inside the RRDR from a gapped alignment against the H37Rv rpoB CDS.
fn rrdr_indels(ga: &GappedAlignment, confidence: &str) -> Vec<RpobSnpCall> {
    let mut calls: Vec<RpobSnpCall> = Vec::new();
    let mut ref_pos = ga.ref_start;
    // (deletion, start ref_pos, bases) of the indel run being built.
    let mut run: Option<(bool, usize, String)> = None;
    let flush = |run: &mut Option<(bool, usize, String)>, calls: &mut Vec<RpobSnpCall>| {
        if let Some((deletion, pos, bases)) = run.take()
            && RRDR_NT.contains(&pos)
        {
            calls.push(RpobSnpCall {
                ref_pos: pos,
                kind: RpobCallKind::RrdrIndel {
                    deletion,
                    bases,
                    confidence: confidence.to_string(),
                },
                resistance_alts: AltMap::new(),
            });
        }
    };
    for (&q, &r) in ga.gapped_query.iter().zip(&ga.gapped_ref) {
        let col = match (q == b'-', r == b'-') {
            (true, false) => Some((true, r)),
            (false, true) => Some((false, q)),
            _ => None,
        };
        match col {
            Some((deletion, base)) => {
                let base = base.to_ascii_uppercase() as char;
                match &mut run {
                    Some(cur) if cur.0 == deletion => cur.2.push(base),
                    _ => {
                        flush(&mut run, &mut calls);
                        run = Some((deletion, ref_pos, base.to_string()));
                    }
                }
            }
            None => flush(&mut run, &mut calls),
        }
        if r != b'-' {
            ref_pos += 1;
        }
    }
    flush(&mut run, &mut calls);
    calls
}

/// Align `query` (either strand) to the H37Rv rpoB CDS and call every rifampicin site.
/// Returns no calls when the read doesn't align to rpoB at [`MIN_H37RV_IDENTITY`].
pub fn call_rpob_rif(query: &[u8]) -> Vec<RpobSnpCall> {
    let reference = &*RPOB_H37RV;
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
    let catalogue = &*RPOB_RIF_SITES;
    let mut calls: Vec<RpobSnpCall> = catalogue
        .sites
        .iter()
        .map(|site| {
            let ref_pos = (site.codon - 1) * 3;
            let query_aa =
                codon_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos)
                    .and_then(|bases| translate_codon(&bases).map(str::to_string));
            RpobSnpCall {
                ref_pos,
                kind: RpobCallKind::Codon {
                    codon: site.codon,
                    wt_aa: site.wt_aa.clone(),
                    query_aa,
                    rrdr_rule: site.rrdr_rule.clone(),
                },
                resistance_alts: site.resistance_alts.clone(),
            }
        })
        .collect();
    calls.extend(rrdr_indels(&ga, &catalogue.indel_confidence));
    calls.sort_by_key(|c| c.ref_pos);
    calls
}

/// NTM region: NCBI type material plus the GTDB 2573f/3337r amplicon references, both
/// ≥ [`super::MIN_RPOB_REF_LEN`] (drops partial sequences too short to separate species).
static RPOB_REFS_NTM: LazyLock<RefPool> = LazyLock::new(|| {
    ref_pool(&[REF_MYCO_RPOB], &[REF_AMPLICON_RPOB], |seq| {
        seq.len() >= super::MIN_RPOB_REF_LEN
    })
});

/// Mtb regions: only the GTDB amplicon references for that region. Most NCBI rpoB entries are
/// partial sequences of the NTM region and don't cover these, and the amplicons are shorter
/// than `MIN_RPOB_REF_LEN` by design (Xpert 146–192 bp, Tb176 365 bp), so no length filter.
static RPOB_REFS_RRDR: LazyLock<RefPool> =
    LazyLock::new(|| ref_pool(&[], &[REF_AMPLICON_RPOB_RRDR], |_| true));
static RPOB_REFS_5PRIME: LazyLock<RefPool> =
    LazyLock::new(|| ref_pool(&[], &[REF_AMPLICON_RPOB_5PRIME], |_| true));
static RPOB_REFS_XPERT: LazyLock<RefPool> =
    LazyLock::new(|| ref_pool(&[], &[REF_AMPLICON_RPOB_XPERT], |_| true));

fn refs_for(region: RpoBRegion) -> &'static RefPool {
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
/// For the Mtb regions the top hit also carries the rifampicin calls ([`call_rpob_rif`]).
pub fn identify_sequence_rpob(query: &[u8], region: RpoBRegion) -> Vec<SeqIdHit> {
    let rc = reverse_complement(query);
    let mut hits: Vec<SeqIdHit> = refs_for(region)
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
    if region.is_mtb()
        && let Some(top) = hits.first_mut()
    {
        top.rpob_snp_calls = call_rpob_rif(query);
    }
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
                    .any(|(_, _, desc, _)| desc.starts_with("Mycobacterium tuberculosis")),
                "{region:?} has no M. tuberculosis reference"
            );
        }
    }

    #[test]
    fn mtb_xpert_read_identifies_tuberculosis() {
        let (_, _, _, mtb) = RPOB_REFS_XPERT
            .iter()
            .find(|(_, _, desc, _)| desc.starts_with("Mycobacterium tuberculosis"))
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

    // --- rifampicin calls -------------------------------------------------------------------

    /// H37Rv rpoB nucleotides for codons `first..=last`.
    fn read(first: usize, last: usize) -> Vec<u8> {
        RPOB_H37RV[(first - 1) * 3..last * 3].to_vec()
    }

    /// Replace codon `codon` in a read starting at codon `first`.
    fn set_codon(read: &mut [u8], first: usize, codon: usize, bases: &[u8; 3]) {
        let i = (codon - first) * 3;
        read[i..i + 3].copy_from_slice(bases);
    }

    fn wt_codon(codon: usize) -> [u8; 3] {
        let i = (codon - 1) * 3;
        RPOB_H37RV[i..i + 3].try_into().unwrap()
    }

    fn labels(calls: &[RpobSnpCall]) -> Vec<String> {
        calls
            .iter()
            .filter(|c| !c.call_tag().is_empty())
            .map(|c| format!("{} {}", c.site_label(), c.call_tag()))
            .collect()
    }

    #[test]
    fn h37rv_reference_matches_catalogue_wildtype() {
        assert_eq!(RPOB_H37RV.len(), 3519);
        for (codon, aa) in [
            (170, "Val"),
            (426, "Gly"),
            (435, "Asp"),
            (440, "Leu"),
            (445, "His"),
            (450, "Ser"),
            (452, "Leu"),
            (491, "Ile"),
        ] {
            assert_eq!(translate_codon(&wt_codon(codon)), Some(aa), "codon {codon}");
        }
    }

    #[test]
    fn catalogue_sites() {
        assert!(
            include_str!("../../tbprofiler/mutations.csv").contains("missense_variant_p.426_452")
        );
        let cat = &*RPOB_RIF_SITES;
        let rrdr: Vec<&RifSite> = cat.sites.iter().filter(|s| s.rrdr_rule.is_some()).collect();
        assert_eq!(rrdr.len(), RRDR_CODONS.count());
        assert!(
            rrdr.iter()
                .all(|s| s.rrdr_rule.as_deref() == Some("Assoc w R - Interim"))
        );
        for (codon, alt) in [(170, "Phe"), (491, "Phe")] {
            let site = cat.sites.iter().find(|s| s.codon == codon).expect("site");
            assert!(site.rrdr_rule.is_none());
            assert!(site.resistance_alts.contains_key(alt), "{codon}{alt}");
        }
        assert_eq!(cat.indel_confidence, "Assoc w R - Interim");
    }

    #[test]
    fn wildtype_rrdr_read_is_susceptible_on_both_strands() {
        let r = read(400, 520);
        let calls = call_rpob_rif(&r);
        assert!(labels(&calls).is_empty(), "{:?}", labels(&calls));
        assert_eq!(is_susceptible_rpob(&calls), Some(true));
        assert_eq!(
            is_susceptible_rpob(&call_rpob_rif(&reverse_complement(&r))),
            Some(true)
        );
    }

    #[test]
    fn s450l_is_resistant() {
        let mut r = read(400, 520);
        set_codon(&mut r, 400, 450, b"TTG");
        let calls = call_rpob_rif(&r);
        assert_eq!(is_susceptible_rpob(&calls), Some(false));
        let l = labels(&calls);
        assert!(
            l.iter()
                .any(|s| s.starts_with("p.Ser450Leu (rifampicin, Assoc w R")),
            "{l:?}"
        );
    }

    #[test]
    fn uncatalogued_rrdr_missense_is_resistant_by_rule_synonymous_is_not() {
        let mut r = read(400, 520);
        set_codon(&mut r, 400, 440, b"GCC"); // Leu440Ala
        let calls = call_rpob_rif(&r);
        assert_eq!(is_susceptible_rpob(&calls), Some(false));
        assert!(
            labels(&calls)
                .iter()
                .any(|s| s.contains("p.Leu440Ala") && s.contains("RRDR rule"))
        );

        let mut r = read(400, 520);
        let mut syn = wt_codon(450);
        syn[2] = if syn[2] == b'A' { b'C' } else { b'A' }; // Ser is TCN: any third base
        assert_eq!(translate_codon(&syn), Some("Ser"));
        set_codon(&mut r, 400, 450, &syn);
        assert_eq!(is_susceptible_rpob(&call_rpob_rif(&r)), Some(true));
    }

    #[test]
    fn rrdr_indels() {
        // In-frame deletion of codon 437 → resistant.
        let mut r = read(400, 520);
        let i = (437 - 400) * 3;
        r.drain(i..i + 3);
        let calls = call_rpob_rif(&r);
        assert_eq!(
            is_susceptible_rpob(&calls),
            Some(false),
            "{:?}",
            labels(&calls)
        );
        assert!(calls.iter().any(|c| matches!(
            &c.kind,
            RpobCallKind::RrdrIndel { deletion: true, bases, .. } if bases.len() == 3
        )));

        // 1-nt deletion (frameshift) → no verdict, flagged as a probable read error.
        let mut r = read(400, 520);
        r.remove((440 - 400) * 3 + 1);
        let calls = call_rpob_rif(&r);
        assert_eq!(is_susceptible_rpob(&calls), None);
        assert!(labels(&calls).iter().any(|s| s.contains("frameshift")));
    }

    #[test]
    fn partial_rrdr_or_5prime_read_gives_no_susceptible_verdict() {
        assert_eq!(is_susceptible_rpob(&call_rpob_rif(&read(380, 440))), None);
        assert_eq!(is_susceptible_rpob(&call_rpob_rif(&read(120, 220))), None);

        let mut r = read(120, 220);
        set_codon(&mut r, 120, 170, b"TTC"); // Val170Phe
        let calls = call_rpob_rif(&r);
        assert_eq!(is_susceptible_rpob(&calls), Some(false));
        assert!(labels(&calls).iter().any(|s| s.starts_with("p.Val170Phe")));
    }

    #[test]
    fn identify_attaches_calls_and_species_flag() {
        use crate::sequencing::batch::rpob_susceptibility_calls;

        let hits = identify_sequence_rpob(&read(400, 520), RpoBRegion::MtbRrdr);
        let calls = rpob_susceptibility_calls(&hits[0]);
        assert!(calls.species_validated, "top hit {}", hits[0].description);
        assert_eq!(calls.is_susceptible, Some(true));

        // An NTM TR1/TR2b amplicon is still called, but flagged.
        let (_, _, _, avium) = RPOB_REFS_RRDR
            .iter()
            .find(|(_, _, desc, _)| desc == "Mycobacterium avium")
            .expect("M. avium RRDR reference");
        let hits = identify_sequence_rpob(avium, RpoBRegion::MtbRrdr);
        assert!(!rpob_susceptibility_calls(&hits[0]).species_validated);

        // The NTM species-ID region gets no rifampicin calls.
        let hits = identify_sequence_rpob(&read(400, 520), RpoBRegion::Ntm);
        assert!(hits[0].rpob_snp_calls.is_empty());
    }
}
