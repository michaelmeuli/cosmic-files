use super::reverse_complement;
use super::{best_alignment, parse_fasta, SeqIdHit};

/// Diagnostic SNPs between M. gastri (AF547836) and M. kansasii (AF547849),
/// defined at 0-based positions in the aligned hsp65 reference sequences.
/// Both references are 423 bp with no indels, so positions are identical in both.
const KANSASII_GASTRI_SNPS: &[(usize, u8, u8)] = &[
    // (0-based ref pos, gastri_base, kansasii_base)
    (100, b'C', b'T'),
    (130, b'C', b'T'),
    (148, b'G', b'A'),
    (193, b'G', b'C'),
    (283, b'C', b'G'),
    (304, b'T', b'C'),
    (349, b'G', b'C'),
    (399, b'G', b'A'),
];

/// Diagnostic SNPs between M. marinum (AY299134) and M. ulcerans (AY299145),
/// defined at 0-based positions in the aligned hsp65 reference sequences.
/// Both references are 603 bp with no indels, so positions are identical in both.
const MARINUM_ULCERANS_SNPS: &[(usize, u8, u8)] = &[
    // (0-based ref pos, marinum_base, ulcerans_base)
    (20, b'C', b'T'),
    (204, b'T', b'C'),
    (212, b'G', b'A'),
    (482, b'T', b'C'),
    (500, b'G', b'C'),
];


fn call_kansasii_gastri_snps(query: &[u8], alignment_offset: isize) -> Vec<KansasiiGastriSnpCall> {
    KANSASII_GASTRI_SNPS
        .iter()
        .filter_map(|&(ref_pos, gastri_base, kansasii_base)| {
            let query_pos = ref_pos as isize - alignment_offset;
            if query_pos >= 0 && (query_pos as usize) < query.len() {
                let query_base = query[query_pos as usize].to_ascii_uppercase();
                Some(KansasiiGastriSnpCall {
                    ref_pos,
                    query_base,
                    gastri_base,
                    kansasii_base,
                })
            } else {
                None
            }
        })
        .collect()
}

fn call_marinum_ulcerans_snps(
    query: &[u8],
    alignment_offset: isize,
) -> Vec<MarinumUlceransSnpCall> {
    MARINUM_ULCERANS_SNPS
        .iter()
        .filter_map(|&(ref_pos, marinum_base, ulcerans_base)| {
            let query_pos = ref_pos as isize - alignment_offset;
            if query_pos >= 0 && (query_pos as usize) < query.len() {
                let query_base = query[query_pos as usize].to_ascii_uppercase();
                Some(MarinumUlceransSnpCall {
                    ref_pos,
                    query_base,
                    marinum_base,
                    ulcerans_base,
                })
            } else {
                None
            }
        })
        .collect()
}

fn trim_hsp65_primers(seq: &[u8]) -> Vec<u8> {
    const FWD_START: &[&[u8]] = &[b"ATGGTGTGTCCATCGCCAAG", b"GAGGACCCGTACGAGAAGAT"];
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

pub fn identify_sequence_hsp65(query: &[u8]) -> Vec<SeqIdHit> {
    let query = trim_hsp65_primers(query);
    let query = query.as_slice();
    let refs = [
        parse_fasta(super::REF_AF547836),
        parse_fasta(super::REF_AF547849),
        parse_fasta(super::REF_AY299134),
        parse_fasta(super::REF_AY299145),
    ];
    let rc = reverse_complement(query);

    let mut hits: Vec<SeqIdHit> = refs
        .into_iter()
        .map(|(accession, description, refseq)| {
            let (fwd_id, fwd_off) = best_alignment(query, &refseq);
            let (rev_id, rev_off) = best_alignment(&rc, &refseq);
            let (identity, is_reverse, aligned_query, offset) = if rev_id > fwd_id {
                (rev_id, true, rc.as_slice(), rev_off)
            } else {
                (fwd_id, false, query, fwd_off)
            };
            let kansasii_gastri_snp_calls = call_kansasii_gastri_snps(aligned_query, offset);
            let marinum_ulcerans_snp_calls = call_marinum_ulcerans_snps(aligned_query, offset);
            SeqIdHit {
                accession,
                description,
                identity,
                is_reverse,
                kansasii_gastri_snp_calls,
                marinum_ulcerans_snp_calls,
                rrl_snp_calls: vec![],
                aligned_query: aligned_query.to_vec(),
                alignment_offset: offset,
                erm41position28_opt: None,
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
#[derive(Clone, Debug)]
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
    pub fn is_gastri(&self) -> bool {
        self.query_base == self.gastri_base
    }
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
#[derive(Clone, Debug)]
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
    pub fn is_marinum(&self) -> bool {
        self.query_base == self.marinum_base
    }
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

