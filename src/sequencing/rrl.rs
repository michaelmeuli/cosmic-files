
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::LazyLock;
use super::reverse_complement;
use super::seqid::{SeqIdHit, best_alignment, parse_fasta_seq};

pub(super) const REF_MAB_R5052: &str = include_str!("../../res/sequences/MAB_r5052.fasta");
const RRL_ANCHOR_L: &[u8] = b"CGTTACGCGCGGCAGGACGA";
const RRL_ANCHOR_R: &[u8] = b"AGACCCCGGGACCTTCACTA";

#[derive(Debug, Deserialize, Clone)]
struct AbscessusResistanceVariants {
    #[serde(rename = "Gene")]
    gene: String,
    #[serde(rename = "Mutation")]
    mutation: String,
    #[serde(rename = "Drug")]
    drug: String,
    #[serde(rename = "Confers")]
    confers: String,
}


/// Maps each 0-based ref_pos to `(wt_base, alt_to_drugs)` for rrl entries in
/// abscessus_resistance_variants.csv. Parsed from HGVS strings like "n.2270A>C".
/// Multiple alts at the same position (e.g. A>C, A>G, A>T) are grouped under one key.
pub static RRL_RESISTANCE_SNPS: LazyLock<BTreeMap<usize, (u8, BTreeMap<u8, Vec<String>>)>> =
    LazyLock::new(|| {
        let mut rdr = csv::Reader::from_reader(
            include_str!("../../res/abscessus_resistance_variants.csv").as_bytes(),
        );
        let mut map: BTreeMap<usize, (u8, BTreeMap<u8, Vec<String>>)> = BTreeMap::new();
        for row in rdr.deserialize::<AbscessusResistanceVariants>() {
            let row = row.unwrap();
            if row.gene.trim() != "rrl" {
                continue;
            }
            if row.confers.trim() != "resistance" {
                continue;
            }
            let drug = row.drug.trim();
            let m = row.mutation.trim();
            if let Some(rest) = m.strip_prefix("n.") {
                let digits_end =
                    rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
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
                        let drugs = entry.1.entry(alt).or_default();
                        if !drugs.contains(&drug.to_string()) {
                            drugs.push(drug.to_string());
                        }
                    }
                }
            }
        }
        map
    });


/// A single macrolide-resistance SNP position in the M. abscessus 23S rRNA (rrl).
/// `query_base` is `None` when the position is not covered by the read.
#[derive(Clone, Debug)]
pub struct RrlSnpCall {
    /// 0-based position in the rrl reference sequence (MAB_r5052).
    pub ref_pos: usize,
    /// Base observed in the query at this position, or `None` if not covered.
    pub query_base: Option<u8>,
    /// Wild-type base at this position.
    pub wt_base: u8,
    /// Maps each resistance-conferring base to the drugs it confers resistance to.
    pub resistance_bases: BTreeMap<u8, Vec<String>>,
}

impl RrlSnpCall {
    /// "NA", "<base> (wt)", "<base> (drug1, drug2, ...)", or "<base> (mutation)".
    pub fn call_tag(&self) -> String {
        match self.query_base {
            None => "NA".to_string(),
            Some(b) if b == self.wt_base => format!("{} (wt)", self.wt_base as char),
            Some(b) if self.resistance_bases.contains_key(&b) => {
                let drugs = self.resistance_bases[&b].join(", ");
                format!("{} ({})", b as char, drugs)
            }
            Some(b) => format!("{} (mutation)", b as char),
        }
    }
}

/// Compute a call for every rrl resistance SNP position.
/// Returns one entry per unique position; `query_base` is `None` when not covered.
pub fn call_rrl_snps(query: &[u8], alignment_offset: isize) -> Vec<RrlSnpCall> {
    RRL_RESISTANCE_SNPS
        .iter()
        .map(|(&ref_pos, (wt_base, alt_to_drugs))| {
            let query_pos = ref_pos as isize - alignment_offset;
            let query_base = if query_pos >= 0 && (query_pos as usize) < query.len() {
                Some(query[query_pos as usize].to_ascii_uppercase())
            } else {
                None
            };
            RrlSnpCall { ref_pos, query_base, wt_base: *wt_base, resistance_bases: alt_to_drugs.clone() }
        })
        .collect()
}


pub(super) fn find_rrl_ntm_display_window(bases: &[u8], peak_locs: &[u16]) -> Option<(usize, usize, bool, usize)> {
    const LEFT: usize  = 10;
    const RIGHT: usize = 10;

    let anchor_len = RRL_ANCHOR_L.len();

    if let Some(hit) = bases
        .windows(anchor_len)
        .position(|w| w.eq_ignore_ascii_case(RRL_ANCHOR_L))
    {
        let snp_pos = hit + anchor_len;
        if let Some(window) = super::scan_window(snp_pos, LEFT, RIGHT, peak_locs) {
            return Some((window.0, window.1, false, snp_pos));
        }
    }

    let rc_anchor_r: Vec<u8> = reverse_complement(RRL_ANCHOR_R);
    if let Some(hit) = bases
        .windows(rc_anchor_r.len())
        .position(|w| w.eq_ignore_ascii_case(&rc_anchor_r))
    {
        let snp_pos_comp = hit + rc_anchor_r.len();
        if let Some(window) = super::scan_window(snp_pos_comp, RIGHT, LEFT, peak_locs) {
            return Some((window.0, window.1, true, snp_pos_comp));
        }
    }

    None
}

/// Align `query` against the M. abscessus rrl (23S rRNA) reference (MAB_r5052) and return
/// the single hit with resistance SNP calls for all positions from abscessus_resistance_variants.csv
/// (Gene == rrl).
pub fn identify_sequence_23s_ntm(query: &[u8]) -> Vec<SeqIdHit> {
    let refseq = parse_fasta_seq(REF_MAB_R5052);
    let rc = reverse_complement(query);

    let (fwd_id, fwd_off) = best_alignment(query, &refseq);
    let (rev_id, rev_off) = best_alignment(&rc, &refseq);
    let (identity, is_reverse, aligned_query, offset) = if rev_id > fwd_id {
        (rev_id, true, rc.as_slice(), rev_off)
    } else {
        (fwd_id, false, query, fwd_off)
    };

    let rrl_snp_calls = call_rrl_snps(aligned_query, offset);

    vec![SeqIdHit {
        accession: "MAB_r5052".to_string(),
        description: "M. abscessus".to_string(),
        identity,
        is_reverse,
        kansasii_gastri_snp_calls: vec![],
        marinum_ulcerans_snp_calls: vec![],
        rrl_snp_calls,
        aligned_query: aligned_query.to_vec(),
        alignment_offset: offset,
        erm41position28_opt: None,
    }]
}
