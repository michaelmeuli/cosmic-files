
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::LazyLock;
use super::reverse_complement;
use super::{SeqIdHit, best_alignment, parse_fasta_seq};
use super::{REF_MAB_R5052, RRL_FWD_START, RRL_FWD_END, RRL_ANCHOR_L, RRL_ANCHOR_R};

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
}

fn parse_rrl_resistance_snps(csv: &str) -> BTreeMap<usize, (u8, BTreeMap<u8, Vec<String>>)> {
    let mut rdr = csv::Reader::from_reader(csv.as_bytes());
    let mut map: BTreeMap<usize, (u8, BTreeMap<u8, Vec<String>>)> = BTreeMap::new();
    for row in rdr.deserialize::<ResistanceVariant>() {
        let row = row.unwrap();
        if row.gene.trim() != "rrl" { continue; }
        if row.confers.trim() != "drug_resistance" { continue; }
        let drug = row.drug.trim();
        let m = row.mutation.trim();
        if let Some(rest) = m.strip_prefix("n.") {
            let digits_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
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
}

pub static RRL_ABSCESSUS_RESISTANCE_SNPS: LazyLock<BTreeMap<usize, (u8, BTreeMap<u8, Vec<String>>)>> =
    LazyLock::new(|| {
        parse_rrl_resistance_snps(include_str!(
            "../../res/sequences/ntm-db/Mycobacterium_abscessus/variants.csv"
        ))
    });
pub static RRL_AVIUM_RESISTANCE_SNPS: LazyLock<BTreeMap<usize, (u8, BTreeMap<u8, Vec<String>>)>> =
    LazyLock::new(|| {
        parse_rrl_resistance_snps(include_str!(
            "../../res/sequences/ntm-db/Mycobacterium_avium/variants.csv"
        ))
    });


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

fn call_rrl_snps(
    snps: &BTreeMap<usize, (u8, BTreeMap<u8, Vec<String>>)>,
    query: &[u8],
    alignment_offset: isize,
) -> Vec<RrlSnpCall> {
    snps.iter()
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

/// Compute a call for every rrl resistance SNP position (M. abscessus).
/// Returns one entry per unique position; `query_base` is `None` when not covered.
pub fn call_rrl_abscessus_snps(query: &[u8], alignment_offset: isize) -> Vec<RrlSnpCall> {
    call_rrl_snps(&RRL_ABSCESSUS_RESISTANCE_SNPS, query, alignment_offset)
}

/// Compute a call for every rrl resistance SNP position (M. avium).
/// Returns one entry per unique position; `query_base` is `None` when not covered.
pub fn call_rrl_avium_snps(query: &[u8], alignment_offset: isize) -> Vec<RrlSnpCall> {
    call_rrl_snps(&RRL_AVIUM_RESISTANCE_SNPS, query, alignment_offset)
}


pub(super) fn find_rrl_ntm_display_window(bases: &[u8], peak_locs: &[u16]) -> Option<(u16, u16, bool, u16)> {
    const LEFT: usize  = 9;
    const RIGHT: usize = 10;

    let anchor_len: u16 = RRL_ANCHOR_L.len() as u16;

    if let Some(hit) = bases
        .windows(anchor_len as usize)
        .position(|w| w.eq_ignore_ascii_case(RRL_ANCHOR_L))
    {
        let snp_pos = hit + anchor_len as usize;
        if let Some(window) = super::scan_window(snp_pos, LEFT, RIGHT, peak_locs) {
            return Some((window.0, window.1, false, snp_pos as u16));
        }
    }

    let rc_anchor_r: Vec<u8> = reverse_complement(RRL_ANCHOR_R);
    if let Some(hit) = bases
        .windows(rc_anchor_r.len())
        .position(|w| w.eq_ignore_ascii_case(&rc_anchor_r))
    {
        let snp_pos_comp = hit + rc_anchor_r.len();
        if let Some(window) = super::scan_window(snp_pos_comp, RIGHT, LEFT, peak_locs) {
            return Some((window.0, window.1, true, snp_pos_comp as u16));
        }
    }

    None
}

pub fn identify_sequence_rrl_ntm(query: &[u8]) -> Vec<SeqIdHit> {
    let query = super::trim_start_end(query, RRL_FWD_START, RRL_FWD_END);
    let rc = reverse_complement(query);

    let refseq = parse_fasta_seq(REF_MAB_R5052); 

    let (fwd_id, fwd_off) = best_alignment(query, &refseq);
    let (rev_id, rev_off) = best_alignment(&rc, &refseq);
    let (identity, is_reverse, aligned_query, offset) = if rev_id > fwd_id {
        (rev_id, true, rc.as_slice(), rev_off)
    } else {
        (fwd_id, false, query, fwd_off)
    };

    let rrl_abscessus_snp_calls = call_rrl_abscessus_snps(aligned_query, offset);

    vec![SeqIdHit {
        accession: "MAB_r5052".to_string(),
        description: "M. abscessus".to_string(),
        identity,
        is_reverse,
        kansasii_gastri_snp_calls: vec![],
        marinum_ulcerans_snp_calls: vec![],
        rrl_snp_calls: rrl_abscessus_snp_calls,
        aligned_query: aligned_query.to_vec(),
        alignment_offset: offset,
        erm41position28_opt: None,
    }]
}
