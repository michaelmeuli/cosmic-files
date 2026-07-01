use super::{REF_MYCO_RPOB, SeqIdHit, align_to_ref, dedup_substring_same_desc, parse_multi_fasta, reverse_complement};
use std::sync::LazyLock;

/// Parsed and substring-deduplicated rpoB reference sequences, initialised once.
static RPOB_REFS: LazyLock<Vec<(String, String, Vec<u8>)>> =
    LazyLock::new(|| dedup_substring_same_desc(parse_multi_fasta(REF_MYCO_RPOB)));

pub fn identify_sequence_rpob(query: &[u8]) -> Vec<SeqIdHit> {
    let rc = reverse_complement(query);
    let mut hits: Vec<SeqIdHit> = RPOB_REFS
        .iter()
        .filter(|(_, _, refseq)| refseq.len() >= super::MIN_RPOB_REF_LEN)
        .map(|(accession, description, refseq)| {
            let fwd = align_to_ref(query, refseq);
            let rev = align_to_ref(&rc, refseq);
            let (ga, is_reverse) = if rev.identity > fwd.identity {
                (rev, true)
            } else {
                (fwd, false)
            };
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
    hits.sort_by(|a, b| {
        b.identity
            .partial_cmp(&a.identity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hits
}
