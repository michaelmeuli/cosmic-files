use super::{REF_MYCO_RPOB, SeqIdHit, best_alignment, parse_multi_fasta, reverse_complement};

pub fn identify_sequence_rpob(query: &[u8]) -> Vec<SeqIdHit> {
    let rc = reverse_complement(query);
    let mut hits: Vec<SeqIdHit> = parse_multi_fasta(REF_MYCO_RPOB)
        .into_iter()
        .filter(|(_, _, refseq)| refseq.len() >= super::MIN_RPOB_REF_LEN)
        .map(|(accession, description, refseq)| {
            let (fwd_id, fwd_off) = best_alignment(query, &refseq);
            let (rev_id, rev_off) = best_alignment(&rc, &refseq);
            let (identity, is_reverse, aligned_query, alignment_offset) = if rev_id > fwd_id {
                (rev_id, true, rc.clone(), rev_off)
            } else {
                (fwd_id, false, query.to_vec(), fwd_off)
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
                rrs_snp_calls: vec![],
                erm41_snp_calls: vec![],
                pnca_snp_calls: vec![],
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
