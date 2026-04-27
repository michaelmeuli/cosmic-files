use super::reverse_complement;
use super::seqid::{best_alignment, parse_fasta_seq, SeqIdHit};

/// Conserved left flank — ends immediately before position 28
const ERM41_ANCHOR_L: &[u8] = b"GCCAACGGTCGCGACGCCAG";

/// Conserved right flank — starts immediately after position 28  
const ERM41_ANCHOR_R: &[u8] = b"GGGGCTGGTATCCGCTCACT";

#[derive(Debug, Clone, PartialEq)]
pub enum Erm41Position28 {
    C28,          // Cytosine — reference allele in some strains
    T28,          // Thymine  — inducible macrolide resistance (ATCC 19977 type)
    G28,          // Guanine
    A28,          // Adenine
    Ambiguous,    // Fwd/rev disagree
    Undetermined, // Anchor not found in read
}

impl std::fmt::Display for Erm41Position28 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::C28          => write!(f, "C28"),
            Self::T28          => write!(f, "T28 — inducible macrolide resistance"),
            Self::G28          => write!(f, "G28"),
            Self::A28          => write!(f, "A28"),
            Self::Ambiguous    => write!(f, "Ambiguous (strand disagreement)"),
            Self::Undetermined => write!(f, "Undetermined (anchor not found)"),
        }
    }
}

pub fn call_position28(read: &[u8]) -> Option<u8> {
    let anchor_len = ERM41_ANCHOR_L.len();
    let hit = read
        .windows(anchor_len)
        .position(|w| w.eq_ignore_ascii_case(ERM41_ANCHOR_L))?;
    let pos28 = hit + anchor_len;
    let base = read.get(pos28).copied()?.to_ascii_uppercase();
    let right_start = pos28 + 1;
    let right_end = right_start + ERM41_ANCHOR_R.len();
    if right_end > read.len() {
        return None;
    }
    let right_ok = read[right_start..right_end]
        .eq_ignore_ascii_case(ERM41_ANCHOR_R);
    if !right_ok {
        return None;
    }
    Some(base)
}

fn base_to_call(base: Option<u8>) -> Option<Erm41Position28> {
    match base {
        Some(b'C') => Some(Erm41Position28::C28),
        Some(b'T') => Some(Erm41Position28::T28),
        Some(b'G') => Some(Erm41Position28::G28),
        Some(b'A') => Some(Erm41Position28::A28), 
        _          => None,
    }
}

pub(super) fn find_erm41_display_window(bases: &[u8], peak_locs: &[u16]) -> Option<(u16, u16, bool, u16)> {
    // Flanking bases to show: 9 before pos28, 11 after (pos28 is the first of the 11)
    const LEFT: usize  = 9;
    const RIGHT: usize = 11;

    let anchor_len: u16 = ERM41_ANCHOR_L.len() as u16;

    // --- Forward orientation: ANCHOR_L directly in PBAS ---
    if let Some(hit) = bases
        .windows(anchor_len as usize)
        .position(|w| w.eq_ignore_ascii_case(ERM41_ANCHOR_L))
    {
        let pos28 = hit + anchor_len as usize;
        if let Some(window) = super::scan_window(pos28, LEFT, RIGHT, peak_locs) {
            return Some((window.0, window.1, false, pos28 as u16));
        }
    }

    let rc_anchor_r: Vec<u8> = reverse_complement(ERM41_ANCHOR_R);
    if let Some(hit) = bases
        .windows(rc_anchor_r.len())
        .position(|w| w.eq_ignore_ascii_case(&rc_anchor_r))
    {
        let pos28_comp = hit + rc_anchor_r.len();
        if let Some(window) = super::scan_window(pos28_comp, RIGHT, LEFT, peak_locs) {
            return Some((window.0, window.1, true, pos28_comp as u16));
        }
    }

    None
}

// TODO: consider fw and rev sequences. Function is unused at the moment.
pub fn erm41position28_from_fw_rev(fwd_read: &[u8], rev_read: &[u8]) -> Erm41Position28 {
    let fwd = base_to_call(call_position28(fwd_read));
    let rc  = reverse_complement(rev_read);
    let rev = base_to_call(call_position28(&rc));

    match (fwd, rev) {
        (Some(a), Some(b)) if a == b => a,          // both agree
        (Some(a), None)              => a,           // only fwd found
        (None,    Some(b))           => b,           // only rev found
        (Some(_), Some(_))           => Erm41Position28::Ambiguous,
        (None,    None)              => Erm41Position28::Undetermined,
    }
}

pub fn erm41position28_from_single_read(read: &[u8]) -> Erm41Position28 {
    if let Some(call) = base_to_call(call_position28(read)) {
        return call;
    }
    let rc = reverse_complement(read);
    base_to_call(call_position28(&rc)).unwrap_or(Erm41Position28::Undetermined)
}

pub fn identify_sequence_erm41(query: &[u8]) -> Vec<SeqIdHit> {
    let refseq = parse_fasta_seq(super::seqid::REF_ERM41_ABSCESSUS);
    let rc = reverse_complement(query);

    let (fwd_id, fwd_off) = best_alignment(query, &refseq);
    let (rev_id, rev_off) = best_alignment(&rc, &refseq);
    let (identity, is_reverse, aligned_query, offset) = if rev_id > fwd_id {
        (rev_id, true, rc.as_slice(), rev_off)
    } else {
        (fwd_id, false, query, fwd_off)
    };

    vec![SeqIdHit {
        accession: "REF_ERM41_ABSCESSUS".to_string(),
        description: "M. abscessus".to_string(),
        identity,
        is_reverse,
        kansasii_gastri_snp_calls: vec![],
        marinum_ulcerans_snp_calls: vec![],
        rrl_snp_calls: vec![],
        aligned_query: aligned_query.to_vec(),
        alignment_offset: offset,
        erm41position28_opt: Some(erm41position28_from_single_read(query)),
    }]
}
