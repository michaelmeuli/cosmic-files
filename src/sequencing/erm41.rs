use super::reverse_complement;

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
    let right_end   = right_start + ERM41_ANCHOR_R.len();
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


/// Find the scan-index window covering "cgacgccag[pos28]ggggctggtat":
/// 9 bases before position 28 and 11 bases after (including pos28 itself).
///
/// Returns `(start_scan, end_scan, is_reverse, pos28_base_idx)`.
/// For reverse reads the window scan indices are returned in the same
/// (start < end) order as for forward reads; the caller flips the x-axis.
pub(super) fn find_erm41_display_window(bases: &[u8], peak_locs: &[u16]) -> Option<(usize, usize, bool, usize)> {
    // Flanking bases to show: 9 before pos28, 11 after (pos28 is the first of the 11)
    const LEFT: usize  = 9;
    const RIGHT: usize = 11;

    let anchor_len = ERM41_ANCHOR_L.len();

    // --- Forward orientation: ANCHOR_L directly in PBAS ---
    if let Some(hit) = bases
        .windows(anchor_len)
        .position(|w| w.eq_ignore_ascii_case(ERM41_ANCHOR_L))
    {
        let pos28 = hit + anchor_len;
        if let Some(window) = scan_window(pos28, LEFT, RIGHT, peak_locs) {
            return Some((window.0, window.1, false, pos28));
        }
    }

    // --- Reverse orientation: RC(ANCHOR_R) appears before comp(pos28) in PBAS ---
    // On the minus strand the read is: RC(ANCHOR_R) · comp(pos28) · RC(ANCHOR_L)
    // We use LEFT=11, RIGHT=9 here because in the RC world the flanks swap sides:
    // the 11-base ANCHOR_R flank sits to the LEFT of comp(pos28) in scan space,
    // and the 9-base ANCHOR_L flank sits to the RIGHT.
    let rc_anchor_r: Vec<u8> = reverse_complement(ERM41_ANCHOR_R);
    if let Some(hit) = bases
        .windows(rc_anchor_r.len())
        .position(|w| w.eq_ignore_ascii_case(&rc_anchor_r))
    {
        let pos28_comp = hit + rc_anchor_r.len();
        if let Some(window) = scan_window(pos28_comp, RIGHT, LEFT, peak_locs) {
            return Some((window.0, window.1, true, pos28_comp));
        }
    }

    None
}

/// Convert a base-array position + left/right flank counts to a scan-index range.
/// Returns `None` if the indices would go out of bounds or produce an empty range.
fn scan_window(
    center: usize,
    left: usize,
    right: usize,
    peak_locs: &[u16],
) -> Option<(usize, usize)> {
    let base_start = center.checked_sub(left)?;
    let base_end   = center + right;
    if base_end >= peak_locs.len() {
        return None;
    }
    let start_scan = peak_locs[base_start] as usize;
    let end_scan   = peak_locs[base_end]   as usize;
    if start_scan >= end_scan {
        return None;
    }
    Some((start_scan, end_scan))
}

/// Call erm41 position 28 from a single sequencing read.
///
/// Tries the read in forward orientation first; if the anchor is not found,
/// tries the reverse complement (handles reads sequenced on either strand).
pub fn erm41_from_single_read(read: &[u8]) -> Erm41Position28 {
    if let Some(call) = base_to_call(call_position28(read)) {
        return call;
    }
    let rc = reverse_complement(read);
    base_to_call(call_position28(&rc)).unwrap_or(Erm41Position28::Undetermined)
}

/// Final call reconciling forward and reverse reads
pub fn erm41_call(fwd_read: &[u8], rev_read: &[u8]) -> Erm41Position28 {
    let fwd = base_to_call(call_position28(fwd_read));
    
    // Reverse read is on opposite strand — reverse complement before searching
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

