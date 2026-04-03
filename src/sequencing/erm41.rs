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

/// Find position 28 in a raw read by scanning for the conserved left anchor.
/// Returns the base at position 28 if the anchor is found.
pub fn call_position28(read: &[u8]) -> Option<u8> {
    let anchor_len = ERM41_ANCHOR_L.len();

    // Slide window looking for left anchor
    let hit = read
        .windows(anchor_len)
        .position(|w| w.eq_ignore_ascii_case(ERM41_ANCHOR_L))?;

    // Position 28 is the base immediately after the left anchor
    let pos28 = hit + anchor_len;
    let base = read.get(pos28).copied()?.to_ascii_uppercase();

    // Validate right anchor is also present for confidence
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

pub fn reverse_complement(seq: &[u8]) -> Vec<u8> {
    seq.iter().rev().map(|&b| match b.to_ascii_uppercase() {
        b'A' => b'T', b'T' => b'A',
        b'G' => b'C', b'C' => b'G',
        _    => b'N',
    }).collect()
}

/// Parse an AB1 (ABIF) Sanger sequencing file and return the primary basecall sequence.
///
/// Tries the edited basecalls (PBAS tag 2) first, falling back to raw basecalls (PBAS tag 1).
/// Returns `None` if the magic bytes are missing or no PBAS tag is found.
pub fn parse_ab1_sequence(data: &[u8]) -> Option<Vec<u8>> {
    // Validate ABIF magic and minimum header size
    if data.len() < 34 || &data[0..4] != b"ABIF" {
        return None;
    }

    // Root directory entry sits at byte 6 (28 bytes long).
    // num_elements (i32 BE) at root+12 = byte 18
    // data_offset  (i32 BE) at root+20 = byte 26
    let dir_count  = i32::from_be_bytes(data[18..22].try_into().ok()?) as usize;
    let dir_offset = i32::from_be_bytes(data[26..30].try_into().ok()?) as usize;

    let mut pbas1: Option<Vec<u8>> = None;

    for i in 0..dir_count {
        let e = dir_offset + i * 28;
        if e + 28 > data.len() {
            break;
        }
        let tag_name   = &data[e..e + 4];
        let tag_number = i32::from_be_bytes(data[e + 4..e + 8].try_into().ok()?);
        // num_elements at e+12, data_size at e+16, data_offset at e+20
        let num_elems = i32::from_be_bytes(data[e + 12..e + 16].try_into().ok()?) as usize;
        let data_size = i32::from_be_bytes(data[e + 16..e + 20].try_into().ok()?) as usize;
        let data_off  = i32::from_be_bytes(data[e + 20..e + 24].try_into().ok()?) as usize;

        if tag_name == b"PBAS" {
            // When data fits in 4 bytes it is stored inline at the data_offset field position
            let offset = if data_size <= 4 { e + 20 } else { data_off };
            if offset + num_elems <= data.len() {
                let seq = data[offset..offset + num_elems].to_vec();
                if tag_number == 2 {
                    return Some(seq); // edited basecalls — best quality
                } else if tag_number == 1 {
                    pbas1 = Some(seq); // raw basecalls — keep as fallback
                }
            }
        }
    }

    pbas1
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