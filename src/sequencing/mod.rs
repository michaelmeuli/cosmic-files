pub mod erm41;
pub mod jsondata;
pub mod seqid;

use erm41::Erm41Position28;
pub use seqid::SeqIdHit;

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
        let tag_number = i32::from_be_bytes(data[e + 4..e + 8].try_into().ok()?) as i32;
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

/// Parsed channel intensity data from an AB1 chromatogram.
#[derive(Clone, Debug)]
pub struct Ab1Channels {
    /// Four intensity arrays in the order given by `base_order`.
    /// Each Vec has the same length (number of scans).
    pub channels: [Vec<i16>; 4],
    /// Called bases (from PBAS tag).
    pub bases: Vec<u8>,
    /// Scan index of each base call (from PLOC tag), same length as `bases`.
    pub peak_locs: Vec<u16>,
    /// Which base each channel corresponds to, e.g. b"ACGT" (from FWO_ tag).
    pub base_order: [u8; 4],
    /// Scan range `(start, end)` covering the 9 bases before erm41 position 28,
    /// position 28 itself, and the 11 bases after — i.e. "cgacgccag[X]ggggctggtat".
    /// `None` when the anchor was not found in the basecall sequence.
    pub display_window: Option<(usize, usize)>,
    /// `true` when the anchor was found in the reverse-complement orientation.
    /// The canvas flips the x-axis and complements bases/colors so the display
    /// always reads 5′→3′ on the plus strand (same frame as a forward read).
    pub is_reverse: bool,
    /// Index into `bases` / `peak_locs` of erm41 position 28 (the variant base).
    /// `None` when the anchor was not found.
    pub pos28_base_idx: Option<usize>,
}

impl Ab1Channels {
    /// Return the channel index for a given base byte (A/C/G/T).
    pub fn channel_for_base(&self, base: u8) -> Option<usize> {
        self.base_order
            .iter()
            .position(|&b| b.to_ascii_uppercase() == base.to_ascii_uppercase())
    }
}


#[derive(Clone, Debug)]
pub struct SeqData {
    pub erm41position28_opt: Option<Erm41Position28>,
    pub chromatogram: Option<Ab1Channels>,
    pub seq_id: Option<SeqIdHit>,
}