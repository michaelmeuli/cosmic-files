pub mod erm41;
pub mod tb_data;
pub mod rrl;
pub mod seqid;

use erm41::Erm41Position28;
pub use seqid::{SeqIdHit, KansasiiGastriSnpCall, MarinumUlceransSnpCall, SpeciesHit};
pub use rrl::RrlSnpCall;

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

/// Parse an AB1 (ABIF) file and return the quality scores (PCON tag).
///
/// Tries edited quality scores (PCON tag 2) first, falling back to raw (PCON tag 1).
/// Each byte is a Phred quality score corresponding to the base at the same index in PBAS.
/// Returns `None` if the file is invalid or no PCON tag is found.
pub fn parse_ab1_quality(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 34 || &data[0..4] != b"ABIF" {
        return None;
    }

    let dir_count  = i32::from_be_bytes(data[18..22].try_into().ok()?) as usize;
    let dir_offset = i32::from_be_bytes(data[26..30].try_into().ok()?) as usize;

    let mut pcon1: Option<Vec<u8>> = None;

    for i in 0..dir_count {
        let e = dir_offset + i * 28;
        if e + 28 > data.len() {
            break;
        }
        let tag_name   = &data[e..e + 4];
        let tag_number = i32::from_be_bytes(data[e + 4..e + 8].try_into().ok()?);
        let num_elems  = i32::from_be_bytes(data[e + 12..e + 16].try_into().ok()?) as usize;
        let data_size  = i32::from_be_bytes(data[e + 16..e + 20].try_into().ok()?) as usize;
        let data_off   = i32::from_be_bytes(data[e + 20..e + 24].try_into().ok()?) as usize;

        if tag_name == b"PCON" {
            let offset = if data_size <= 4 { e + 20 } else { data_off };
            if offset + num_elems <= data.len() {
                let qual = data[offset..offset + num_elems].to_vec();
                if tag_number == 2 {
                    return Some(qual); // edited quality — best
                } else if tag_number == 1 {
                    pcon1 = Some(qual); // raw quality — keep as fallback
                }
            }
        }
    }

    pcon1
}

/// Trim a basecall sequence to the high-quality region.
///
/// Removes leading and trailing bases whose Phred quality score is below
/// `min_q`.  If `qual` is shorter than `seq` the excess bases are treated as
/// quality 0.  Returns an empty slice when no base meets the threshold.
pub fn trim_to_min_quality<'a>(seq: &'a [u8], qual: &[u8], min_q: u8) -> &'a [u8] {
    let start = seq
        .iter()
        .enumerate()
        .find(|&(i, _)| qual.get(i).copied().unwrap_or(0) >= min_q)
        .map(|(i, _)| i)
        .unwrap_or(seq.len());

    let end = seq
        .iter()
        .enumerate()
        .rev()
        .find(|&(i, _)| qual.get(i).copied().unwrap_or(0) >= min_q)
        .map(|(i, _)| i + 1)
        .unwrap_or(0);

    if start >= end { &[] } else { &seq[start..end] }
}

pub fn reverse_complement(seq: &[u8]) -> Vec<u8> {
    seq.iter().rev().map(|&b| match b.to_ascii_uppercase() {
        b'A' => b'T', b'T' => b'A',
        b'G' => b'C', b'C' => b'G',
        _    => b'N',
    }).collect()
}

/// Parse an AB1 file and return chromatogram channel data plus basecalls.
///
/// Collects DATA tags 9-12 (analyzed, preferred) or 1-4 (raw fallback),
/// PBAS tag 2/1 (basecalls), PLOC tag 2/1 (peak locations), and FWO_ tag 1
/// (filter wheel order mapping channel index → base letter).
pub fn parse_ab1_chromatogram(data: &[u8]) -> Option<Ab1Channels> {
    if data.len() < 34 || &data[0..4] != b"ABIF" {
        return None;
    }

    let dir_count  = i32::from_be_bytes(data[18..22].try_into().ok()?) as usize;
    let dir_offset = i32::from_be_bytes(data[26..30].try_into().ok()?) as usize;

    // Collect all tag entries we care about
    let mut data_tags: std::collections::HashMap<i32, Vec<i16>> = std::collections::HashMap::new();
    let mut pbas1: Option<Vec<u8>>  = None;
    let mut pbas2: Option<Vec<u8>>  = None;
    let mut ploc1: Option<Vec<u16>> = None;
    let mut ploc2: Option<Vec<u16>> = None;
    let mut fwo: Option<[u8; 4]>    = None;

    for i in 0..dir_count {
        let e = dir_offset + i * 28;
        if e + 28 > data.len() {
            break;
        }
        let tag_name   = &data[e..e + 4];
        let tag_number = i32::from_be_bytes(data[e + 4..e + 8].try_into().ok()?);
        let num_elems  = i32::from_be_bytes(data[e + 12..e + 16].try_into().ok()?) as usize;
        let data_size  = i32::from_be_bytes(data[e + 16..e + 20].try_into().ok()?) as usize;
        let data_off   = i32::from_be_bytes(data[e + 20..e + 24].try_into().ok()?) as usize;

        let offset = if data_size <= 4 { e + 20 } else { data_off };

        if tag_name == b"DATA" && (1..=12).contains(&tag_number) {
            // Each element is an i16 BE (2 bytes)
            if offset + num_elems * 2 <= data.len() {
                let values: Vec<i16> = (0..num_elems)
                    .map(|j| i16::from_be_bytes([data[offset + j * 2], data[offset + j * 2 + 1]]))
                    .collect();
                data_tags.insert(tag_number, values);
            }
        } else if tag_name == b"PBAS" {
            if offset + num_elems <= data.len() {
                let seq = data[offset..offset + num_elems].to_vec();
                match tag_number {
                    2 => pbas2 = Some(seq),
                    1 => pbas1 = Some(seq),
                    _ => {}
                }
            }
        } else if tag_name == b"PLOC" {
            // i16 BE peak scan positions
            if offset + num_elems * 2 <= data.len() {
                let locs: Vec<u16> = (0..num_elems)
                    .map(|j| u16::from_be_bytes([data[offset + j * 2], data[offset + j * 2 + 1]]))
                    .collect();
                match tag_number {
                    2 => ploc2 = Some(locs),
                    1 => ploc1 = Some(locs),
                    _ => {}
                }
            }
        } else if tag_name == b"FWO_" && tag_number == 1 {
            // 4 bytes: base letter for each channel in order
            if offset + 4 <= data.len() {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&data[offset..offset + 4]);
                fwo = Some(arr);
            }
        }
    }

    // Prefer analyzed channels (9-12), fall back to raw (1-4)
    let channel_indices: [(i32, i32); 4] = [(9, 1), (10, 2), (11, 3), (12, 4)];
    let channels: [Vec<i16>; 4] = channel_indices.map(|(preferred, fallback)| {
        data_tags
            .remove(&preferred)
            .or_else(|| data_tags.remove(&fallback))
            .unwrap_or_default()
    });

    let bases     = pbas2.or(pbas1)?;
    let peak_locs = ploc2
        .or(ploc1)
        .unwrap_or_else(|| vec![0u16; bases.len()]);
    let base_order = fwo.unwrap_or(*b"ACGT");

    let erm41 = erm41::find_erm41_display_window(&bases, &peak_locs)
        .map(|(start, end, is_reverse, pos28_base_idx)| Erm41ViewState {
            window: (start, end),
            is_reverse,
            pos28_base_idx,
        });

    Some(Ab1Channels {
        channels,
        bases,
        peak_locs,
        base_order,
        erm41,
    })
}

/// Erm41-specific view state derived from the chromatogram basecalls.
/// `None` on `Ab1Channels::erm41` when the anchor sequence was not found.
#[derive(Clone, Copy, Debug)]
pub struct Erm41ViewState {
    /// Scan range `(start, end)` covering the 9 bases before position 28,
    /// position 28 itself, and the 11 bases after — "cgacgccag[X]ggggctggtat".
    pub window: (usize, usize),
    /// `true` when the anchor was found in the reverse-complement orientation.
    /// The canvas flips the x-axis and complements bases/colors so the display
    /// always reads 5′→3′ on the plus strand.
    pub is_reverse: bool,
    /// Index into `Ab1Channels::bases` / `peak_locs` of position 28.
    pub pos28_base_idx: usize,
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
    /// Erm41 view state; `None` when the anchor was not found in the basecall sequence.
    pub erm41: Option<Erm41ViewState>,
}

impl Ab1Channels {
    /// Return the channel index for a given base byte (A/C/G/T).
    pub fn channel_for_base(&self, base: u8) -> Option<usize> {
        self.base_order
            .iter()
            .position(|&b| b.eq_ignore_ascii_case(&base))
    }
}


#[derive(Clone, Debug)]
pub struct SeqData {
    pub chromatogram: Option<Ab1Channels>,
    pub seq_id: Vec<SeqIdHit>,
    pub species_hit_opt: Option<SpeciesHit>,
    /// Length of the quality-trimmed basecall sequence used for identification.
    pub trimmed_length: usize,
    /// Mean Phred quality score over the trimmed region. `None` when no quality data is available.
    pub trimmed_avg_quality: Option<f32>,
}