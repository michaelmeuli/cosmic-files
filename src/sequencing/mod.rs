pub mod erm41;
pub mod jsondata;

use erm41::Erm41Position28;

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
    pub ab1_call_opt: Option<Erm41Position28>,
    pub chromatogram: Option<Ab1Channels>,
}