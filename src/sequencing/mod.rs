pub mod erm41;
pub mod tb_data;
pub mod rrl;
pub mod bed;
pub mod hsp65;

pub use hsp65::{KansasiiGastriSnpCall, MarinumUlceransSnpCall, identify_sequence_hsp65};
pub use rrl::RrlSnpCall;

use erm41::Erm41Position28;
use rrl::REF_MAB_R5052;

const REF_MYCO_HSP65: &str = include_str!("../../res/sequences/myco_hsp65.fasta");
const REF_AF547836: &str = include_str!("../../res/sequences/hsp65/AF547836.fasta");
const REF_AF547849: &str = include_str!("../../res/sequences/hsp65/AF547849.fasta");
const REF_AY299134: &str = include_str!("../../res/sequences/hsp65/AY299134.fasta");
const REF_AY299145: &str = include_str!("../../res/sequences/hsp65/AY299145.fasta");
const REF_MYCO_ERM41: &str = include_str!("../../res/sequences/myco_erm41.fasta");
const REF_MYCO_RRS: &str = include_str!("../../res/sequences/myco_rrs.fasta");
const REF_MYCO_RRL: &str = include_str!("../../res/sequences/myco_rrl.fasta");
const REF_MYCO_RPOB: &str = include_str!("../../res/sequences/myco_rpoB.fasta");
const REF_ERM41_ABSCESSUS: &str = include_str!("../../res/sequences/erm41/erm41_abscessus_ATCC_19977.fasta");
const REF_ERM41_BOLLETII: &str = include_str!("../../res/sequences/erm41/erm41_bolletii_CIP_108541.fasta");
const REF_ERM41_MASSILENSE: &str = include_str!("../../res/sequences/erm41/erm41_massiliense_CCUG_48898.fasta");


pub fn reverse_complement(seq: &[u8]) -> Vec<u8> {
    seq.iter().rev().map(|&b| match b.to_ascii_uppercase() {
        b'A' => b'T', b'T' => b'A',
        b'G' => b'C', b'C' => b'G',
        _    => b'N',
    }).collect()
}

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

/// Parse a FASTA string, returning just the sequence bytes (ignores header).
pub(crate) fn parse_fasta_seq(fasta: &str) -> Vec<u8> {
    fasta
        .lines()
        .filter(|l| !l.starts_with('>'))
        .flat_map(|l| l.bytes().filter(|b| b.is_ascii_alphabetic()))
        .collect()
}


/// Parse a FASTA string into `(accession, description, sequence_bytes)`.
pub(crate) fn parse_fasta(fasta: &str) -> (String, String, Vec<u8>) {
    let mut accession = String::new();
    let mut description = String::new();
    let mut seq: Vec<u8> = Vec::new();
    for line in fasta.lines() {
        if let Some(rest) = line.strip_prefix('>') {
            let parts: Vec<&str> = rest.splitn(4, '|').collect();
            accession = parts.get(1).copied().unwrap_or(rest).to_string();
            description = parts
                .get(2)
                .and_then(|s| s.split_once(' ').map(|x| x.1))
                .map(|s| {
                    let mut words = s.splitn(3, ' ');
                    let genus = words.next().unwrap_or("");
                    let species = words.next().unwrap_or("");
                    format!("{} {}", genus, species)
                })
                .unwrap_or_default();
        } else {
            seq.extend(line.bytes().filter(|b| b.is_ascii_alphabetic()));
        }
    }
    (accession, description, seq)
}

fn parse_multi_fasta(fasta: &str) -> Vec<(String, String, Vec<u8>)> {
    let mut result = Vec::new();
    let mut cur_acc = String::new();
    let mut cur_desc = String::new();
    let mut cur_seq: Vec<u8> = Vec::new();
    for line in fasta.lines() {
        if let Some(rest) = line.strip_prefix('>') {
            if !cur_acc.is_empty() {
                result.push((cur_acc.clone(), cur_desc.clone(), std::mem::take(&mut cur_seq)));
            }
            let mut words = rest.splitn(4, ' ');
            cur_acc = words.next().unwrap_or("").to_string();
            let genus = words.next().unwrap_or("");
            let species = words.next().unwrap_or("");
            cur_desc = format!("{} {}", genus, species).trim().to_string();
        } else {
            cur_seq.extend(line.bytes().filter(|b| b.is_ascii_alphabetic()));
        }
    }
    if !cur_acc.is_empty() {
        result.push((cur_acc, cur_desc, cur_seq));
    }
    result
}


fn format_pairwise_alignment_impl(
    accession: &str,
    description: &str,
    identity: f32,
    is_reverse: bool,
    query: &[u8],
    refseq: &[u8],
    offset: isize,
) -> String {
    let (ref_padded, query_padded): (Vec<u8>, Vec<u8>) = if query.len() <= refseq.len() {
        let start = offset as usize;
        let end = start + query.len();
        let ref_p = refseq.to_vec();
        let query_p: Vec<u8> = (0..refseq.len())
            .map(|i| if i >= start && i < end { query[i - start] } else { b'-' })
            .collect();
        (ref_p, query_p)
    } else {
        let start = (-offset) as usize;
        let end = start + refseq.len();
        let query_p = query.to_vec();
        let ref_p: Vec<u8> = (0..query.len())
            .map(|i| if i >= start && i < end { refseq[i - start] } else { b'-' })
            .collect();
        (ref_p, query_p)
    };

    let match_line: Vec<u8> = ref_padded
        .iter()
        .zip(query_padded.iter())
        .map(|(&r, &q)| {
            if r == b'-' || q == b'-' {
                b' '
            } else if r.eq_ignore_ascii_case(&q) {
                b'|'
            } else {
                b'.'
            }
        })
        .collect();

    let orient = if is_reverse { "Reverse Complement" } else { "Forward" };
    let mut out = format!("Query vs {} ({}) — {:.1}% identity\n\n", accession, description, identity);
    out.push_str(&format!("Orientation: {orient}\n\n"));

    let line_width = 60usize;
    let len = ref_padded.len();
    let mut ref_pos = 1usize;
    let mut query_pos = 1usize;
    for chunk_start in (0..len).step_by(line_width) {
        let chunk_end = (chunk_start + line_width).min(len);
        let ref_chunk   = std::str::from_utf8(&ref_padded[chunk_start..chunk_end]).unwrap_or("");
        let match_chunk = std::str::from_utf8(&match_line[chunk_start..chunk_end]).unwrap_or("");
        let query_chunk = std::str::from_utf8(&query_padded[chunk_start..chunk_end]).unwrap_or("");

        out.push_str(&format!("Ref   {:5}: {}\n", ref_pos, ref_chunk));
        out.push_str(&format!("             {match_chunk}\n"));
        out.push_str(&format!("Query {:5}: {}\n\n", query_pos, query_chunk));

        ref_pos   += ref_chunk.bytes().filter(|&b| b != b'-').count();
        query_pos += query_chunk.bytes().filter(|&b| b != b'-').count();
    }
    out
}



/// FNV-1a hash of a k-mer, case-insensitive.
fn kmer_hash(kmer: &[u8]) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for &b in kmer {
        h ^= b.to_ascii_uppercase() as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

pub(crate) fn best_alignment(query: &[u8], reference: &[u8]) -> (f32, isize) {
    const WORD_SIZE: usize = 11;

    if query.is_empty() || reference.is_empty() {
        return (0.0, 0);
    }

    // Orient so `shorter` fits inside `longer`.
    let (shorter, longer, swapped) = if query.len() <= reference.len() {
        (query, reference, false)
    } else {
        (reference, query, true)
    };

    let max_offset = longer.len() - shorter.len();

    // ── Phase 1: seed ────────────────────────────────────────────────────────
    // Build a k-mer index over the shorter sequence, then scan the longer
    // sequence for matching k-mers.  Each match fixes a diagonal (offset).
    let mut candidates: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();

    if shorter.len() >= WORD_SIZE {
        let mut kmer_index: std::collections::HashMap<u64, Vec<usize>> =
            std::collections::HashMap::new();
        for (i, w) in shorter.windows(WORD_SIZE).enumerate() {
            kmer_index.entry(kmer_hash(w)).or_default().push(i);
        }
        for (j, w) in longer.windows(WORD_SIZE).enumerate() {
            if let Some(positions) = kmer_index.get(&kmer_hash(w)) {
                for &i in positions {
                    if j >= i {
                        let d = j - i;
                        if d <= max_offset
                            // Verify to guard against hash collisions.
                            && shorter[i..i + WORD_SIZE]
                                .iter()
                                .zip(&longer[j..j + WORD_SIZE])
                                .all(|(a, b)| a.eq_ignore_ascii_case(b))
                        {
                            candidates.insert(d);
                        }
                    }
                }
            }
        }
    }

    // ── Phase 2: extend ──────────────────────────────────────────────────────
    // Score each candidate diagonal; fall back to all diagonals when no seeds
    // were found (short sequences or no k-mer overlap).
    let score_offset = |off: usize| -> (usize, usize) {
        let count = shorter
            .iter()
            .zip(&longer[off..off + shorter.len()])
            .filter(|(a, b)| a.eq_ignore_ascii_case(b))
            .count();
        (count, off)
    };

    let (best_count, best_off) = if candidates.is_empty() {
        (0..=max_offset).map(score_offset).max_by_key(|&(c, _)| c)
    } else {
        candidates.into_iter().map(score_offset).max_by_key(|&(c, _)| c)
    }
    .unwrap_or((0, 0));

    let identity = best_count as f32 / shorter.len() as f32 * 100.0;
    let offset = if swapped { -(best_off as isize) } else { best_off as isize };
    (identity, offset)
}

/// Align `query` against every sequence in `database` and return the best hit.
pub fn identify_species(query: &[u8], database: &str) -> Option<SpeciesHit> {
    let rc = reverse_complement(query);
    parse_multi_fasta(database)
        .into_iter()
        .map(|(accession, description, refseq)| {
            let (fwd_id, fwd_off) = best_alignment(query, &refseq);
            let (rev_id, rev_off) = best_alignment(&rc, &refseq);
            let (identity, is_reverse, aligned_query, alignment_offset) = if rev_id > fwd_id {
                (rev_id, true, rc.clone(), rev_off)
            } else {
                (fwd_id, false, query.to_vec(), fwd_off)
            };
            SpeciesHit {
                accession,
                description,
                identity,
                is_reverse,
                aligned_query,
                alignment_offset,
                ref_seq: refseq,
            }
        })
        .max_by(|a, b| a.identity.partial_cmp(&b.identity).unwrap_or(std::cmp::Ordering::Equal))
}

pub fn identify_species_hsp65(query: &[u8]) -> Option<SpeciesHit> {
    identify_species(query, REF_MYCO_HSP65)
}
pub fn identify_species_erm41(query: &[u8]) -> Option<SpeciesHit> {
    identify_species(query, REF_MYCO_ERM41)
}
pub fn identify_species_16s(query: &[u8]) -> Option<SpeciesHit> {
    identify_species(query, REF_MYCO_RRS)
}
pub fn identify_species_rpob(query: &[u8]) -> Option<SpeciesHit> {
    identify_species(query, REF_MYCO_RPOB)
}
pub fn identify_species_23s_ntm(query: &[u8]) -> Option<SpeciesHit> {
    identify_species(query, REF_MYCO_RRL)
}



pub(super) fn scan_window(
    center: usize,
    left: usize,
    right: usize,
    peak_locs: &[u16],
) -> Option<(u16, u16)> {
    let base_start = center.checked_sub(left)?;
    let base_end   = center + right;
    if base_end >= peak_locs.len() {
        return None;
    }
    let start_scan = peak_locs[base_start];
    let end_scan   = peak_locs[base_end];
    if start_scan >= end_scan {
        return None;
    }
    Some((start_scan, end_scan))
}

/// Tries the edited basecalls (PBAS tag 2) first, falling back to raw basecalls (PBAS tag 1).
pub fn parse_ab1_sequence(data: &[u8]) -> Option<Vec<u8>> {
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

/// Tries edited quality scores (PCON tag 2) first, falling back to raw (PCON tag 1).
/// Each byte is a Phred quality score corresponding to the base at the same index in PBAS.
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

    let erm41_view_state_opt = erm41::find_erm41_display_window(&bases, &peak_locs)
        .map(|(start, end, is_reverse, pos28_base_idx)| Erm41ViewState {
            window: (start, end),
            is_reverse,
            pos28_base_idx,
        });

    let rrl_ntm_view_state_opt = rrl::find_rrl_ntm_display_window(&bases, &peak_locs)
        .map(|(start, end, is_reverse, snp_base_idx)| RrlNtmViewState {
            window: (start, end),
            is_reverse,
            snp_base_idx,
        });

    Some(Ab1Channels {
        channels,
        bases,
        peak_locs,
        base_order,
        erm41_view_state_opt,
        rrl_ntm_view_state_opt,
    })
}




#[derive(Clone, Copy, Debug)]
pub struct Erm41ViewState {
    pub window: (u16, u16),
    pub is_reverse: bool,
    pub pos28_base_idx: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct RrlNtmViewState {
    pub window: (u16, u16),
    pub is_reverse: bool,
    pub snp_base_idx: u16,
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
    pub erm41_view_state_opt: Option<Erm41ViewState>,
    /// Rrl/NTM view state; `None` when the anchor was not found in the basecall sequence.
    pub rrl_ntm_view_state_opt: Option<RrlNtmViewState>,
}

impl Ab1Channels {
    /// Return the channel index for a given base byte (A/C/G/T).
    pub fn channel_for_base(&self, base: u8) -> Option<usize> {
        self.base_order
            .iter()
            .position(|&b| b.eq_ignore_ascii_case(&base))
    }
}

/// Best-hit result from aligning an AB1 read against the reference sequences.
#[derive(Clone, Debug)]
pub struct SeqIdHit {
    /// Accession of the best-matching reference (e.g. "AF547836").
    pub accession: String,
    /// Species name stripped to genus + species (e.g. "Mycobacterium gastri").
    pub description: String,
    /// Percent identity of the best local alignment window (0.0–100.0).
    pub identity: f32,
    /// `true` when the reverse complement of the query was the better match.
    pub is_reverse: bool,
    /// Calls at each diagnostic kansasii/gastri SNP position.
    pub kansasii_gastri_snp_calls: Vec<KansasiiGastriSnpCall>,
    /// Calls at each diagnostic marinum/ulcerans SNP position.
    pub marinum_ulcerans_snp_calls: Vec<MarinumUlceransSnpCall>,
    /// Calls at each rrl macrolide-resistance SNP position (23S rRNA).
    pub rrl_snp_calls: Vec<RrlSnpCall>,
    /// The aligned query (forward or reverse-complement, whichever scored best).
    pub aligned_query: Vec<u8>,
    /// Signed offset such that `query_index = ref_index - alignment_offset`.
    pub alignment_offset: isize,
    /// Erm41 position 28 call; `None` for non-erm41 targets.
    pub erm41position28_opt: Option<Erm41Position28>,
}

impl SeqIdHit {
    /// Format the alignment as a human-readable pairwise text (60-column wrapping).
    pub fn format_pairwise_alignment(&self) -> String {
        let ref_fasta = match self.accession.as_str() {
            // For hsp65
            "AF547836" => REF_AF547836,
            "AF547849" => REF_AF547849,
            "AY299134" => REF_AY299134,
            "AY299145" => REF_AY299145,
            // For erm(41)
            "REF_ERM41_ABSCESSUS" => REF_ERM41_ABSCESSUS,
            "REF_ERM41_BOLLETII" => REF_ERM41_BOLLETII,
            "REF_ERM41_MASSILENSE" => REF_ERM41_MASSILENSE,
            // For 23S rRNA NTM
            "MAB_r5052" => REF_MAB_R5052,
            _ => return format!("Unknown reference accession: {}\n", self.accession),
        };
        let (_, _, refseq) = parse_fasta(ref_fasta);
        format_pairwise_alignment_impl(
            &self.accession,
            &self.description,
            self.identity,
            self.is_reverse,
            &self.aligned_query,
            &refseq,
            self.alignment_offset,
        )
    }

    pub fn is_kansasii(&self) -> bool {
        self.accession == "AF547849"
    }
    pub fn is_gastri(&self) -> bool {
        self.accession == "AF547836"
    }
    pub fn is_marinum(&self) -> bool {
        self.accession == "AY299134"
    }
    pub fn is_ulcerans(&self) -> bool {
        self.accession == "AY299145"
    }
    pub fn kansasii_gastri_snp_species_call(&self) -> Option<&'static str> {
        let gastri = self
            .kansasii_gastri_snp_calls
            .iter()
            .filter(|c| c.is_gastri())
            .count();
        let kansasii = self
            .kansasii_gastri_snp_calls
            .iter()
            .filter(|c| c.is_kansasii())
            .count();
        match gastri.cmp(&kansasii) {
            std::cmp::Ordering::Greater => Some("M. gastri"),
            std::cmp::Ordering::Less => Some("M. kansasii"),
            std::cmp::Ordering::Equal => None,
        }
    }
    pub fn marinum_ulcerans_snp_species_call(&self) -> Option<&'static str> {
        let marinum = self
            .marinum_ulcerans_snp_calls
            .iter()
            .filter(|c| c.is_marinum())
            .count();
        let ulcerans = self
            .marinum_ulcerans_snp_calls
            .iter()
            .filter(|c| c.is_ulcerans())
            .count();
        match marinum.cmp(&ulcerans) {
            std::cmp::Ordering::Greater => Some("M. marinum"),
            std::cmp::Ordering::Less => Some("M. ulcerans"),
            std::cmp::Ordering::Equal => None,
        }
    }
}

/// Best-hit species identification from aligning against a multi-FASTA reference database.
#[derive(Clone, Debug)]
pub struct SpeciesHit {
    pub accession: String,
    pub description: String,
    pub identity: f32,
    /// `true` when the reverse complement of the query was the better match.
    pub is_reverse: bool,
    /// The aligned query (forward or reverse-complement, whichever scored best).
    pub aligned_query: Vec<u8>,
    /// Signed offset such that `query_index = ref_index - alignment_offset`.
    pub alignment_offset: isize,
    /// The full reference sequence for this hit (used for pairwise display).
    pub ref_seq: Vec<u8>,
}

impl SpeciesHit {
    /// Format the alignment as a human-readable pairwise text (60-column wrapping).
    pub fn format_pairwise_alignment(&self) -> String {
        format_pairwise_alignment_impl(
            &self.accession,
            &self.description,
            self.identity,
            self.is_reverse,
            &self.aligned_query,
            &self.ref_seq,
            self.alignment_offset,
        )
    }
}

#[derive(Clone, Debug)]
pub struct SeqData {
    pub chromatogram_opt: Option<Ab1Channels>,
    pub seq_id_hits: Vec<SeqIdHit>,
    pub species_hit_opt: Option<SpeciesHit>,
    pub trimmed_length: usize,
    pub trimmed_avg_quality_opt: Option<f32>,
}