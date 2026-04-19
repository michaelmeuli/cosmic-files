use super::erm41::reverse_complement;
use super::rrl::{call_rrl_snps, RrlSnpCall};

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
            "MAB_2297" => REF_MAB2297,
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

/// A single diagnostic SNP position in the kansasii/gastri comparison.
#[derive(Clone, Debug)]
pub struct KansasiiGastriSnpCall {
    /// 0-based position in the reference sequence.
    pub ref_pos: usize,
    /// Base observed in the query at this position (uppercase ASCII).
    pub query_base: u8,
    /// Expected base for M. gastri (uppercase ASCII).
    pub gastri_base: u8,
    /// Expected base for M. kansasii (uppercase ASCII).
    pub kansasii_base: u8,
}

impl KansasiiGastriSnpCall {
    pub fn is_gastri(&self) -> bool {
        self.query_base == self.gastri_base
    }
    pub fn is_kansasii(&self) -> bool {
        self.query_base == self.kansasii_base
    }
    /// Human-readable species tag: "M. gastri", "M. kansasii", or "?".
    pub fn species_tag(&self) -> &'static str {
        if self.is_gastri() {
            "M. gastri"
        } else if self.is_kansasii() {
            "M. kansasii"
        } else {
            "?"
        }
    }
}

// ── SNP table ────────────────────────────────────────────────────────────────
/// Diagnostic SNPs between M. gastri (AF547836) and M. kansasii (AF547849),
/// defined at 0-based positions in the aligned hsp65 reference sequences.
/// Both references are 423 bp with no indels, so positions are identical in both.
const KANSASII_GASTRI_SNPS: &[(usize, u8, u8)] = &[
    // (0-based ref pos, gastri_base, kansasii_base)
    (100, b'C', b'T'),
    (130, b'C', b'T'),
    (148, b'G', b'A'),
    (193, b'G', b'C'),
    (283, b'C', b'G'),
    (304, b'T', b'C'),
    (349, b'G', b'C'),
    (399, b'G', b'A'),
];

/// A single diagnostic SNP position in the kansasii/gastri comparison.
#[derive(Clone, Debug)]
pub struct MarinumUlceransSnpCall {
    /// 0-based position in the reference sequence.
    pub ref_pos: usize,
    /// Base observed in the query at this position (uppercase ASCII).
    pub query_base: u8,
    /// Expected base for M. marinum (uppercase ASCII).
    pub marinum_base: u8,
    /// Expected base for M. ulcerans (uppercase ASCII).
    pub ulcerans_base: u8,
}

impl MarinumUlceransSnpCall {
    pub fn is_marinum(&self) -> bool {
        self.query_base == self.marinum_base
    }
    pub fn is_ulcerans(&self) -> bool {
        self.query_base == self.ulcerans_base
    }
    /// Human-readable species tag: "M. marinum", "M. ulcerans", or "?".
    pub fn species_tag(&self) -> &'static str {
        if self.is_marinum() {
            "M. marinum"
        } else if self.is_ulcerans() {
            "M. ulcerans"
        } else {
            "?"
        }
    }
}

// ── SNP table ────────────────────────────────────────────────────────────────

/// Diagnostic SNPs between M. marinum (AY299134) and M. ulcerans (AY299145),
/// defined at 0-based positions in the aligned hsp65 reference sequences.
/// Both references are 603 bp with no indels, so positions are identical in both.
const MARINUM_ULCERANS_SNPS: &[(usize, u8, u8)] = &[
    // (0-based ref pos, marinum_base, ulcerans_base)
    (20, b'C', b'T'),
    (204, b'T', b'C'),
    (212, b'G', b'A'),
    (482, b'T', b'C'),
    (500, b'G', b'C'),
];

// ── Shared alignment formatter ────────────────────────────────────────────────

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
            } else if r.to_ascii_uppercase() == q.to_ascii_uppercase() {
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

// ── FASTA parsing ─────────────────────────────────────────────────────────────

const REF_MYCO_HSP65: &str = include_str!("../../res/sequences/myco_hsp65.fasta");
const REF_MYCO_ERM41: &str = include_str!("../../res/sequences/myco_erm41.fasta");
const REF_MYCO_RRS: &str = include_str!("../../res/sequences/myco_rrs.fasta");
const REF_MYCO_RRL: &str = include_str!("../../res/sequences/myco_rrl.fasta");
const REF_MYCO_RPOB: &str = include_str!("../../res/sequences/myco_rpoB.fasta");
const REF_AF547836: &str = include_str!("../../res/sequences/hsp65/AF547836.fasta");
const REF_AF547849: &str = include_str!("../../res/sequences/hsp65/AF547849.fasta");
const REF_AY299134: &str = include_str!("../../res/sequences/hsp65/AY299134.fasta");
const REF_AY299145: &str = include_str!("../../res/sequences/hsp65/AY299145.fasta");
const REF_MAB2297: &str = include_str!("../../res/sequences/MAB_2297.fasta");
const REF_MAB_R5052: &str = include_str!("../../res/sequences/MAB_r5052.fasta");

/// Parse a FASTA string into `(accession, description, sequence_bytes)`.
fn parse_fasta(fasta: &str) -> (String, String, Vec<u8>) {
    let mut accession = String::new();
    let mut description = String::new();
    let mut seq: Vec<u8> = Vec::new();
    for line in fasta.lines() {
        if let Some(rest) = line.strip_prefix('>') {
            let parts: Vec<&str> = rest.splitn(4, '|').collect();
            accession = parts.get(1).copied().unwrap_or(rest).to_string();
            description = parts
                .get(2)
                .and_then(|s| s.splitn(2, ' ').nth(1))
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

// ── Alignment ─────────────────────────────────────────────────────────────────

/// FNV-1a hash of a k-mer, case-insensitive.
fn kmer_hash(kmer: &[u8]) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for &b in kmer {
        h ^= b.to_ascii_uppercase() as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

/// BLAST-inspired gapless alignment: k-mer seeding followed by ungapped extension.
/// Returns `(identity%, alignment_offset)`.
///
/// `alignment_offset` is a signed integer such that for any aligned position:
///   `query_index = ref_index - alignment_offset`
///
/// - When `query.len() <= reference.len()`: query slides along the reference;
///   `alignment_offset = ref_offset_where_query_starts` (≥ 0).
/// - When `query.len() > reference.len()`: reference slides along the query;
///   `alignment_offset = -query_offset_where_reference_starts` (≤ 0).
///
/// Identity denominator is always the shorter sequence (the aligned window).
///
/// Phase 1 (seed): exact k-mer matches (word size 11, matching BLAST's blastn default)
/// identify candidate diagonals.  Phase 2 (extend): each candidate diagonal is scored
/// by counting identical bases over the full window; the highest-scoring diagonal wins.
/// When no seeds are found (sequences shorter than the word size, or zero k-mer overlap)
/// every valid diagonal is evaluated, preserving correctness.
fn best_alignment(query: &[u8], reference: &[u8]) -> (f32, isize) {
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
                                .all(|(a, b)| a.to_ascii_uppercase() == b.to_ascii_uppercase())
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
            .filter(|(a, b)| a.to_ascii_uppercase() == b.to_ascii_uppercase())
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

/// Look up what the query has at each diagnostic SNP position given the alignment offset.
fn call_kansasii_gastri_snps(query: &[u8], alignment_offset: isize) -> Vec<KansasiiGastriSnpCall> {
    KANSASII_GASTRI_SNPS
        .iter()
        .filter_map(|&(ref_pos, gastri_base, kansasii_base)| {
            let query_pos = ref_pos as isize - alignment_offset;
            if query_pos >= 0 && (query_pos as usize) < query.len() {
                let query_base = query[query_pos as usize].to_ascii_uppercase();
                Some(KansasiiGastriSnpCall {
                    ref_pos,
                    query_base,
                    gastri_base,
                    kansasii_base,
                })
            } else {
                None
            }
        })
        .collect()
}

fn call_marinum_ulcerans_snps(
    query: &[u8],
    alignment_offset: isize,
) -> Vec<MarinumUlceransSnpCall> {
    MARINUM_ULCERANS_SNPS
        .iter()
        .filter_map(|&(ref_pos, marinum_base, ulcerans_base)| {
            let query_pos = ref_pos as isize - alignment_offset;
            if query_pos >= 0 && (query_pos as usize) < query.len() {
                let query_base = query[query_pos as usize].to_ascii_uppercase();
                Some(MarinumUlceransSnpCall {
                    ref_pos,
                    query_base,
                    marinum_base,
                    ulcerans_base,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse a FASTA string, returning just the sequence bytes (ignores header).
fn parse_fasta_seq(fasta: &str) -> Vec<u8> {
    fasta
        .lines()
        .filter(|l| !l.starts_with('>'))
        .flat_map(|l| l.bytes().filter(|b| b.is_ascii_alphabetic()))
        .collect()
}

fn trim_hsp65_primers(seq: &[u8]) -> Vec<u8> {
    const FWD_START: &[&[u8]] = &[b"ATGGTGTGTCCATCGCCAAG", b"GAGGACCCGTACGAGAAGAT"];
    const FWD_END: &[&[u8]] = &[b"GAGCTCACCGAGGGTATGCG", b"CGCTGTCCACCCTGGTCGTC"];

    // On an RC-strand query the start primers appear as RC(end primers) and vice versa,
    // so we search both orientations for each boundary.
    let rc_start: Vec<Vec<u8>> = FWD_END.iter().map(|p| reverse_complement(p)).collect();
    let rc_end: Vec<Vec<u8>> = FWD_START.iter().map(|p| reverse_complement(p)).collect();

    let find_start = |p: &[u8]| seq.windows(p.len()).position(|w| w.eq_ignore_ascii_case(p));
    let find_end = |p: &[u8]| {
        seq.windows(p.len())
            .rposition(|w| w.eq_ignore_ascii_case(p))
            .map(|pos| pos + p.len())
    };

    let start = FWD_START
        .iter()
        .map(|p| p as &[u8])
        .chain(rc_start.iter().map(|p| p.as_slice()))
        .filter_map(find_start)
        .min()
        .unwrap_or(0);

    let end = FWD_END
        .iter()
        .map(|p| p as &[u8])
        .chain(rc_end.iter().map(|p| p.as_slice()))
        .filter_map(find_end)
        .max()
        .unwrap_or(seq.len());

    seq[start..end.min(seq.len())].to_vec()
}

pub fn identify_hsp65_sequence(query: &[u8]) -> Vec<SeqIdHit> {
    let query = trim_hsp65_primers(query);
    let query = query.as_slice();
    let refs = [
        parse_fasta(REF_AF547836),
        parse_fasta(REF_AF547849),
        parse_fasta(REF_AY299134),
        parse_fasta(REF_AY299145),
    ];
    let rc = reverse_complement(query);

    let mut hits: Vec<SeqIdHit> = refs
        .into_iter()
        .map(|(accession, description, refseq)| {
            let (fwd_id, fwd_off) = best_alignment(query, &refseq);
            let (rev_id, rev_off) = best_alignment(&rc, &refseq);
            let (identity, is_reverse, aligned_query, offset) = if rev_id > fwd_id {
                (rev_id, true, rc.as_slice(), rev_off)
            } else {
                (fwd_id, false, query, fwd_off)
            };
            let kansasii_gastri_snp_calls = call_kansasii_gastri_snps(aligned_query, offset);
            let marinum_ulcerans_snp_calls = call_marinum_ulcerans_snps(aligned_query, offset);
            SeqIdHit {
                accession,
                description,
                identity,
                is_reverse,
                kansasii_gastri_snp_calls,
                marinum_ulcerans_snp_calls,
                rrl_snp_calls: vec![],
                aligned_query: aligned_query.to_vec(),
                alignment_offset: offset,
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

/// Align `query` against the erm(41) reference (MAB_2297) and return the single hit.
pub fn identify_sequence_erm41(query: &[u8]) -> Vec<SeqIdHit> {
    let refseq = parse_fasta_seq(REF_MAB2297);
    let rc = reverse_complement(query);

    let (fwd_id, fwd_off) = best_alignment(query, &refseq);
    let (rev_id, rev_off) = best_alignment(&rc, &refseq);
    let (identity, is_reverse, aligned_query, offset) = if rev_id > fwd_id {
        (rev_id, true, rc.as_slice(), rev_off)
    } else {
        (fwd_id, false, query, fwd_off)
    };

    vec![SeqIdHit {
        accession: "MAB_2297".to_string(),
        description: "M. abscessus".to_string(),
        identity,
        is_reverse,
        kansasii_gastri_snp_calls: vec![],
        marinum_ulcerans_snp_calls: vec![],
        rrl_snp_calls: vec![],
        aligned_query: aligned_query.to_vec(),
        alignment_offset: offset,
    }]
}

/// Align `query` against the M. abscessus rrl (23S rRNA) reference (MAB_r5052) and return
/// the single hit with resistance SNP calls for all positions from abscessus_resistance_variants.csv
/// (Gene == rrl).
pub fn identify_sequence_23s_ntm(query: &[u8]) -> Vec<SeqIdHit> {
    let refseq = parse_fasta_seq(REF_MAB_R5052);
    let rc = reverse_complement(query);

    let (fwd_id, fwd_off) = best_alignment(query, &refseq);
    let (rev_id, rev_off) = best_alignment(&rc, &refseq);
    let (identity, is_reverse, aligned_query, offset) = if rev_id > fwd_id {
        (rev_id, true, rc.as_slice(), rev_off)
    } else {
        (fwd_id, false, query, fwd_off)
    };

    let rrl_snp_calls = call_rrl_snps(aligned_query, offset);

    vec![SeqIdHit {
        accession: "MAB_r5052".to_string(),
        description: "M. abscessus".to_string(),
        identity,
        is_reverse,
        kansasii_gastri_snp_calls: vec![],
        marinum_ulcerans_snp_calls: vec![],
        rrl_snp_calls,
        aligned_query: aligned_query.to_vec(),
        alignment_offset: offset,
    }]
}

/// Parse a simple multi-FASTA (`>accession description\nSEQ...`) into
/// `(accession, "Genus species", sequence)` tuples.
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