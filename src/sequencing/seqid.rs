use super::erm41::reverse_complement;

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
    /// Calls at each diagnostic hsp65 SNP position.
    pub snp_calls: Vec<SnpCall>,
    /// The aligned query (forward or reverse-complement, whichever scored best).
    pub aligned_query: Vec<u8>,
    /// Signed offset such that `query_index = ref_index - alignment_offset`.
    pub alignment_offset: isize,
}

impl SeqIdHit {
    /// Format the alignment as a human-readable pairwise text (60-column wrapping).
    pub fn format_pairwise_alignment(&self) -> String {
        let ref_fasta = match self.accession.as_str() {
            "AF547836" => REF_AF547836,
            "AF547849" => REF_AF547849,
            "MAB_2297" => REF_MAB2297,
            _ => return format!("Unknown reference accession: {}\n", self.accession),
        };
        let (_, _, refseq) = parse_fasta(ref_fasta);
        let query = &self.aligned_query;
        let offset = self.alignment_offset;

        // Build padded strings of equal length so positions align.
        let (ref_padded, query_padded): (Vec<u8>, Vec<u8>) = if query.len() <= refseq.len() {
            let start = offset as usize;
            let end = start + query.len();
            let ref_p = refseq.clone();
            let query_p: Vec<u8> = (0..refseq.len())
                .map(|i| if i >= start && i < end { query[i - start] } else { b'-' })
                .collect();
            (ref_p, query_p)
        } else {
            let start = (-offset) as usize;
            let end = start + refseq.len();
            let query_p = query.clone();
            let ref_p: Vec<u8> = (0..query.len())
                .map(|i| if i >= start && i < end { refseq[i - start] } else { b'-' })
                .collect();
            (ref_p, query_p)
        };

        let match_line: Vec<u8> = ref_padded
            .iter()
            .zip(query_padded.iter())
            .map(|(&r, &q)| {
                if r == b'-' || q == b'-' { b' ' }
                else if r.to_ascii_uppercase() == q.to_ascii_uppercase() { b'|' }
                else { b'.' }
            })
            .collect();

        let orient = if self.is_reverse { "Reverse Complement" } else { "Forward" };
        let mut out = format!(
            "Query vs {} ({}) — {:.1}% identity\n\n",
            self.accession, self.description, self.identity
        );
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

            ref_pos += ref_chunk.bytes().filter(|&b| b != b'-').count();
            query_pos += query_chunk.bytes().filter(|&b| b != b'-').count();
        }
        out
    }

    /// Majority-vote species call based on the diagnostic SNPs.
    /// Returns `Some("M. gastri")`, `Some("M. kansasii")`, or `None` when ambiguous/no data.
    pub fn snp_species_call(&self) -> Option<&'static str> {
        let gastri   = self.snp_calls.iter().filter(|c| c.is_gastri()).count();
        let kansasii = self.snp_calls.iter().filter(|c| c.is_kansasii()).count();
        match gastri.cmp(&kansasii) {
            std::cmp::Ordering::Greater => Some("M. gastri"),
            std::cmp::Ordering::Less    => Some("M. kansasii"),
            std::cmp::Ordering::Equal   => None,
        }
    }
}

/// A single diagnostic SNP position in the hsp65 gene.
#[derive(Clone, Debug)]
pub struct SnpCall {
    /// 0-based position in the reference sequence.
    pub ref_pos: usize,
    /// Base observed in the query at this position (uppercase ASCII).
    pub query_base: u8,
    /// Expected base for M. gastri (uppercase ASCII).
    pub gastri_base: u8,
    /// Expected base for M. kansasii (uppercase ASCII).
    pub kansasii_base: u8,
}

impl SnpCall {
    pub fn is_gastri(&self) -> bool {
        self.query_base == self.gastri_base
    }
    pub fn is_kansasii(&self) -> bool {
        self.query_base == self.kansasii_base
    }
    /// Human-readable species tag: "M. gastri", "M. kansasii", or "?".
    pub fn species_tag(&self) -> &'static str {
        if self.is_gastri()   { "M. gastri" }
        else if self.is_kansasii() { "M. kansasii" }
        else { "?" }
    }
}

// ── SNP table ────────────────────────────────────────────────────────────────

/// Diagnostic SNPs between M. gastri (AF547836) and M. kansasii (AF547849),
/// defined at 0-based positions in the aligned hsp65 reference sequences.
/// Both references are 423 bp with no indels, so positions are identical in both.
const HSP65_SNPS: &[(usize, u8, u8)] = &[
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

// ── FASTA parsing ─────────────────────────────────────────────────────────────

const REF_AF547836: &str = include_str!("../../res/sequences/AF547836.fasta");
const REF_AF547849: &str = include_str!("../../res/sequences/AF547849.fasta");
const REF_MAB2297:  &str = include_str!("../../res/sequences/MAB_2297.fasta");

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
                    let genus   = words.next().unwrap_or("");
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

/// Gapless sliding-window alignment.  Returns `(identity%, alignment_offset)`.
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
fn best_alignment(query: &[u8], reference: &[u8]) -> (f32, isize) {
    if query.is_empty() || reference.is_empty() {
        return (0.0, 0);
    }
    if query.len() <= reference.len() {
        let (best_count, best_off) = reference
            .windows(query.len())
            .enumerate()
            .map(|(off, window)| {
                let m = query.iter().zip(window)
                    .filter(|(a, b)| a.to_ascii_uppercase() == b.to_ascii_uppercase())
                    .count();
                (m, off)
            })
            .max_by_key(|&(c, _)| c)
            .unwrap_or((0, 0));
        (best_count as f32 / query.len() as f32 * 100.0, best_off as isize)
    } else {
        let (best_count, best_off) = query
            .windows(reference.len())
            .enumerate()
            .map(|(off, window)| {
                let m = reference.iter().zip(window)
                    .filter(|(a, b)| a.to_ascii_uppercase() == b.to_ascii_uppercase())
                    .count();
                (m, off)
            })
            .max_by_key(|&(c, _)| c)
            .unwrap_or((0, 0));
        (best_count as f32 / reference.len() as f32 * 100.0, -(best_off as isize))
    }
}

/// Look up what the query has at each diagnostic SNP position given the alignment offset.
fn call_snps(query: &[u8], alignment_offset: isize) -> Vec<SnpCall> {
    HSP65_SNPS
        .iter()
        .filter_map(|&(ref_pos, gastri_base, kansasii_base)| {
            let query_pos = ref_pos as isize - alignment_offset;
            if query_pos >= 0 && (query_pos as usize) < query.len() {
                let query_base = query[query_pos as usize].to_ascii_uppercase();
                Some(SnpCall { ref_pos, query_base, gastri_base, kansasii_base })
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

// ── Public API ────────────────────────────────────────────────────────────────

/// Align `query` against all embedded reference sequences and return every hit,
/// sorted by identity descending (best match first).
pub fn identify_sequence(query: &[u8]) -> Vec<SeqIdHit> {
    let refs = [
        parse_fasta(REF_AF547836),
        parse_fasta(REF_AF547849),
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
            let snp_calls = call_snps(aligned_query, offset);
            SeqIdHit {
                accession,
                description,
                identity,
                is_reverse,
                snp_calls,
                aligned_query: aligned_query.to_vec(),
                alignment_offset: offset,
            }
        })
        .collect();

    hits.sort_by(|a, b| b.identity.partial_cmp(&a.identity).unwrap_or(std::cmp::Ordering::Equal));
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
        snp_calls: vec![],
        aligned_query: aligned_query.to_vec(),
        alignment_offset: offset,
    }]
}
