use super::erm41::reverse_complement;

/// Best-hit result from aligning an AB1 read against the reference sequences.
#[derive(Clone, Debug)]
pub struct SeqIdHit {
    /// Accession of the best-matching reference (e.g. "AF547836").
    pub accession: String,
    /// Percent identity of the best local alignment window (0.0–100.0).
    pub identity: f32,
    /// `true` when the reverse complement of the query was the better match.
    pub is_reverse: bool,
}

const REF_AF547836: &str = include_str!("../../res/sequences/AF547836.fasta");
const REF_AF547849: &str = include_str!("../../res/sequences/AF547849.fasta");

/// Parse a FASTA string into `(accession, sequence_bytes)`.
/// Accession is taken from the second pipe-delimited field of the header
/// (e.g. `>ENA|AF547836|…` → `"AF547836"`), falling back to the full header.
fn parse_fasta(fasta: &str) -> (String, Vec<u8>) {
    let mut accession = String::new();
    let mut seq: Vec<u8> = Vec::new();
    for line in fasta.lines() {
        if let Some(rest) = line.strip_prefix('>') {
            accession = rest
                .split('|')
                .nth(1)
                .unwrap_or(rest)
                .to_string();
        } else {
            seq.extend(line.bytes().filter(|b| b.is_ascii_alphabetic()));
        }
    }
    (accession, seq)
}

/// Compute the best percent identity of `query` against `reference` using a
/// sliding-window local alignment (no gaps).  Returns a value in `0.0..=100.0`.
fn sliding_identity(query: &[u8], reference: &[u8]) -> f32 {
    if query.is_empty() || reference.len() < query.len() {
        return 0.0;
    }
    let best = reference
        .windows(query.len())
        .map(|window| {
            query
                .iter()
                .zip(window.iter())
                .filter(|(a, b)| a.to_ascii_uppercase() == b.to_ascii_uppercase())
                .count()
        })
        .max()
        .unwrap_or(0);
    best as f32 / query.len() as f32 * 100.0
}

/// Identify the closest reference sequence for an AB1 basecall read.
///
/// Aligns `query` (and its reverse complement) against each embedded reference
/// sequence using a gapless sliding-window approach and returns the best hit.
pub fn identify_sequence(query: &[u8]) -> Option<SeqIdHit> {
    let refs = [
        parse_fasta(REF_AF547836),
        parse_fasta(REF_AF547849),
    ];
    let rc = reverse_complement(query);

    let mut best: Option<SeqIdHit> = None;
    for (accession, refseq) in &refs {
        let fwd_score = sliding_identity(query, refseq);
        let rev_score = sliding_identity(&rc, refseq);
        let (identity, is_reverse) = if rev_score > fwd_score {
            (rev_score, true)
        } else {
            (fwd_score, false)
        };
        if best.as_ref().map(|h| identity > h.identity).unwrap_or(true) {
            best = Some(SeqIdHit { accession: accession.clone(), identity, is_reverse });
        }
    }
    best
}
