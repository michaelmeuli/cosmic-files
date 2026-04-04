use super::erm41::reverse_complement;

/// Best-hit result from aligning an AB1 read against the reference sequences.
#[derive(Clone, Debug)]
pub struct SeqIdHit {
    /// Accession of the best-matching reference (e.g. "AF547836").
    pub accession: String,
    /// Species / strain description taken from the FASTA header
    /// (e.g. "Mycobacterium gastri strain CIP 104530 65 kDa heat shock protein …").
    pub description: String,
    /// Percent identity of the best local alignment window (0.0–100.0).
    pub identity: f32,
    /// `true` when the reverse complement of the query was the better match.
    pub is_reverse: bool,
}

const REF_AF547836: &str = include_str!("../../res/sequences/AF547836.fasta");
const REF_AF547849: &str = include_str!("../../res/sequences/AF547849.fasta");

/// Parse a FASTA string into `(accession, description, sequence_bytes)`.
///
/// For ENA-style headers (`>ENA|AF547836|AF547836.1 Mycobacterium gastri …`):
/// - accession  → second pipe field (`AF547836`)
/// - description → everything after the first space in the third pipe field
///   (`Mycobacterium gastri strain CIP 104530 …`)
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
            let fwd_score = sliding_identity(query, &refseq);
            let rev_score = sliding_identity(&rc, &refseq);
            let (identity, is_reverse) = if rev_score > fwd_score {
                (rev_score, true)
            } else {
                (fwd_score, false)
            };
            SeqIdHit { accession, description, identity, is_reverse }
        })
        .collect();

    hits.sort_by(|a, b| b.identity.partial_cmp(&a.identity).unwrap_or(std::cmp::Ordering::Equal));
    hits
}
