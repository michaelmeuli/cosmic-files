use super::erm41::reverse_complement;

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
        let query = &self.aligned_query;
        let refseq = &self.ref_seq;
        let offset = self.alignment_offset;

        let (ref_padded, query_padded): (Vec<u8>, Vec<u8>) = if query.len() <= refseq.len() {
            let start = offset as usize;
            let end = start + query.len();
            let ref_p = refseq.clone();
            let query_p: Vec<u8> = (0..refseq.len())
                .map(|i| {
                    if i >= start && i < end {
                        query[i - start]
                    } else {
                        b'-'
                    }
                })
                .collect();
            (ref_p, query_p)
        } else {
            let start = (-offset) as usize;
            let end = start + refseq.len();
            let query_p = query.clone();
            let ref_p: Vec<u8> = (0..query.len())
                .map(|i| {
                    if i >= start && i < end {
                        refseq[i - start]
                    } else {
                        b'-'
                    }
                })
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
            let ref_chunk = std::str::from_utf8(&ref_padded[chunk_start..chunk_end]).unwrap_or("");
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
                .map(|i| {
                    if i >= start && i < end {
                        query[i - start]
                    } else {
                        b'-'
                    }
                })
                .collect();
            (ref_p, query_p)
        } else {
            let start = (-offset) as usize;
            let end = start + refseq.len();
            let query_p = query.clone();
            let ref_p: Vec<u8> = (0..query.len())
                .map(|i| {
                    if i >= start && i < end {
                        refseq[i - start]
                    } else {
                        b'-'
                    }
                })
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

        let orient = if self.is_reverse {
            "Reverse Complement"
        } else {
            "Forward"
        };
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
            let ref_chunk = std::str::from_utf8(&ref_padded[chunk_start..chunk_end]).unwrap_or("");
            let match_chunk =
                std::str::from_utf8(&match_line[chunk_start..chunk_end]).unwrap_or("");
            let query_chunk =
                std::str::from_utf8(&query_padded[chunk_start..chunk_end]).unwrap_or("");

            out.push_str(&format!("Ref   {:5}: {}\n", ref_pos, ref_chunk));
            out.push_str(&format!("             {match_chunk}\n"));
            out.push_str(&format!("Query {:5}: {}\n\n", query_pos, query_chunk));

            ref_pos += ref_chunk.bytes().filter(|&b| b != b'-').count();
            query_pos += query_chunk.bytes().filter(|&b| b != b'-').count();
        }
        out
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

// ── FASTA parsing ─────────────────────────────────────────────────────────────

const REF_MYCO_HSP65: &str = include_str!("../../res/sequences/myco_hsp65.fasta");
const REF_MYCO_ERM41: &str = include_str!("../../res/sequences/myco_erm41.fasta");
const REF_MYCO_16S: &str = include_str!("../../res/sequences/myco_16S.fasta");
const REF_MYCO_RPOB: &str = include_str!("../../res/sequences/myco_rpoB.fasta");
const REF_AF547836: &str = include_str!("../../res/sequences/hsp65/AF547836.fasta");
const REF_AF547849: &str = include_str!("../../res/sequences/hsp65/AF547849.fasta");
const REF_AY299134: &str = include_str!("../../res/sequences/hsp65/AY299134.fasta");
const REF_AY299145: &str = include_str!("../../res/sequences/hsp65/AY299145.fasta");
const REF_MAB2297: &str = include_str!("../../res/sequences/MAB_2297.fasta");

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
                let m = query
                    .iter()
                    .zip(window)
                    .filter(|(a, b)| a.to_ascii_uppercase() == b.to_ascii_uppercase())
                    .count();
                (m, off)
            })
            .max_by_key(|&(c, _)| c)
            .unwrap_or((0, 0));
        (
            best_count as f32 / query.len() as f32 * 100.0,
            best_off as isize,
        )
    } else {
        let (best_count, best_off) = query
            .windows(reference.len())
            .enumerate()
            .map(|(off, window)| {
                let m = reference
                    .iter()
                    .zip(window)
                    .filter(|(a, b)| a.to_ascii_uppercase() == b.to_ascii_uppercase())
                    .count();
                (m, off)
            })
            .max_by_key(|&(c, _)| c)
            .unwrap_or((0, 0));
        (
            best_count as f32 / reference.len() as f32 * 100.0,
            -(best_off as isize),
        )
    }
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

pub fn identify_hsp65_sequence(query: &[u8]) -> Vec<SeqIdHit> {
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
pub fn identify_species_16S(query: &[u8]) -> Option<SpeciesHit> {
    identify_species(query, REF_MYCO_16S)
}
pub fn identify_species_rpoB(query: &[u8]) -> Option<SpeciesHit> {
    identify_species(query, REF_MYCO_RPOB)
}
