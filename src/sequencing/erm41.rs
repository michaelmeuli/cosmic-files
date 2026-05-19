use super::reverse_complement;
use super::{ERM41_ANCHOR_L, ERM41_ANCHOR_R, ERM41_FWD_END, ERM41_FWD_START};
use super::{SeqIdHit, best_alignment, parse_fasta_seq};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::LazyLock;

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
            Self::C28 => write!(f, "C28"),
            Self::T28 => write!(f, "T28 — inducible macrolide resistance"),
            Self::G28 => write!(f, "G28"),
            Self::A28 => write!(f, "A28"),
            Self::Ambiguous => write!(f, "Ambiguous (strand disagreement)"),
            Self::Undetermined => write!(f, "Undetermined (anchor not found)"),
        }
    }
}

/// Returns susceptibility for an erm(41) call given the observed LOF SNP calls.
///
/// Returns `Some(true)` if any observed base is a LOF alt — a single LOF mutation is sufficient
/// to render erm(41) non-functional, making the organism susceptible. Otherwise delegates to
/// `pos.is_susceptible()`, preserving `None` for ambiguous or undetermined positions.
pub fn is_susceptible_erm41(pos: &Erm41Position28, snp_calls: &[Erm41LofCall]) -> Option<bool> {
    let has_lof = snp_calls
        .iter()
        .any(|c| c.query_base.map_or(false, |b| c.lof_alts.contains_key(&b)));
    if has_lof {
        Some(true)
    } else {
        pos.is_susceptible()
    }
}

impl Erm41Position28 {
    /// Returns `Some(true)` for susceptible alleles (C28, G28, A28), `Some(false)` for T28
    /// (inducible resistance), and `None` when the call is ambiguous or undetermined.
    pub fn is_susceptible(&self) -> Option<bool> {
        match self {
            Self::C28 | Self::G28 | Self::A28 => Some(true),
            Self::T28 => Some(false),
            Self::Ambiguous | Self::Undetermined => None,
        }
    }

    /// Returns the uppercase nucleotide byte (`b'C'`, `b'T'`, `b'G'`, `b'A'`) at erm41
    /// position 28, located by bracketing it between `ERM41_ANCHOR_L` and `ERM41_ANCHOR_R`.
    /// Returns `None` if either anchor is absent or the read is too short.
    fn call_position28(read: &[u8]) -> Option<u8> {
        let anchor_len = ERM41_ANCHOR_L.len();
        let hit = read
            .windows(anchor_len)
            .position(|w| w.eq_ignore_ascii_case(ERM41_ANCHOR_L))?;
        let pos28 = hit + anchor_len;
        let base = read.get(pos28).copied()?.to_ascii_uppercase();
        let right_start = pos28 + 1;
        let right_end = right_start + ERM41_ANCHOR_R.len();
        if right_end > read.len() {
            return None;
        }
        let right_ok = read[right_start..right_end].eq_ignore_ascii_case(ERM41_ANCHOR_R);
        if !right_ok {
            return None;
        }
        Some(base)
    }

    /// Converts a raw nucleotide byte from [`call_position28`](Self::call_position28) into the
    /// corresponding variant. Returns `None` for any byte that is not `C`, `T`, `G`, or `A`.
    fn from_base(base: Option<u8>) -> Option<Self> {
        match base {
            Some(b'C') => Some(Self::C28),
            Some(b'T') => Some(Self::T28),
            Some(b'G') => Some(Self::G28),
            Some(b'A') => Some(Self::A28),
            _ => None,
        }
    }

    /// Consider both forward and reverse reads for Erm41Position28.
    /// Function is not used at the moment.
    pub fn from_fw_rev(fwd_read: &[u8], rev_read: &[u8]) -> Self {
        let fwd = Self::from_base(Self::call_position28(fwd_read));
        let rc = reverse_complement(rev_read);
        let rev = Self::from_base(Self::call_position28(&rc));

        match (fwd, rev) {
            (Some(a), Some(b)) if a == b => a,
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (Some(_), Some(_)) => Self::Ambiguous,
            (None, None) => Self::Undetermined,
        }
    }

    /// Calls erm41 position 28 from a single read, trying the forward orientation first and
    /// falling back to the reverse complement. Returns [`Undetermined`](Self::Undetermined) if
    /// the anchors are not found in either orientation.
    pub fn from_single_read(read: &[u8]) -> Self {
        if let Some(call) = Self::from_base(Self::call_position28(read)) {
            return call;
        }
        let rc = reverse_complement(read);
        Self::from_base(Self::call_position28(&rc)).unwrap_or(Self::Undetermined)
    }
}

fn translate_codon(codon: &[u8]) -> u8 {
    if codon.len() < 3 {
        return 0;
    }
    let c = [
        codon[0].to_ascii_uppercase(),
        codon[1].to_ascii_uppercase(),
        codon[2].to_ascii_uppercase(),
    ];
    match &c[..] {
        b"TTT" | b"TTC" => b'F',
        b"TTA" | b"TTG" | b"CTT" | b"CTC" | b"CTA" | b"CTG" => b'L',
        b"ATT" | b"ATC" | b"ATA" => b'I',
        b"ATG" => b'M',
        b"GTT" | b"GTC" | b"GTA" | b"GTG" => b'V',
        b"TCT" | b"TCC" | b"TCA" | b"TCG" | b"AGT" | b"AGC" => b'S',
        b"CCT" | b"CCC" | b"CCA" | b"CCG" => b'P',
        b"ACT" | b"ACC" | b"ACA" | b"ACG" => b'T',
        b"GCT" | b"GCC" | b"GCA" | b"GCG" => b'A',
        b"TAT" | b"TAC" => b'Y',
        b"TAA" | b"TAG" | b"TGA" => b'*',
        b"CAT" | b"CAC" => b'H',
        b"CAA" | b"CAG" => b'Q',
        b"AAT" | b"AAC" => b'N',
        b"AAA" | b"AAG" => b'K',
        b"GAT" | b"GAC" => b'D',
        b"GAA" | b"GAG" => b'E',
        b"TGT" | b"TGC" => b'C',
        b"TGG" => b'W',
        b"CGT" | b"CGC" | b"CGA" | b"CGG" | b"AGA" | b"AGG" => b'R',
        b"GGT" | b"GGC" | b"GGA" | b"GGG" => b'G',
        _ => 0,
    }
}

fn three_letter_to_one(aa3: &str) -> u8 {
    match aa3.to_ascii_uppercase().as_str() {
        "ALA" => b'A',
        "ARG" => b'R',
        "ASN" => b'N',
        "ASP" => b'D',
        "CYS" => b'C',
        "GLN" => b'Q',
        "GLU" => b'E',
        "GLY" => b'G',
        "HIS" => b'H',
        "ILE" => b'I',
        "LEU" => b'L',
        "LYS" => b'K',
        "MET" => b'M',
        "PHE" => b'F',
        "PRO" => b'P',
        "SER" => b'S',
        "THR" => b'T',
        "TRP" => b'W',
        "TYR" => b'Y',
        "VAL" => b'V',
        _ => 0,
    }
}

fn empty_string_as_none<'de, D>(de: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = Option::<String>::deserialize(de)?;
    Ok(s.filter(|s| !s.trim().is_empty()))
}

#[derive(Debug, Deserialize)]
struct Erm41LofRow {
    #[serde(rename = "Gene")]
    gene: String,
    #[serde(rename = "Mutation")]
    mutation: String,
    #[serde(rename = "type")]
    variant_type: String,
    /// `None` means no drug resistance annotated — interpret as susceptible (`Some(true)`).
    #[serde(rename = "drug", default, deserialize_with = "empty_string_as_none")]
    drug: Option<String>,
}

/// Parse loss-of-function SNPs for erm(41) from a ntm-db resistance CSV.
///
/// Returns a map keyed by **0-based nucleotide position** in the erm(41) reference sequence.
/// Each value is a tuple:
/// - `.0` — the wild-type base at that position (`u8` ASCII, e.g. `b'A'`)
/// - `.1` — `lof_alts`: a map from **alternative base** (`u8` ASCII) to a
///   `(mutation_label, drug)` pair, where `mutation_label` is the HGVS protein annotation
///   (e.g. `"p.Trp28*"`) and `drug` is the affected drug (`None` if absent in the CSV,
///   interpreted as susceptible).
///   Only single-nucleotide substitutions that produce the annotated LoF amino-acid change
///   (stop codon or annotated replacement) are included; synonymous changes are skipped.
fn parse_erm41_lof_snps(
    csv: &str,
    refseq: &[u8],
) -> BTreeMap<usize, (u8, BTreeMap<u8, (String, Option<String>)>)> {
    let mut rdr = csv::Reader::from_reader(csv.as_bytes());
    let mut map: BTreeMap<usize, (u8, BTreeMap<u8, (String, Option<String>)>)> = BTreeMap::new();
    for row in rdr.deserialize::<Erm41LofRow>() {
        let row = match row {
            Ok(r) => r,
            Err(_) => continue,
        };
        if row.gene.trim() != "erm(41)" || row.variant_type.trim() != "loss_of_function" {
            continue;
        }
        let m = row.mutation.trim();
        let rest = match m.strip_prefix("p.") {
            Some(r) if r.len() >= 4 => r,
            _ => continue,
        };
        let digits_end = rest[3..]
            .find(|c: char| !c.is_ascii_digit())
            .map(|i| i + 3)
            .unwrap_or(rest.len());
        if digits_end <= 3 {
            continue;
        }
        let prot_pos: usize = match rest[3..digits_end].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let target_str = &rest[digits_end..];
        let target_aa = if target_str == "*" {
            b'*'
        } else if target_str.len() >= 3 {
            three_letter_to_one(&target_str[..3])
        } else {
            continue;
        };
        if target_aa == 0 {
            continue;
        }
        let codon_start = (prot_pos - 1) * 3;
        if codon_start + 3 > refseq.len() {
            continue;
        }
        let ref_codon = [
            refseq[codon_start].to_ascii_uppercase(),
            refseq[codon_start + 1].to_ascii_uppercase(),
            refseq[codon_start + 2].to_ascii_uppercase(),
        ];
        for codon_pos in 0..3usize {
            let wt_base = ref_codon[codon_pos];
            for &alt in b"ACGT" {
                if alt == wt_base {
                    continue;
                }
                let mut alt_codon = ref_codon;
                alt_codon[codon_pos] = alt;
                if translate_codon(&alt_codon) == target_aa {
                    let ref_pos = codon_start + codon_pos;
                    let entry = map
                        .entry(ref_pos)
                        .or_insert_with(|| (wt_base, BTreeMap::new()));
                    entry
                        .1
                        .entry(alt)
                        .or_insert_with(|| (m.to_string(), row.drug.clone()));
                }
            }
        }
    }
    map
}

static ERM41_LOF_SNPS: LazyLock<
    BTreeMap<&'static str, BTreeMap<usize, (u8, BTreeMap<u8, (String, Option<String>)>)>>,
> = LazyLock::new(|| {
    [(
        "M. abscessus subsp. abscessus",
        include_str!("../../res/sequences/ntm-db/db/Mycobacterium_abscessus/variants.csv"),
        super::REF_ERM41_ABSCESSUS,
    )]
    .into_iter()
    .map(|(desc, csv, fasta)| (desc, parse_erm41_lof_snps(csv, &parse_fasta_seq(fasta))))
    .collect()
});

#[derive(Clone, Debug)]
pub struct Erm41LofCall {
    pub ref_pos: usize,
    pub query_base: Option<u8>,
    pub wt_base: u8,
    /// Maps each loss-of-function alt base to `(mutation_label, drug)`.
    pub lof_alts: BTreeMap<u8, (String, Option<String>)>,
}

impl Erm41LofCall {
    pub fn call_tag(&self) -> String {
        match self.query_base {
            None => "NA".to_string(),
            Some(b) if b == self.wt_base => format!("{} (wt)", b as char),
            Some(b) if self.lof_alts.contains_key(&b) => {
                format!("{} ({})", b as char, self.lof_alts[&b].0)
            }
            Some(b) => format!("{} (novel variant)", b as char),
        }
    }
}

/// Maps each known loss-of-function SNP position to the base observed in the query sequence,
/// adjusting for the alignment offset between reference and query coordinates.
///
/// `snps` maps each reference position to `(wt_base, lof_alts)`, where `lof_alts` maps each
/// loss-of-function alternate base to a `(mutation_label, drug)` pair.
fn call_erm41_lof_snps(
    snps: &BTreeMap<usize, (u8, BTreeMap<u8, (String, Option<String>)>)>,
    query: &[u8],
    alignment_offset: isize,
) -> Vec<Erm41LofCall> {
    snps.iter()
        .map(|(&ref_pos, (wt_base, lof_alts))| {
            let query_pos = ref_pos as isize - alignment_offset;
            let query_base = if query_pos >= 0 && (query_pos as usize) < query.len() {
                Some(query[query_pos as usize].to_ascii_uppercase())
            } else {
                None
            };
            Erm41LofCall {
                ref_pos,
                query_base,
                wt_base: *wt_base,
                lof_alts: lof_alts.clone(),
            }
        })
        .collect()
}

pub(super) fn find_erm41_display_window(
    bases: &[u8],
    peak_locs: &[u16],
) -> Option<(u16, u16, bool, u16)> {
    // Flanking bases to show: 9 before pos28, 11 after (pos28 is the first of the 11)
    const LEFT: usize = 9;
    const RIGHT: usize = 11;

    let anchor_len: u16 = ERM41_ANCHOR_L.len() as u16;

    // --- Forward orientation: ANCHOR_L directly in PBAS ---
    if let Some(hit) = bases
        .windows(anchor_len as usize)
        .position(|w| w.eq_ignore_ascii_case(ERM41_ANCHOR_L))
    {
        let pos28 = hit + anchor_len as usize;
        if let Some(window) = super::scan_window(pos28, LEFT, RIGHT, peak_locs) {
            return Some((window.0, window.1, false, pos28 as u16));
        }
    }

    let rc_anchor_r: Vec<u8> = reverse_complement(ERM41_ANCHOR_R);
    if let Some(hit) = bases
        .windows(rc_anchor_r.len())
        .position(|w| w.eq_ignore_ascii_case(&rc_anchor_r))
    {
        let pos28_comp = hit + rc_anchor_r.len();
        if let Some(window) = super::scan_window(pos28_comp, RIGHT, LEFT, peak_locs) {
            return Some((window.0, window.1, true, pos28_comp as u16));
        }
    }

    None
}

/// Unlike identify_sequence_hsp65() and identify_sequence_rrl_ntm(), this only uses reference sequences extracted via sequences.toml and not the database fetched via fetch_myco_sequences().
pub fn identify_sequence_erm41(query: &[u8]) -> Vec<SeqIdHit> {
    let query = super::trim_start_end(query, ERM41_FWD_START, ERM41_FWD_END);
    let rc = reverse_complement(query);
    let erm41_pos28 = Erm41Position28::from_single_read(query);

    let refs: &[(&str, &str, &str)] = &[
        (
            super::REF_ERM41_ABSCESSUS,
            "REF_ERM41_ABSCESSUS",
            "M. abscessus subsp. abscessus",
        ),
        (
            super::REF_ERM41_BOLLETII,
            "REF_ERM41_BOLLETII",
            "M. abscessus subsp. bolletii",
        ),
        (
            super::REF_ERM41_MASSILENSE,
            "REF_ERM41_MASSILENSE",
            "M. abscessus subsp. massiliense",
        ),
    ];

    let mut hits: Vec<SeqIdHit> = refs
        .iter()
        .map(|(fasta, accession, description)| {
            let refseq = parse_fasta_seq(fasta);
            let (fwd_id, fwd_off) = best_alignment(query, &refseq);
            let (rev_id, rev_off) = best_alignment(&rc, &refseq);
            let (identity, is_reverse, aligned_query, offset) = if rev_id > fwd_id {
                (rev_id, true, rc.as_slice(), rev_off)
            } else {
                (fwd_id, false, query, fwd_off)
            };
            // Abscessus LOF SNP positions apply to all three subspecies — bolletii and
            // massiliense are sequence-similar enough, and no separate variants.csv exists for them.
            let erm41_snp_calls = ERM41_LOF_SNPS
                .get("M. abscessus subsp. abscessus")
                .map(|snps| call_erm41_lof_snps(snps, aligned_query, offset))
                .unwrap_or_default();
            SeqIdHit {
                accession: accession.to_string(),
                description: description.to_string(),
                identity,
                is_reverse,
                kansasii_gastri_snp_calls: vec![],
                marinum_ulcerans_snp_calls: vec![],
                rrl_snp_calls: vec![],
                erm41_snp_calls,
                aligned_query: aligned_query.to_vec(),
                alignment_offset: offset,
                erm41position28_opt: Some(erm41_pos28.clone()),
                ref_seq: refseq,
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
