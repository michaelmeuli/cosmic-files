//! pncA pyrazinamide resistance calling for *M. tuberculosis* complex.
//!
//! Unlike the fixed-anchor SNP sets in [`erm41`](super::erm41)/[`rrl`](super::rrl)/
//! [`rrs`](super::rrs), pncA resistance mutations are scattered across the whole gene (plus a
//! promoter region) with no small fixed set of diagnostic positions, so this module dynamically
//! parses the WHO resistance catalogue (`tbprofiler/mutations.csv`) into per-position lookup
//! maps at startup ([`PNCA_RESISTANCE_SNPS`]) and calls every site the catalogue mentions
//! ([`PncaSnpCall`]) against the read's alignment. Every insertion or deletion inside the
//! alignment is listed as well, so that a frameshifted gene never looks wildtype, and is looked
//! up among the catalogue's indel rows by its HGVS name ([`PNCA_RESISTANCE_INDELS`]). The generic
//! rows (`frameshift_variant`, gene ablations) are not applied. Changes at positions the
//! catalogue doesn't list (a promoter base, or a codon's amino acid, including a premature stop)
//! are listed too, as untested; synonymous ones are not. See [`is_susceptible_pnca`] for how
//! those calls are combined into one verdict.

use super::tb_data::confidence_rank;
use super::{
    GappedAlignment, REF_PNCA, SeqIdHit, align_to_ref, base_at_ref_pos, parse_multi_fasta,
    reverse_complement, trim_alignment_ends,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// Extra bases fetched upstream of the start codon when building `pnca/pnca_h37rv.fasta`
/// (must match `upstream_flank` in `res/sequences/sequences.toml`'s pncA `[[genome]]` entry).
/// HGVS `c.-N` positions are resolved against this flank.
const UPSTREAM_FLANK: isize = 50;

/// Maps a signed HGVS coding-sequence position (negative = promoter, e.g. `c.-11`) to
/// `(wt_base, alts)` where `alts` maps each resistance alt to `(drugs, WHO confidence label)`.
type PncaNtSnpMap = BTreeMap<isize, (u8, BTreeMap<u8, (Vec<String>, String)>)>;

/// Maps a 1-based codon number to `(wt_aa, alts)` where `alts` maps each resistance alt amino
/// acid (3-letter code, or `"*"` for nonsense) to `(drugs, WHO confidence label)`.
type PncaAaSnpMap = BTreeMap<usize, (String, BTreeMap<String, (Vec<String>, String)>)>;

/// Standard 3-letter amino acid codes used by the WHO catalogue `p.` notation.
pub(super) const AA3: [&str; 20] = [
    "Ala", "Arg", "Asn", "Asp", "Cys", "Gln", "Glu", "Gly", "His", "Ile", "Leu", "Lys", "Met",
    "Phe", "Pro", "Ser", "Thr", "Trp", "Tyr", "Val",
];

/// One row of `tbprofiler/mutations.csv` (the WHO resistance catalogue).
#[derive(Debug, Deserialize, Clone)]
pub(super) struct MutationRow {
    #[serde(rename = "Gene")]
    pub(super) gene: String,
    #[serde(rename = "Mutation")]
    pub(super) mutation: String,
    #[serde(rename = "drug")]
    pub(super) drug: String,
    /// WHO confidence label; empty means this row carries no resistance evidence and is
    /// skipped (see [`confidence_rank`]).
    #[serde(rename = "confidence")]
    pub(super) confidence: String,
}

/// Translate a single codon to its 3-letter amino acid code (`"*"` for a stop codon).
/// Returns `None` for incomplete codons or non-ACGT bytes.
pub(super) fn translate_codon(codon: &[u8]) -> Option<&'static str> {
    let c = [
        codon.first()?.to_ascii_uppercase(),
        codon.get(1)?.to_ascii_uppercase(),
        codon.get(2)?.to_ascii_uppercase(),
    ];
    Some(match &c {
        b"TTT" | b"TTC" => "Phe",
        b"TTA" | b"TTG" | b"CTT" | b"CTC" | b"CTA" | b"CTG" => "Leu",
        b"ATT" | b"ATC" | b"ATA" => "Ile",
        b"ATG" => "Met",
        b"GTT" | b"GTC" | b"GTA" | b"GTG" => "Val",
        b"TCT" | b"TCC" | b"TCA" | b"TCG" | b"AGT" | b"AGC" => "Ser",
        b"CCT" | b"CCC" | b"CCA" | b"CCG" => "Pro",
        b"ACT" | b"ACC" | b"ACA" | b"ACG" => "Thr",
        b"GCT" | b"GCC" | b"GCA" | b"GCG" => "Ala",
        b"TAT" | b"TAC" => "Tyr",
        b"TAA" | b"TAG" | b"TGA" => "*",
        b"CAT" | b"CAC" => "His",
        b"CAA" | b"CAG" => "Gln",
        b"AAT" | b"AAC" => "Asn",
        b"AAA" | b"AAG" => "Lys",
        b"GAT" | b"GAC" => "Asp",
        b"GAA" | b"GAG" => "Glu",
        b"TGT" | b"TGC" => "Cys",
        b"TGG" => "Trp",
        b"CGT" | b"CGC" | b"CGA" | b"CGG" | b"AGA" | b"AGG" => "Arg",
        b"GGT" | b"GGC" | b"GGA" | b"GGG" => "Gly",
        _ => return None,
    })
}

/// 0-based index into `REF_PNCA` of a signed HGVS coding-sequence position. There is no
/// `c.0` — `c.-1` sits immediately before `c.1` (the `A` of the start codon).
fn nt_pos_to_ref_idx(c_pos: isize) -> Option<usize> {
    let offset = if c_pos > 0 { c_pos - 1 } else { c_pos };
    let idx = UPSTREAM_FLANK + offset;
    if idx < 0 { None } else { Some(idx as usize) }
}

/// Inverse of [`nt_pos_to_ref_idx`]: the signed HGVS position of a 0-based `REF_PNCA` index.
fn ref_idx_to_nt_pos(ref_idx: usize) -> Option<isize> {
    let offset = isize::try_from(ref_idx).ok()? - UPSTREAM_FLANK;
    Some(if offset >= 0 { offset + 1 } else { offset })
}

/// 0-based index into `REF_PNCA` of the first base of a 1-based codon number.
fn codon_to_ref_idx(codon: usize) -> Option<usize> {
    nt_pos_to_ref_idx(isize::try_from(codon.checked_sub(1)? * 3 + 1).ok()?)
}

/// Parses `tbprofiler/mutations.csv`, keeping only `pncA` rows whose mutation is a simple
/// nucleotide substitution (`c.POS[wt]>[alt]`, promoter or coding) or a single-codon amino
/// acid substitution / nonsense call (`p.WtNNNAlt` / `p.WtNNN*`).
///
/// Frameshifts, in-frame indels, delins, and stop-codon extensions (`fs`, `del`, `dup`,
/// `delins`, `ext`) are not sites with a fixed position and are skipped here; the indel rows are
/// read by [`parse_pnca_resistance_indels`] (stop-codon extensions by neither).
fn parse_pnca_resistance_snps(csv: &str) -> (PncaNtSnpMap, PncaAaSnpMap) {
    static NT_SNP_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^c\.(-?\d+)([ACGT])>([ACGT])$").unwrap());
    static CODON_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^p\.([A-Za-z]{3})(\d+)([A-Za-z]{3}|\*)$").unwrap());

    let mut rdr = csv::Reader::from_reader(csv.as_bytes());
    let mut nt_map: PncaNtSnpMap = BTreeMap::new();
    let mut aa_map: PncaAaSnpMap = BTreeMap::new();

    for row in rdr.deserialize::<MutationRow>() {
        let Ok(row) = row else { continue };
        if row.gene.trim() != "pncA" {
            continue;
        }
        let confidence = row.confidence.trim().to_string();
        if confidence.is_empty() {
            continue;
        }
        let drug = row.drug.trim().to_string();
        let m = row.mutation.trim();

        // Keep the strongest (lowest-rank) confidence seen for a given alt, since the same
        // mutation can appear once under "who_confidence" and once under "drug_resistance".
        if let Some(caps) = NT_SNP_RE.captures(m) {
            let Ok(c_pos) = caps[1].parse::<isize>() else {
                continue;
            };
            let wt = caps[2].as_bytes()[0];
            let alt = caps[3].as_bytes()[0];
            let entry = nt_map.entry(c_pos).or_insert_with(|| (wt, BTreeMap::new()));
            let variant = entry
                .1
                .entry(alt)
                .or_insert_with(|| (Vec::new(), confidence.clone()));
            if !variant.0.contains(&drug) {
                variant.0.push(drug);
            }
            if confidence_rank(&confidence) < confidence_rank(&variant.1) {
                variant.1 = confidence.clone();
            }
        } else if let Some(caps) = CODON_RE.captures(m) {
            let wt_aa = caps[1].to_string();
            let alt_aa = caps[3].to_string();
            if !AA3.contains(&wt_aa.as_str()) || (alt_aa != "*" && !AA3.contains(&alt_aa.as_str()))
            {
                continue;
            }
            let Some(codon) = caps[2].parse::<usize>().ok().filter(|&c| c > 0) else {
                continue;
            };
            let entry = aa_map
                .entry(codon)
                .or_insert_with(|| (wt_aa.clone(), BTreeMap::new()));
            let variant = entry
                .1
                .entry(alt_aa)
                .or_insert_with(|| (Vec::new(), confidence.clone()));
            if !variant.0.contains(&drug) {
                variant.0.push(drug);
            }
            if confidence_rank(&confidence) < confidence_rank(&variant.1) {
                variant.1 = confidence.clone();
            }
        }
    }
    (nt_map, aa_map)
}

static PNCA_RESISTANCE_SNPS: LazyLock<(PncaNtSnpMap, PncaAaSnpMap)> =
    LazyLock::new(|| parse_pnca_resistance_snps(include_str!("../../tbprofiler/mutations.csv")));

/// Maps an indel's catalogue name (e.g. `p.His51fs`, `c.-5delG`) to `(drugs, WHO confidence
/// label)`.
type PncaIndelMap = BTreeMap<String, (Vec<String>, String)>;

/// The pncA rows of `tbprofiler/mutations.csv` that name one specific indel: protein-level
/// frameshifts, deletions, insertions, duplications and delins, and promoter indels. Rows without
/// a confidence label are skipped, as in [`parse_pnca_resistance_snps`].
fn parse_pnca_resistance_indels(csv: &str) -> PncaIndelMap {
    static INDEL_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(p\.[A-Z][a-z]{2}\d+(_[A-Z][a-z]{2}\d+)?(fs|dup|del(ins([A-Z][a-z]{2})+)?|ins([A-Z][a-z]{2})+)|c\.-\d+(_-?\d+)?(del|ins|dup)[ACGT]+)$",
        )
        .unwrap()
    });
    let mut map = PncaIndelMap::new();
    for row in csv::Reader::from_reader(csv.as_bytes()).deserialize::<MutationRow>() {
        let Ok(row) = row else { continue };
        let name = row.mutation.trim();
        let confidence = row.confidence.trim().to_string();
        if row.gene.trim() != "pncA" || confidence.is_empty() || !INDEL_RE.is_match(name) {
            continue;
        }
        let drug = row.drug.trim().to_string();
        let entry = map
            .entry(name.to_string())
            .or_insert_with(|| (Vec::new(), confidence.clone()));
        if !entry.0.contains(&drug) {
            entry.0.push(drug);
        }
        if confidence_rank(&confidence) < confidence_rank(&entry.1) {
            entry.1 = confidence;
        }
    }
    map
}

static PNCA_RESISTANCE_INDELS: LazyLock<PncaIndelMap> =
    LazyLock::new(|| parse_pnca_resistance_indels(include_str!("../../tbprofiler/mutations.csv")));

/// [`PncaCallKind::Codon::query_aa`] of a covered codon with an unresolved base.
const UNRESOLVED_AA: &str = "?";

/// Amino acids of the coding sequence in `seq` (promoter flank + CDS); `"?"` for a codon with an
/// unresolved base.
fn translate_cds(seq: &[u8]) -> Vec<&'static str> {
    seq.get(UPSTREAM_FLANK as usize..)
        .unwrap_or_default()
        .chunks_exact(3)
        .map(|codon| translate_codon(codon).unwrap_or("?"))
        .collect()
}

/// HGVS frameshift name of `mutant` against `reference` (both promoter flank + CDS): the first
/// codon whose amino acid differs, e.g. `"p.His51fs"`.
fn frameshift_name(reference: &[u8], mutant: &[u8]) -> Option<String> {
    let (wt, new) = (translate_cds(reference), translate_cds(mutant));
    let first = (0..wt.len()).find(|&i| new.get(i) != Some(&wt[i]))?;
    Some(format!("p.{}{}fs", wt[first], first + 1))
}

/// HGVS protein name of the in-frame change from `reference` to `mutant`, e.g.
/// `"p.Glu127_Asp129del"` or `"p.Asp63_Ser67delinsGlu"`. Trimming the common start before the
/// common end places a change inside a repeat at its 3′-most position, as HGVS requires.
fn in_frame_name(reference: &[u8], mutant: &[u8]) -> Option<String> {
    let (wt, new) = (translate_cds(reference), translate_cds(mutant));
    let shortest = wt.len().min(new.len());
    let start = (0..shortest).find(|&i| wt[i] != new[i]).unwrap_or(shortest);
    let end = (0..shortest - start)
        .find(|&i| wt[wt.len() - 1 - i] != new[new.len() - 1 - i])
        .unwrap_or(shortest - start);
    let removed = &wt[start..wt.len() - end];
    let added = new[start..new.len() - end].concat();
    // Residues `from..to` (0-based) as "Xaa12" or "Xaa12_Yaa14".
    let range = |from: usize, to: usize| {
        if to - from == 1 {
            format!("{}{to}", wt[from])
        } else {
            format!("{}{}_{}{to}", wt[from], from + 1, wt[to - 1])
        }
    };
    let stop = wt.len() - end;
    match (removed.is_empty(), added.is_empty()) {
        (true, true) => None,
        (false, true) => Some(format!("p.{}del", range(start, stop))),
        (false, false) => Some(format!("p.{}delins{added}", range(start, stop))),
        (true, false) => {
            let n = new.len() - wt.len();
            if start >= n && wt[start - n..start] == new[start..start + n] {
                Some(format!("p.{}dup", range(start - n, start)))
            } else if start > 0 && start < wt.len() {
                Some(format!("p.{}ins{added}", range(start - 1, start + 1)))
            } else {
                None
            }
        }
    }
}

/// HGVS name of a promoter indel, moved to its 3′-most equivalent position, e.g. `"c.-5delG"`.
/// `None` if that position isn't upstream of the start codon.
fn promoter_indel_name(
    reference: &[u8],
    mut pos: usize,
    deletion: bool,
    bases: &str,
) -> Option<String> {
    let mut bases = bases.as_bytes().to_vec();
    if deletion {
        while reference.get(pos + bases.len()) == reference.get(pos) {
            pos += 1;
        }
        bases = reference.get(pos..pos + bases.len())?.to_ascii_uppercase();
    } else {
        while reference.get(pos).is_some_and(|b| {
            bases
                .first()
                .is_some_and(|first| b.eq_ignore_ascii_case(first))
        }) {
            bases.rotate_left(1);
            pos += 1;
        }
    }
    if pos >= UPSTREAM_FLANK as usize {
        return None;
    }
    let c_pos = ref_idx_to_nt_pos;
    let bases = String::from_utf8(bases).ok()?;
    Some(if !deletion {
        format!(
            "c.{}_{}ins{bases}",
            c_pos(pos.checked_sub(1)?)?,
            c_pos(pos)?
        )
    } else if bases.len() == 1 {
        format!("c.{}del{bases}", c_pos(pos)?)
    } else {
        let last = c_pos(pos + bases.len() - 1)?;
        format!("c.{}_{last}del{bases}", c_pos(pos)?)
    })
}

/// One pncA call: a catalogued site (a single nucleotide, promoter or coding, or a single codon),
/// or a change the read shows elsewhere (an unlisted promoter base or codon, or an indel).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PncaCallKind {
    /// A single promoter or coding-sequence nucleotide substitution (HGVS `c.` notation).
    Nucleotide {
        wt_base: u8,
        /// Base observed in the query at this position, or `None` if not covered.
        query_base: Option<u8>,
    },
    /// A single-codon amino acid substitution or nonsense call (HGVS `p.` notation).
    Codon {
        /// 1-based codon number.
        codon: usize,
        /// Wild-type amino acid, as a 3-letter code.
        wt_aa: String,
        /// Amino acid translated from the query's codon, or `None` if not fully covered.
        query_aa: Option<String>,
    },
    /// An insertion or deletion relative to the reference.
    Indel {
        deletion: bool,
        /// The deleted reference bases, or the inserted query bases.
        bases: String,
        /// Name of the catalogue row this indel matches, if any.
        #[serde(default)]
        catalogue: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(from = "PncaSnpCallStored")]
pub struct PncaSnpCall {
    /// 0-based position in the pncA reference sequence: the substituted base for nucleotide
    /// calls, the first base of the codon for codon calls, the first deleted base, or the base
    /// an insertion precedes.
    pub ref_pos: usize,
    pub kind: PncaCallKind,
    /// Maps each resistance-conferring alt (a 1-character base string, an amino acid
    /// 3-letter code / `"*"`, or a matched indel's catalogue name) to
    /// `(drugs, WHO confidence label)`.
    ///
    /// Not serialised: it is a copy of the catalogue entry for this site (a pncA hit carries
    /// ~190 calls, so storing it dominated the disk cache). Deserialisation looks it up again
    /// from [`PNCA_RESISTANCE_SNPS`] via [`PncaSnpCallStored`].
    #[serde(skip_serializing)]
    pub resistance_alts: BTreeMap<String, (Vec<String>, String)>,
}

/// On-disk form of [`PncaSnpCall`]. `resistance_alts` is accepted (and ignored) so caches
/// written before it stopped being serialised still load.
#[derive(Deserialize)]
struct PncaSnpCallStored {
    ref_pos: usize,
    kind: PncaCallKind,
    #[serde(default, rename = "resistance_alts")]
    _resistance_alts: serde::de::IgnoredAny,
}

impl From<PncaSnpCallStored> for PncaSnpCall {
    fn from(s: PncaSnpCallStored) -> Self {
        let resistance_alts = catalogue_alts(s.ref_pos, &s.kind);
        Self {
            ref_pos: s.ref_pos,
            kind: s.kind,
            resistance_alts,
        }
    }
}

/// The catalogued resistance alts for one site, keyed as in [`PncaSnpCall::resistance_alts`].
fn catalogue_alts(ref_pos: usize, kind: &PncaCallKind) -> BTreeMap<String, (Vec<String>, String)> {
    let (nt_map, aa_map) = &*PNCA_RESISTANCE_SNPS;
    match kind {
        PncaCallKind::Nucleotide { .. } => ref_idx_to_nt_pos(ref_pos)
            .and_then(|c_pos| nt_map.get(&c_pos))
            .map(|(_, alts)| nt_alts_to_strings(alts))
            .unwrap_or_default(),
        PncaCallKind::Codon { codon, .. } => aa_map
            .get(codon)
            .map(|(_, alts)| alts.clone())
            .unwrap_or_default(),
        PncaCallKind::Indel { catalogue, .. } => catalogue
            .as_ref()
            .and_then(|name| PNCA_RESISTANCE_INDELS.get_key_value(name))
            .map(|(name, entry)| BTreeMap::from([(name.clone(), entry.clone())]))
            .unwrap_or_default(),
    }
}

/// Re-keys a nucleotide site's alts by 1-character base string.
fn nt_alts_to_strings(
    alts: &BTreeMap<u8, (Vec<String>, String)>,
) -> BTreeMap<String, (Vec<String>, String)> {
    alts.iter()
        .map(|(&b, v)| ((b as char).to_string(), v.clone()))
        .collect()
}

impl PncaSnpCall {
    /// HGVS-style label for this site, e.g. `"c.-11A>C"`, `"p.Ala102Pro"`, `"c.151del"` or
    /// `"c.150_151insTT"`. An indel inside a repeat may be placed at any of its equivalent
    /// positions, not necessarily the 3′-most one HGVS asks for.
    /// When the query didn't cover the site (`query_base`/`query_aa` is `None`), the alt is `"?"`.
    pub fn site_label(&self) -> String {
        match &self.kind {
            PncaCallKind::Nucleotide {
                wt_base,
                query_base,
            } => {
                // Recover the signed c. position from ref_pos for display.
                let offset = self.ref_pos as isize - UPSTREAM_FLANK;
                if offset >= 0 {
                    format!(
                        "c.{}{}>{}",
                        offset + 1,
                        *wt_base as char,
                        query_base.map(|b| b as char).unwrap_or('?')
                    )
                } else {
                    format!(
                        "c.{}{}>{}",
                        offset,
                        *wt_base as char,
                        query_base.map(|b| b as char).unwrap_or('?')
                    )
                }
            }
            PncaCallKind::Codon {
                codon,
                wt_aa,
                query_aa,
            } => format!("p.{}{}{}", wt_aa, codon, query_aa.as_deref().unwrap_or("?")),
            PncaCallKind::Indel {
                deletion, bases, ..
            } => {
                let c_pos = |idx: usize| ref_idx_to_nt_pos(idx).unwrap_or_default();
                if !*deletion {
                    let before = c_pos(self.ref_pos.saturating_sub(1));
                    format!("c.{before}_{}ins{bases}", c_pos(self.ref_pos))
                } else if bases.len() == 1 {
                    format!("c.{}del", c_pos(self.ref_pos))
                } else {
                    let last = c_pos(self.ref_pos + bases.len() - 1);
                    format!("c.{}_{last}del", c_pos(self.ref_pos))
                }
            }
        }
    }

    /// Human-readable annotation for the observed allele at this site: empty when it matches
    /// wildtype or wasn't covered, the catalogued `(drugs, confidence)` when it's a known
    /// resistance alt, or `"<alt> (mutation, untested)"` for an uncatalogued variant (an unlisted
    /// premature stop or unreadable codon says so instead). An indel
    /// in the catalogue also names the matched row; any other says whether it shifts the reading
    /// frame.
    pub fn call_tag(&self) -> String {
        match &self.kind {
            PncaCallKind::Nucleotide {
                wt_base,
                query_base,
            } => match query_base {
                None => String::new(),
                Some(b) if b == wt_base => String::new(),
                Some(b) => {
                    let key = (*b as char).to_string();
                    match self.resistance_alts.get(&key) {
                        Some((drugs, confidence)) => {
                            format!("({}, {})", drugs.join(", "), confidence)
                        }
                        None => format!("{} (mutation, untested)", *b as char),
                    }
                }
            },
            PncaCallKind::Codon {
                wt_aa, query_aa, ..
            } => match query_aa {
                None => String::new(),
                Some(aa) if aa == wt_aa => String::new(),
                Some(aa) => match self.resistance_alts.get(aa) {
                    Some((drugs, confidence)) => {
                        format!("({}, {})", drugs.join(", "), confidence)
                    }
                    None if aa == "*" => "premature stop (check read)".to_string(),
                    None if aa == UNRESOLVED_AA => "unresolved codon (check read)".to_string(),
                    None => format!("{aa} (mutation, untested)"),
                },
            },
            PncaCallKind::Indel {
                deletion,
                bases,
                catalogue,
            } => {
                if let Some(name) = catalogue
                    && let Some((drugs, confidence)) = self.resistance_alts.get(name)
                {
                    return format!("({}, {}, catalogue {name})", drugs.join(", "), confidence);
                }
                // The first coding base (`c.1`) follows the upstream flank. A deletion is
                // coding when any deleted base is; an insertion when it lies after `c.1`.
                let flank = UPSTREAM_FLANK as usize;
                let coding = if *deletion {
                    self.ref_pos + bases.len() > flank
                } else {
                    self.ref_pos > flank
                };
                let tag = if !coding {
                    "promoter indel (not assessed)"
                } else if bases.len() % 3 == 0 {
                    "in-frame indel (not assessed)"
                } else {
                    "frameshift (check read)"
                };
                tag.to_string()
            }
        }
    }

    /// Classifies the allele observed at this site, or `None` when the read doesn't cover it
    /// at all (as opposed to covering it and finding wildtype — those are not the same thing).
    fn evidence(&self) -> Option<PncaEvidence> {
        let (observed, wt) = match &self.kind {
            PncaCallKind::Indel { catalogue, .. } => {
                let entry = catalogue
                    .as_ref()
                    .and_then(|name| self.resistance_alts.get(name));
                return Some(match entry {
                    Some((_, conf)) => PncaEvidence::Catalogued(confidence_rank(conf)),
                    None => PncaEvidence::Uncatalogued,
                });
            }
            PncaCallKind::Nucleotide {
                wt_base,
                query_base: Some(b),
            } => ((*b as char).to_string(), *b == *wt_base),
            PncaCallKind::Codon {
                wt_aa,
                query_aa: Some(aa),
                ..
            } => (aa.clone(), aa == wt_aa),
            _ => return None,
        };
        if wt {
            return Some(PncaEvidence::Wildtype);
        }
        Some(match self.resistance_alts.get(&observed) {
            Some((_, conf)) => PncaEvidence::Catalogued(confidence_rank(conf)),
            None => PncaEvidence::Uncatalogued,
        })
    }
}

/// What the read showed at one diagnostic pncA site, for [`is_susceptible_pnca`].
enum PncaEvidence {
    /// Matches the wildtype allele — positive evidence of susceptibility at this site.
    Wildtype,
    /// Differs from wildtype but isn't in the WHO catalogue — neither confirms nor rules out
    /// resistance, but does confirm the site was covered.
    Uncatalogued,
    /// Matches a catalogued resistance-conferring alt, at this confidence rank
    /// (see [`confidence_rank`]; lower = stronger resistance evidence).
    Catalogued(u8),
}

/// All pncA susceptibility evidence for one sample, ready for UI display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PncaSusceptibilityCalls {
    /// Every catalogued diagnostic site, with whatever allele (if any) was observed.
    pub snp_calls: Vec<PncaSnpCall>,
    /// Verdict from [`is_susceptible_pnca`].
    pub is_susceptible: Option<bool>,
}

/// Returns `Some(false)` when any covered site's allele matches a catalogued resistance-
/// conferring alt at confidence rank `< 2` (e.g. "Assoc w R"). Returns `Some(true)` only when
/// every diagnostic site is covered *and* every observed allele is wildtype. Returns `None`
/// whenever any site went uncovered, an uncatalogued variant or an indel was found,
/// weak/uncertain resistance evidence was seen, or no diagnostic site was reached at all.
pub fn is_susceptible_pnca(snp_calls: &[PncaSnpCall]) -> Option<bool> {
    let mut saw_wildtype = false;
    let mut saw_problem = false;
    let mut min_resistant_rank: Option<u8> = None;

    for call in snp_calls {
        match call.evidence() {
            None => saw_problem = true,
            Some(PncaEvidence::Wildtype) => saw_wildtype = true,
            Some(PncaEvidence::Uncatalogued) => saw_problem = true,
            Some(PncaEvidence::Catalogued(rank)) => {
                saw_problem = true;
                min_resistant_rank = Some(min_resistant_rank.map_or(rank, |r| r.min(rank)));
            }
        }
    }

    if min_resistant_rank.is_some_and(|rank| rank < 2) {
        Some(false)
    } else if saw_wildtype && !saw_problem {
        Some(true)
    } else {
        None
    }
}

/// Collect 3 consecutive non-deleted query bases at reference positions `ref_pos..ref_pos+3`.
/// Returns `None` if the position is outside the aligned region or any of the 3 ref positions
/// has a deletion in the query (indels are called separately).
pub(super) fn codon_at_ref_pos(
    gapped_query: &[u8],
    gapped_ref: &[u8],
    ref_start: usize,
    ref_pos: usize,
) -> Option<[u8; 3]> {
    if ref_pos < ref_start {
        return None;
    }
    let mut current = ref_start;
    let mut codon = [0u8; 3];
    let mut idx = 0usize;
    let mut collecting = false;
    for (&q, &r) in gapped_query.iter().zip(gapped_ref.iter()) {
        if r != b'-' {
            if current == ref_pos {
                collecting = true;
            }
            if collecting {
                if q == b'-' {
                    return None;
                }
                codon[idx] = q.to_ascii_uppercase();
                idx += 1;
                if idx == 3 {
                    return Some(codon);
                }
            }
            current += 1;
        }
    }
    None
}

/// Maps each catalogued nucleotide SNP position to the base observed in the query sequence.
fn call_pnca_nt_snps(map: &PncaNtSnpMap, ga: &GappedAlignment) -> Vec<PncaSnpCall> {
    map.iter()
        .filter_map(|(&c_pos, (wt_base, alts))| {
            let ref_pos = nt_pos_to_ref_idx(c_pos)?;
            let query_base =
                base_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos);
            let resistance_alts = nt_alts_to_strings(alts);
            Some(PncaSnpCall {
                ref_pos,
                kind: PncaCallKind::Nucleotide {
                    wt_base: *wt_base,
                    query_base,
                },
                resistance_alts,
            })
        })
        .collect()
}

/// Maps each catalogued codon to the amino acid translated from the query's aligned codon.
fn call_pnca_aa_snps(map: &PncaAaSnpMap, ga: &GappedAlignment) -> Vec<PncaSnpCall> {
    map.iter()
        .filter_map(|(&codon, (wt_aa, alts))| {
            let ref_pos = codon_to_ref_idx(codon)?;
            let query_aa =
                codon_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos)
                    .and_then(|bases| translate_codon(&bases).map(str::to_string));
            Some(PncaSnpCall {
                ref_pos,
                kind: PncaCallKind::Codon {
                    codon,
                    wt_aa: wt_aa.clone(),
                    query_aa,
                },
                resistance_alts: alts.clone(),
            })
        })
        .collect()
}

/// Calls for the changes the read shows at positions the catalogue doesn't list: promoter bases
/// and codons whose amino acid differs from `h37rv` (synonymous changes are left out). Without
/// these, such a read would look wildtype at every listed site. Indels are called separately.
fn call_pnca_unlisted(
    h37rv: &[u8],
    nt_map: &PncaNtSnpMap,
    aa_map: &PncaAaSnpMap,
    ga: &GappedAlignment,
) -> Vec<PncaSnpCall> {
    let flank = UPSTREAM_FLANK as usize;
    let promoter = (0..flank.min(h37rv.len())).filter_map(|ref_pos| {
        if nt_map.contains_key(&ref_idx_to_nt_pos(ref_pos)?) {
            return None;
        }
        let wt_base = h37rv[ref_pos].to_ascii_uppercase();
        let query_base = base_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos)
            .filter(|&b| b != wt_base)?;
        Some(PncaSnpCall {
            ref_pos,
            kind: PncaCallKind::Nucleotide {
                wt_base,
                query_base: Some(query_base),
            },
            resistance_alts: BTreeMap::new(),
        })
    });
    let coding = h37rv
        .get(flank..)
        .unwrap_or_default()
        .chunks_exact(3)
        .enumerate()
        .filter_map(|(i, wt_codon)| {
            let codon = i + 1;
            if aa_map.contains_key(&codon) {
                return None;
            }
            let wt_aa = translate_codon(wt_codon)?;
            let ref_pos = codon_to_ref_idx(codon)?;
            let bases = codon_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos)?;
            let query_aa = translate_codon(&bases).unwrap_or(UNRESOLVED_AA);
            (query_aa != wt_aa).then(|| PncaSnpCall {
                ref_pos,
                kind: PncaCallKind::Codon {
                    codon,
                    wt_aa: wt_aa.to_string(),
                    query_aa: Some(query_aa.to_string()),
                },
                resistance_alts: BTreeMap::new(),
            })
        });
    promoter.chain(coding).collect()
}

/// `reference` with the aligned part replaced by the read: every difference the read shows, not
/// just one indel. A delins aligns as a gap plus mismatches, so only this names it.
fn read_applied(reference: &[u8], ga: &GappedAlignment) -> Option<Vec<u8>> {
    let paired = |(q, r): (&u8, &u8)| *q != b'-' && *r != b'-';
    let columns = || ga.gapped_query.iter().zip(&ga.gapped_ref);
    let first = columns().position(paired)?;
    let last = columns().rposition(paired)?;
    let ref_bases = |end: usize| ga.gapped_ref[..end].iter().filter(|&&b| b != b'-').count();
    let from = ga.ref_start + ref_bases(first);
    let to = ga.ref_start + ref_bases(last + 1);
    let read = ga.gapped_query[first..=last]
        .iter()
        .copied()
        .filter(|&b| b != b'-');
    let mut mutant = reference.get(..from)?.to_vec();
    mutant.extend(read);
    mutant.extend_from_slice(reference.get(to..)?);
    Some(mutant)
}

/// Name of the catalogue row matching the indel of `bases` at `pos` in `reference`.
fn match_pnca_indel(
    reference: &[u8],
    ga: &GappedAlignment,
    pos: usize,
    deletion: bool,
    bases: &str,
) -> Option<String> {
    if !bases.bytes().all(|b| b"ACGT".contains(&b)) {
        return None;
    }
    let listed = |name: Option<String>| name.filter(|n| PNCA_RESISTANCE_INDELS.contains_key(n));
    let flank = UPSTREAM_FLANK as usize;
    if pos < flank || (!deletion && pos == flank) {
        return listed(promoter_indel_name(reference, pos, deletion, bases));
    }
    let mut mutant = reference.to_vec();
    if deletion {
        mutant.drain(pos..(pos + bases.len()).min(reference.len()));
    } else {
        mutant.splice(pos..pos, bases.bytes());
    }
    if bases.len() % 3 != 0 {
        return listed(frameshift_name(reference, &mutant));
    }
    listed(in_frame_name(reference, &mutant)).or_else(|| {
        let whole = read_applied(reference, ga)?;
        // Only if the read as a whole keeps the frame.
        if whole.len().abs_diff(reference.len()) % 3 != 0 {
            return None;
        }
        listed(in_frame_name(reference, &whole))
    })
}

/// One call per run of inserted or deleted bases inside the alignment, matched against the
/// catalogue. Gaps at either end of the alignment are where the read starts or stops, not indels.
/// `reference` is the sequence `ga` was aligned to.
fn call_pnca_indels(reference: &[u8], ga: &GappedAlignment) -> Vec<PncaSnpCall> {
    let columns: Vec<(u8, u8)> = ga
        .gapped_query
        .iter()
        .copied()
        .zip(ga.gapped_ref.iter().copied())
        .collect();
    let mut calls = Vec::new();
    let mut ref_pos = ga.ref_start;
    let mut i = 0;
    while i < columns.len() {
        let (q, r) = columns[i];
        if q != b'-' && r != b'-' {
            ref_pos += 1;
            i += 1;
            continue;
        }
        let deletion = q == b'-';
        let start = i;
        let mut bases = String::new();
        while let Some(&(q, r)) = columns.get(i) {
            let in_run = if deletion { q == b'-' } else { r == b'-' };
            if !in_run {
                break;
            }
            bases.push((if deletion { r } else { q }).to_ascii_uppercase() as char);
            i += 1;
        }
        let call_pos = ref_pos;
        if deletion {
            ref_pos += bases.len();
        }
        if start > 0 && i < columns.len() {
            let catalogue = match_pnca_indel(reference, ga, call_pos, deletion, &bases);
            let kind = PncaCallKind::Indel {
                deletion,
                bases,
                catalogue,
            };
            calls.push(PncaSnpCall {
                ref_pos: call_pos,
                resistance_alts: catalogue_alts(call_pos, &kind),
                kind,
            });
        }
    }
    calls
}

/// Database is `REF_PNCA`: the pncA CDS plus a 50bp upstream promoter flank for each
/// *M. tuberculosis* complex member with a distinct sequence (H37Rv `Rv2043c`, bovis AF2122/97,
/// canettii — see `res/sequences/sequences.toml` for the rest, including the bovis BCG
/// Pasteur/africanum/mungi/orygis references that were tried and dropped as exact duplicates
/// of one of these three), fetched from NCBI at build time (via `fetch_sequences_from_toml()`
/// in build.rs).
///
/// Like [`super::rrl::identify_sequence_rrl_ntm`], this aligns the query against every reference
/// in the database (forward and reverse-complement) and returns one [`SeqIdHit`] per reference,
/// sorted by identity descending, so the caller can compare how well the read matches each
/// member of the complex rather than assuming it's H37Rv.
pub fn identify_sequence_pnca(query: &[u8]) -> Vec<SeqIdHit> {
    let query = super::trim_start_end(query, super::PNCA_FWD_START, super::PNCA_FWD_END);
    let rc = reverse_complement(query);
    let (nt_map, aa_map) = &*PNCA_RESISTANCE_SNPS;
    let references = parse_multi_fasta(REF_PNCA);
    // H37Rv, the first entry: the sequence the catalogue's wildtype refers to.
    let h37rv = references.first().map(|r| r.2.clone()).unwrap_or_default();

    let mut hits: Vec<SeqIdHit> = references
        .into_iter()
        .filter(|(_, _, refseq)| refseq.len() >= super::MIN_PNCA_REF_LEN)
        .map(|(accession, description, refseq)| {
            let fwd = align_to_ref(query, &refseq);
            let rev = align_to_ref(&rc, &refseq);
            let (ga, is_reverse) = if rev.identity > fwd.identity {
                (rev, true)
            } else {
                (fwd, false)
            };
            let ga = trim_alignment_ends(ga);

            let mut pnca_snp_calls = call_pnca_nt_snps(nt_map, &ga);
            pnca_snp_calls.extend(call_pnca_aa_snps(aa_map, &ga));
            pnca_snp_calls.extend(call_pnca_indels(&refseq, &ga));
            pnca_snp_calls.extend(call_pnca_unlisted(&h37rv, nt_map, aa_map, &ga));
            pnca_snp_calls.sort_by_key(|c| c.ref_pos);

            SeqIdHit {
                accession,
                description,
                source: super::RefSource::Ncbi,
                identity: ga.identity,
                is_reverse,
                rrl_snp_calls: vec![],
                rrs_snp_calls: vec![],
                rrs_snp_calls_3end: vec![],
                rrs_mtb_snp_calls: vec![],
                rrl_mtb_snp_calls: vec![],
                erm41_snp_calls: vec![],
                pnca_snp_calls,
                rpob_snp_calls: vec![],
                aligned_query: ga.gapped_query,
                aligned_ref: ga.gapped_ref,
                ref_start: ga.ref_start,
                erm41_position_28_opt: None,
                rrs3end_position_1248_opt: None,
                rrl_position_2058_2059_opt: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_codon() {
        assert_eq!(translate_codon(b"ATG"), Some("Met"));
        assert_eq!(translate_codon(b"atg"), Some("Met")); // case-insensitive
        assert_eq!(translate_codon(b"TGA"), Some("*"));
        assert_eq!(translate_codon(b"GCC"), Some("Ala"));
        assert_eq!(translate_codon(b"NNN"), None);
        assert_eq!(translate_codon(b"AT"), None); // incomplete
    }

    #[test]
    fn test_nt_pos_to_ref_idx_and_site_label_roundtrip() {
        // c.1 (the A of ATG) sits right after the upstream flank.
        assert_eq!(nt_pos_to_ref_idx(1), Some(UPSTREAM_FLANK as usize));
        // c.-1 sits immediately before it; there is no c.0.
        assert_eq!(nt_pos_to_ref_idx(-1), Some(UPSTREAM_FLANK as usize - 1));
        assert_eq!(nt_pos_to_ref_idx(103), Some(UPSTREAM_FLANK as usize + 102));

        let nt_call = PncaSnpCall {
            ref_pos: nt_pos_to_ref_idx(-11).unwrap(),
            kind: PncaCallKind::Nucleotide {
                wt_base: b'A',
                query_base: None,
            },
            resistance_alts: BTreeMap::new(),
        };
        assert_eq!(nt_call.site_label(), "c.-11A>?");

        let nt_call = PncaSnpCall {
            ref_pos: nt_pos_to_ref_idx(103).unwrap(),
            kind: PncaCallKind::Nucleotide {
                wt_base: b'C',
                query_base: None,
            },
            resistance_alts: BTreeMap::new(),
        };
        assert_eq!(nt_call.site_label(), "c.103C>?");

        // With a known alt base.
        let nt_call = PncaSnpCall {
            ref_pos: nt_pos_to_ref_idx(-11).unwrap(),
            kind: PncaCallKind::Nucleotide {
                wt_base: b'A',
                query_base: Some(b'C'),
            },
            resistance_alts: BTreeMap::new(),
        };
        assert_eq!(nt_call.site_label(), "c.-11A>C");

        // Codon label.
        let codon_call = PncaSnpCall {
            ref_pos: codon_to_ref_idx(102).unwrap(),
            kind: PncaCallKind::Codon {
                codon: 102,
                wt_aa: "Ala".to_string(),
                query_aa: Some("Pro".to_string()),
            },
            resistance_alts: BTreeMap::new(),
        };
        assert_eq!(codon_call.site_label(), "p.Ala102Pro");
    }

    #[test]
    fn test_codon_to_ref_idx() {
        // Codon 1 is the start codon, sitting right after the flank.
        assert_eq!(codon_to_ref_idx(1), Some(UPSTREAM_FLANK as usize));
        // Codon 2 starts 3 bases later.
        assert_eq!(codon_to_ref_idx(2), Some(UPSTREAM_FLANK as usize + 3));
    }

    #[test]
    fn test_parse_pnca_resistance_snps() {
        let csv = "Gene,Mutation,type,drug,original_mutation,confidence,source,comment\n\
                    pncA,c.-11A>C,drug_resistance,pyrazinamide,c.-11A>C,Assoc w R,WHO catalogue v2,\n\
                    pncA,p.Ala102Pro,drug_resistance,pyrazinamide,p.Ala102Pro,Assoc w R,WHO catalogue v2,\n\
                    pncA,p.Ala102fs,drug_resistance,pyrazinamide,p.Ala102fs,Assoc w R,WHO catalogue v2,\n\
                    pncA,c.-744_492del,drug_resistance,pyrazinamide,c.-744_492del,,tbdb,\n\
                    rrs,n.1473T>C,drug_resistance,amikacin,n.1473T>C,Assoc w R,WHO catalogue v2,\n";
        let (nt_map, aa_map) = parse_pnca_resistance_snps(csv);

        // c.-11A>C parsed as a nucleotide SNP.
        assert_eq!(nt_map.len(), 1);
        let (wt, alts) = &nt_map[&-11];
        assert_eq!(*wt, b'A');
        assert!(alts.contains_key(&b'C'));

        // p.Ala102Pro parsed as a codon call; the unpositioned frameshift and large deletion,
        // and the non-pncA row, are all skipped.
        assert_eq!(aa_map.len(), 1);
        let (wt_aa, alts) = &aa_map[&102];
        assert_eq!(wt_aa, "Ala");
        assert!(alts.contains_key("Pro"));
    }

    #[test]
    fn test_is_susceptible_pnca() {
        // No calls at all â†’ unknown (nothing was covered).
        assert_eq!(is_susceptible_pnca(&[]), None);

        let resistance_alts = || {
            BTreeMap::from([(
                "C".to_string(),
                (vec!["pyrazinamide".to_string()], "Assoc w R".to_string()),
            )])
        };

        // A site that the read simply didn't cover â†’ unknown, same as no calls at all.
        let uncovered_call = PncaSnpCall {
            ref_pos: 0,
            kind: PncaCallKind::Nucleotide {
                wt_base: b'A',
                query_base: None,
            },
            resistance_alts: resistance_alts(),
        };
        assert_eq!(is_susceptible_pnca(&[uncovered_call]), None);

        // Wildtype observed â†’ susceptible. A fully wildtype pncA read is real evidence of
        // susceptibility, not an absence of information.
        let wt_call = PncaSnpCall {
            ref_pos: 0,
            kind: PncaCallKind::Nucleotide {
                wt_base: b'A',
                query_base: Some(b'A'),
            },
            resistance_alts: resistance_alts(),
        };
        assert_eq!(
            is_susceptible_pnca(std::slice::from_ref(&wt_call)),
            Some(true)
        );

        // Strong resistance evidence observed â†’ resistant, even alongside wildtype calls
        // elsewhere (the strongest evidence wins).
        let resistant_call = PncaSnpCall {
            ref_pos: 0,
            kind: PncaCallKind::Nucleotide {
                wt_base: b'A',
                query_base: Some(b'C'),
            },
            resistance_alts: resistance_alts(),
        };
        assert_eq!(
            is_susceptible_pnca(&[wt_call.clone(), resistant_call]),
            Some(false)
        );

        // Weak/uncertain catalogue entry â†’ unknown (not enough to call susceptible or resistant).
        let uncertain_call = PncaSnpCall {
            ref_pos: 0,
            kind: PncaCallKind::Nucleotide {
                wt_base: b'A',
                query_base: Some(b'G'),
            },
            resistance_alts: BTreeMap::from([(
                "G".to_string(),
                (
                    vec!["pyrazinamide".to_string()],
                    "Uncertain significance".to_string(),
                ),
            )]),
        };
        assert_eq!(is_susceptible_pnca(&[uncertain_call]), None);

        // A non-wildtype allele with no catalogue entry at all â†’ uncatalogued, unknown.
        let uncatalogued_call = PncaSnpCall {
            ref_pos: 0,
            kind: PncaCallKind::Nucleotide {
                wt_base: b'A',
                query_base: Some(b'T'),
            },
            resistance_alts: resistance_alts(),
        };
        assert_eq!(is_susceptible_pnca(&[uncatalogued_call]), None);
    }

    #[test]
    fn test_identify_sequence_pnca_perfect_match() {
        // Aligning the H37Rv reference against the whole database should return one hit per
        // reference (H37Rv, bovis AF2122/97, canettii), with H37Rv itself sorted first at 100%
        // identity and the start/stop codons translated correctly.
        let (_, _, refseq) = parse_multi_fasta(REF_PNCA).into_iter().next().unwrap();
        let hits = identify_sequence_pnca(&refseq);
        assert_eq!(hits.len(), 3);
        let hit = &hits[0];
        assert!(hit.identity > 99.0);
        assert!(!hit.is_reverse);
    }

    /// H37Rv reference (50 bp promoter flank + CDS) and the verdict and non-empty calls of its
    /// best hit after `edit`.
    fn call_edited(edit: impl Fn(&mut Vec<u8>)) -> (Option<bool>, Vec<(String, String)>) {
        let (_, _, mut read) = parse_multi_fasta(REF_PNCA).into_iter().next().unwrap();
        edit(&mut read);
        let calls = identify_sequence_pnca(&read).swap_remove(0).pnca_snp_calls;
        let tagged = calls
            .iter()
            .filter(|c| !c.call_tag().is_empty())
            .map(|c| (c.site_label(), c.call_tag()))
            .collect();
        (is_susceptible_pnca(&calls), tagged)
    }

    /// 0-based reference index of `c.` position `c_pos`.
    fn at(c_pos: isize) -> usize {
        nt_pos_to_ref_idx(c_pos).unwrap()
    }

    #[test]
    fn wildtype_read_is_susceptible() {
        assert_eq!(call_edited(|_| {}), (Some(true), vec![]));
    }

    #[test]
    fn unlisted_indels_give_no_verdict() {
        type Edit = fn(&mut Vec<u8>);
        let cases: [(Edit, &str); 4] = [
            // No `p.Met1fs` row; the generic `frameshift_variant` row isn't applied.
            (
                |s| {
                    s.remove(at(2));
                },
                "frameshift (check read)",
            ),
            (|s| s.insert(at(4), b'G'), "frameshift (check read)"),
            (
                |s| {
                    s.drain(at(7)..at(10));
                },
                "in-frame indel (not assessed)",
            ),
            (
                |s| {
                    s.remove(at(-20));
                },
                "promoter indel (not assessed)",
            ),
        ];
        for (edit, tag) in cases {
            let (verdict, calls) = call_edited(edit);
            assert_eq!(verdict, None, "{tag}: {calls:?}");
            assert!(calls.iter().any(|(_, t)| t == tag), "{tag}: {calls:?}");
        }
    }

    /// Catalogue name and confidence of the matched indel, in the tag form.
    fn matched(drugs_confidence: &str, name: &str) -> String {
        format!("(pyrazinamide, {drugs_confidence}, catalogue {name})")
    }

    #[test]
    fn listed_indels_are_resistant() {
        type Edit = fn(&mut Vec<u8>);
        let cases: [(Edit, &str, &str); 4] = [
            (
                |s| {
                    s.remove(at(151));
                },
                "Assoc w R - Interim",
                "p.His51fs",
            ),
            // Codons 127–129.
            (
                |s| {
                    s.drain(at(379)..at(388));
                },
                "Assoc w R",
                "p.Glu127_Asp129del",
            ),
            // Codons 63–67 replaced by one Glu.
            (
                |s| {
                    s.splice(at(187)..at(202), *b"GAG");
                },
                "Assoc w R - Interim",
                "p.Asp63_Ser67delinsGlu",
            ),
            (
                |s| {
                    s.remove(at(-5));
                },
                "Assoc w R",
                "c.-5delG",
            ),
        ];
        for (edit, confidence, name) in cases {
            let (verdict, calls) = call_edited(edit);
            let tag = matched(confidence, name);
            assert!(calls.iter().any(|(_, t)| *t == tag), "{name}: {calls:?}");
            assert_eq!(verdict, Some(false), "{name}: {calls:?}");
        }
    }

    #[test]
    fn matched_indel_survives_serde() {
        let (_, _, mut read) = parse_multi_fasta(REF_PNCA).into_iter().next().unwrap();
        read.remove(at(151));
        let calls = identify_sequence_pnca(&read).swap_remove(0).pnca_snp_calls;
        let json = serde_json::to_string(&calls).unwrap();
        let back: Vec<PncaSnpCall> = serde_json::from_str(&json).unwrap();
        assert_eq!(is_susceptible_pnca(&back), Some(false));
        for (a, b) in calls.iter().zip(&back) {
            assert_eq!(a.call_tag(), b.call_tag());
        }
    }

    /// Every resistance-graded frameshift and in-frame deletion row can be produced by the
    /// naming functions from a change to H37Rv, so its residues agree with the reference.
    #[test]
    fn graded_catalogue_indels_are_nameable() {
        static DEL_RE: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^p\.[A-Za-z]{3}(\d+)(?:_[A-Za-z]{3}(\d+))?del$").unwrap()
        });
        static FS_RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^p\.[A-Za-z]{3}(\d+)fs$").unwrap());
        let (_, _, reference) = parse_multi_fasta(REF_PNCA).into_iter().next().unwrap();
        let mut checked = 0;
        for (name, (_, confidence)) in PNCA_RESISTANCE_INDELS.iter() {
            if confidence_rank(confidence) >= 2 {
                continue;
            }
            if let Some(caps) = FS_RE.captures(name) {
                let codon: usize = caps[1].parse().unwrap();
                // A deletion of one or two bases, or an inserted base, in or just before this
                // codon. In a run like codon 83 (CCC) a single deletion keeps the residue.
                let first = codon_to_ref_idx(codon).unwrap() - 3;
                let found = (first..first + 6).any(|pos| {
                    let edits = [(1, None), (2, None)]
                        .into_iter()
                        .chain(b"ACGT".iter().map(|&base| (0, Some(base))));
                    edits.into_iter().any(|(deleted, inserted)| {
                        let mut mutant = reference.clone();
                        mutant.splice(pos..pos + deleted, inserted);
                        frameshift_name(&reference, &mutant).as_ref() == Some(name)
                    })
                });
                assert!(found, "{name}");
                checked += 1;
            } else if let Some(caps) = DEL_RE.captures(name) {
                let from: usize = caps[1].parse().unwrap();
                let to: usize = caps.get(2).map_or(from, |m| m.as_str().parse().unwrap());
                let mut mutant = reference.clone();
                mutant.drain(codon_to_ref_idx(from).unwrap()..codon_to_ref_idx(to + 1).unwrap());
                assert_eq!(in_frame_name(&reference, &mutant).as_ref(), Some(name));
                checked += 1;
            }
        }
        assert!(checked >= 100, "only {checked} rows checked");
    }

    #[test]
    fn unlisted_changes_give_no_verdict() {
        let (nt_map, aa_map) = &*PNCA_RESISTANCE_SNPS;
        let (_, _, h37rv) = parse_multi_fasta(REF_PNCA).into_iter().next().unwrap();
        // The first codon, after the start codon, that the catalogue doesn't list and that one
        // base change turns into another amino acid.
        let change = |want_stop: bool| {
            (2..=186)
                .filter(|codon| !aa_map.contains_key(codon))
                .find_map(|codon| {
                    let start = codon_to_ref_idx(codon)?;
                    let wt = translate_codon(&h37rv[start..start + 3])?;
                    (start..start + 3).find_map(|pos| {
                        b"ACGT".iter().find_map(|&base| {
                            let mut codon_bases = h37rv[start..start + 3].to_vec();
                            codon_bases[pos - start] = base;
                            let aa = translate_codon(&codon_bases)?;
                            let c_pos = ref_idx_to_nt_pos(pos)?;
                            (aa != wt && (aa == "*") == want_stop && !nt_map.contains_key(&c_pos))
                                .then_some((pos, base))
                        })
                    })
                })
                .expect("an unlisted codon")
        };
        let promoter = (0..UPSTREAM_FLANK as usize)
            .find(|&i| !nt_map.contains_key(&ref_idx_to_nt_pos(i).unwrap()))
            .map(|i| (i, if h37rv[i] == b'A' { b'C' } else { b'A' }))
            .expect("an unlisted promoter position");
        for ((pos, base), tag) in [
            (change(false), "(mutation, untested)"),
            (change(true), "premature stop (check read)"),
            ((change(false).0, b'N'), "unresolved codon (check read)"),
            (promoter, "(mutation, untested)"),
        ] {
            let (verdict, calls) = call_edited(|s| s[pos] = base);
            assert_eq!(verdict, None, "{tag}: {calls:?}");
            assert!(
                calls.iter().any(|(_, t)| t.ends_with(tag)),
                "{tag}: {calls:?}"
            );
        }
    }

    #[test]
    fn synonymous_change_stays_susceptible() {
        let (nt_map, aa_map) = &*PNCA_RESISTANCE_SNPS;
        let (_, _, h37rv) = parse_multi_fasta(REF_PNCA).into_iter().next().unwrap();
        // Third codon position of an unlisted codon, changed without changing the amino acid.
        let (pos, base) = (2..=186)
            .filter(|codon| !aa_map.contains_key(codon))
            .find_map(|codon| {
                let start = codon_to_ref_idx(codon)?;
                let pos = start + 2;
                let c_pos = ref_idx_to_nt_pos(pos)?;
                b"ACGT".iter().find_map(|&base| {
                    let mut bases = h37rv[start..start + 3].to_vec();
                    bases[2] = base;
                    (!nt_map.contains_key(&c_pos)
                        && base != h37rv[pos].to_ascii_uppercase()
                        && translate_codon(&bases) == translate_codon(&h37rv[start..start + 3]))
                    .then_some((pos, base))
                })
            })
            .expect("a synonymous change");
        assert_eq!(call_edited(|s| s[pos] = base), (Some(true), vec![]));
    }

    #[test]
    fn indel_labels() {
        let call = |c_pos, deletion, bases: &str| PncaSnpCall {
            ref_pos: at(c_pos),
            kind: PncaCallKind::Indel {
                deletion,
                bases: bases.to_string(),
                catalogue: None,
            },
            resistance_alts: BTreeMap::new(),
        };
        assert_eq!(call(151, true, "A").site_label(), "c.151del");
        assert_eq!(call(151, true, "ACG").site_label(), "c.151_153del");
        assert_eq!(call(151, false, "TT").site_label(), "c.150_151insTT");
        assert_eq!(call(-20, true, "A").site_label(), "c.-20del");
    }

    #[test]
    fn resistance_substitution_wins_over_frameshift() {
        let (verdict, calls) = call_edited(|s| {
            // c.-11A>G ("Assoc w R") plus a frameshift further downstream.
            s[at(-11)] = b'G';
            s.remove(at(151));
        });
        assert_eq!(verdict, Some(false), "{calls:?}");
    }

    #[test]
    fn other_complex_references_have_no_indels() {
        for (_, name, read) in parse_multi_fasta(REF_PNCA) {
            let calls = identify_sequence_pnca(&read).swap_remove(0).pnca_snp_calls;
            assert!(
                !calls
                    .iter()
                    .any(|c| matches!(c.kind, PncaCallKind::Indel { .. })),
                "{name}"
            );
        }
    }

    #[test]
    fn ref_idx_to_nt_pos_inverts_nt_pos_to_ref_idx() {
        for c_pos in [-50, -11, -1, 1, 2, 300, 561] {
            let idx = nt_pos_to_ref_idx(c_pos).unwrap();
            assert_eq!(ref_idx_to_nt_pos(idx), Some(c_pos), "c.{c_pos}");
        }
    }

    #[test]
    fn serde_round_trip_restores_catalogue_alts() {
        let (_, _, refseq) = parse_multi_fasta(REF_PNCA).into_iter().next().unwrap();
        let calls = identify_sequence_pnca(&refseq)
            .swap_remove(0)
            .pnca_snp_calls;
        assert!(calls.iter().any(|c| !c.resistance_alts.is_empty()));

        let json = serde_json::to_string(&calls).unwrap();
        assert!(
            !json.contains("resistance_alts"),
            "catalogue copy not stored"
        );
        let back: Vec<PncaSnpCall> = serde_json::from_str(&json).unwrap();

        assert_eq!(back.len(), calls.len());
        for (a, b) in calls.iter().zip(&back) {
            assert_eq!(a.ref_pos, b.ref_pos);
            assert_eq!(
                a.resistance_alts,
                b.resistance_alts,
                "site {}",
                a.site_label()
            );
            assert_eq!(a.call_tag(), b.call_tag());
        }
        assert_eq!(is_susceptible_pnca(&calls), is_susceptible_pnca(&back));
    }

    #[test]
    fn deserializes_records_that_still_carry_resistance_alts() {
        let old = r#"{"ref_pos":11,"kind":{"Nucleotide":{"wt_base":67,"query_base":67}},
                      "resistance_alts":{"T":[["pyrazinamide"],"Uncertain significance"]}}"#;
        let call: PncaSnpCall = serde_json::from_str(old).unwrap();
        assert_eq!(call.ref_pos, 11);
        assert_eq!(
            call.resistance_alts,
            catalogue_alts(11, &call.kind),
            "taken from the catalogue, not the stored copy"
        );
    }
}
