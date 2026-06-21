use super::tb_data::confidence_rank;
use super::{
    GappedAlignment, REF_PNCA, SeqIdHit, align_to_ref, base_at_ref_pos, parse_multi_fasta,
    reverse_complement,
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
const AA3: [&str; 20] = [
    "Ala", "Arg", "Asn", "Asp", "Cys", "Gln", "Glu", "Gly", "His", "Ile", "Leu", "Lys", "Met",
    "Phe", "Pro", "Ser", "Thr", "Trp", "Tyr", "Val",
];

#[derive(Debug, Deserialize, Clone)]
struct MutationRow {
    #[serde(rename = "Gene")]
    gene: String,
    #[serde(rename = "Mutation")]
    mutation: String,
    #[serde(rename = "drug")]
    drug: String,
    #[serde(rename = "confidence")]
    confidence: String,
}

/// Translate a single codon to its 3-letter amino acid code (`"*"` for a stop codon).
/// Returns `None` for incomplete codons or non-ACGT bytes.
fn translate_codon(codon: &[u8]) -> Option<&'static str> {
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

/// 0-based index into `REF_PNCA` of the first base of a 1-based codon number.
fn codon_to_ref_idx(codon: usize) -> Option<usize> {
    nt_pos_to_ref_idx(((codon - 1) * 3 + 1) as isize)
}

/// Parses `tbprofiler/mutations.csv`, keeping only `pncA` rows whose mutation is a simple
/// nucleotide substitution (`c.POS[wt]>[alt]`, promoter or coding) or a single-codon amino
/// acid substitution / nonsense call (`p.WtNNNAlt` / `p.WtNNN*`).
///
/// Frameshifts, in-frame indels, delins, and stop-codon extensions (`fs`, `del`, `dup`,
/// `delins`, `ext`) are not positioned by this simple gapless-alignment model and are skipped —
/// same limitation as the rest of this codebase, which only calls substitutions, not indels.
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
            let Ok(c_pos) = caps[1].parse::<isize>() else { continue };
            let wt = caps[2].as_bytes()[0];
            let alt = caps[3].as_bytes()[0];
            let entry = nt_map.entry(c_pos).or_insert_with(|| (wt, BTreeMap::new()));
            let variant = entry.1.entry(alt).or_insert_with(|| (Vec::new(), confidence.clone()));
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
            let Ok(codon) = caps[2].parse::<usize>() else { continue };
            let entry = aa_map.entry(codon).or_insert_with(|| (wt_aa.clone(), BTreeMap::new()));
            let variant = entry.1.entry(alt_aa).or_insert_with(|| (Vec::new(), confidence.clone()));
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

/// One diagnostic pncA site: either a single nucleotide (promoter or coding) or a single codon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PncaCallKind {
    Nucleotide {
        wt_base: u8,
        query_base: Option<u8>,
    },
    Codon {
        codon: usize,
        wt_aa: String,
        query_aa: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PncaSnpCall {
    /// 0-based position in the pncA reference sequence: the substituted base for nucleotide
    /// calls, or the first base of the codon for codon calls.
    pub ref_pos: usize,
    pub kind: PncaCallKind,
    /// Maps each resistance-conferring alt (a 1-character base string, or an amino acid
    /// 3-letter code / `"*"`) to `(drugs, WHO confidence label)`.
    pub resistance_alts: BTreeMap<String, (Vec<String>, String)>,
}

impl PncaSnpCall {
    /// HGVS-style label for this site, e.g. `"c.-11A>C"` or `"p.Ala102Pro"`.
    /// When the query didn't cover the site (`query_base`/`query_aa` is `None`), the alt is `"?"`.
    pub fn site_label(&self) -> String {
        match &self.kind {
            PncaCallKind::Nucleotide { wt_base, query_base } => {
                // Recover the signed c. position from ref_pos for display.
                let offset = self.ref_pos as isize - UPSTREAM_FLANK;
                if offset >= 0 {
                    format!("c.{}{}>{}", offset + 1, *wt_base as char, query_base.map(|b| b as char).unwrap_or('?'))
                } else {
                    format!("c.{}{}>{}", offset, *wt_base as char, query_base.map(|b| b as char).unwrap_or('?'))
                }
            }
            PncaCallKind::Codon { codon, wt_aa, query_aa } => format!("p.{}{}{}", wt_aa, codon, query_aa.as_deref().unwrap_or("?")),
        }
    }

    pub fn call_tag(&self) -> String {
        match &self.kind {
            PncaCallKind::Nucleotide { wt_base, query_base } => match query_base {
                None => String::new(),
                Some(b) if b == wt_base => format!(""),
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
            PncaCallKind::Codon { wt_aa, query_aa, .. } => match query_aa {
                None => String::new(),
                Some(aa) if aa == wt_aa => format!(""),
                Some(aa) => match self.resistance_alts.get(aa) {
                    Some((drugs, confidence)) => {
                        format!("({}, {})", drugs.join(", "), confidence)
                    }
                    None => format!("{aa} (mutation, untested)"),
                },
            },
        }
    }

    /// Classifies the allele observed at this site, or `None` when the read doesn't cover it
    /// at all (as opposed to covering it and finding wildtype — those are not the same thing).
    fn evidence(&self) -> Option<PncaEvidence> {
        let (observed, wt) = match &self.kind {
            PncaCallKind::Nucleotide { wt_base, query_base: Some(b) } => {
                ((*b as char).to_string(), *b == *wt_base)
            }
            PncaCallKind::Codon { wt_aa, query_aa: Some(aa), .. } => (aa.clone(), aa == wt_aa),
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
    pub snp_calls: Vec<PncaSnpCall>,
    pub is_susceptible: Option<bool>,
}

/// Returns `Some(false)` when any covered site's allele matches a catalogued resistance-
/// conferring alt at confidence rank `< 2` (e.g. "Assoc w R"). Returns `Some(true)` only when
/// every diagnostic site is covered *and* every observed allele is wildtype. Returns `None`
/// whenever any site went uncovered, an uncatalogued variant was found, weak/uncertain
/// resistance evidence was seen, or no diagnostic site was reached at all.
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
/// has a deletion in the query (consistent with the existing policy of skipping frameshifts).
fn codon_at_ref_pos(
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

fn call_pnca_nt_snps(map: &PncaNtSnpMap, ga: &GappedAlignment) -> Vec<PncaSnpCall> {
    map.iter()
        .filter_map(|(&c_pos, (wt_base, alts))| {
            let ref_pos = nt_pos_to_ref_idx(c_pos)?;
            let query_base =
                base_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos);
            let resistance_alts = alts
                .iter()
                .map(|(&b, v)| ((b as char).to_string(), v.clone()))
                .collect();
            Some(PncaSnpCall {
                ref_pos,
                kind: PncaCallKind::Nucleotide { wt_base: *wt_base, query_base },
                resistance_alts,
            })
        })
        .collect()
}

fn call_pnca_aa_snps(map: &PncaAaSnpMap, ga: &GappedAlignment) -> Vec<PncaSnpCall> {
    map.iter()
        .filter_map(|(&codon, (wt_aa, alts))| {
            let ref_pos = codon_to_ref_idx(codon)?;
            let query_aa =
                codon_at_ref_pos(&ga.gapped_query, &ga.gapped_ref, ga.ref_start, ref_pos)
                    .and_then(|bases| translate_codon(&bases).map(str::to_string));
            Some(PncaSnpCall {
                ref_pos,
                kind: PncaCallKind::Codon { codon, wt_aa: wt_aa.clone(), query_aa },
                resistance_alts: alts.clone(),
            })
        })
        .collect()
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

    let mut hits: Vec<SeqIdHit> = parse_multi_fasta(REF_PNCA)
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

            let mut pnca_snp_calls = call_pnca_nt_snps(nt_map, &ga);
            pnca_snp_calls.extend(call_pnca_aa_snps(aa_map, &ga));
            pnca_snp_calls.sort_by_key(|c| c.ref_pos);

            SeqIdHit {
                accession,
                description,
                identity: ga.identity,
                is_reverse,
                kansasii_gastri_snp_calls: vec![],
                marinum_ulcerans_snp_calls: vec![],
                rrl_snp_calls: vec![],
                rrs_snp_calls: vec![],
                erm41_snp_calls: vec![],
                pnca_snp_calls,
                aligned_query: ga.gapped_query,
                aligned_ref: ga.gapped_ref,
                ref_start: ga.ref_start,
                erm41_position_28_opt: None,
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
            kind: PncaCallKind::Nucleotide { wt_base: b'A', query_base: None },
            resistance_alts: BTreeMap::new(),
        };
        assert_eq!(nt_call.site_label(), "c.-11A>?");

        let nt_call = PncaSnpCall {
            ref_pos: nt_pos_to_ref_idx(103).unwrap(),
            kind: PncaCallKind::Nucleotide { wt_base: b'C', query_base: None },
            resistance_alts: BTreeMap::new(),
        };
        assert_eq!(nt_call.site_label(), "c.103C>?");

        // With a known alt base.
        let nt_call = PncaSnpCall {
            ref_pos: nt_pos_to_ref_idx(-11).unwrap(),
            kind: PncaCallKind::Nucleotide { wt_base: b'A', query_base: Some(b'C') },
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
        // No calls at all → unknown (nothing was covered).
        assert_eq!(is_susceptible_pnca(&[]), None);

        let resistance_alts = || {
            BTreeMap::from([(
                "C".to_string(),
                (vec!["pyrazinamide".to_string()], "Assoc w R".to_string()),
            )])
        };

        // A site that the read simply didn't cover → unknown, same as no calls at all.
        let uncovered_call = PncaSnpCall {
            ref_pos: 0,
            kind: PncaCallKind::Nucleotide { wt_base: b'A', query_base: None },
            resistance_alts: resistance_alts(),
        };
        assert_eq!(is_susceptible_pnca(&[uncovered_call]), None);

        // Wildtype observed → susceptible. A fully wildtype pncA read is real evidence of
        // susceptibility, not an absence of information.
        let wt_call = PncaSnpCall {
            ref_pos: 0,
            kind: PncaCallKind::Nucleotide { wt_base: b'A', query_base: Some(b'A') },
            resistance_alts: resistance_alts(),
        };
        assert_eq!(is_susceptible_pnca(&[wt_call.clone()]), Some(true));

        // Strong resistance evidence observed → resistant, even alongside wildtype calls
        // elsewhere (the strongest evidence wins).
        let resistant_call = PncaSnpCall {
            ref_pos: 0,
            kind: PncaCallKind::Nucleotide { wt_base: b'A', query_base: Some(b'C') },
            resistance_alts: resistance_alts(),
        };
        assert_eq!(
            is_susceptible_pnca(&[wt_call.clone(), resistant_call]),
            Some(false)
        );

        // Weak/uncertain catalogue entry → unknown (not enough to call susceptible or resistant).
        let uncertain_call = PncaSnpCall {
            ref_pos: 0,
            kind: PncaCallKind::Nucleotide { wt_base: b'A', query_base: Some(b'G') },
            resistance_alts: BTreeMap::from([(
                "G".to_string(),
                (vec!["pyrazinamide".to_string()], "Uncertain significance".to_string()),
            )]),
        };
        assert_eq!(is_susceptible_pnca(&[uncertain_call]), None);

        // A non-wildtype allele with no catalogue entry at all → uncatalogued, unknown.
        let uncatalogued_call = PncaSnpCall {
            ref_pos: 0,
            kind: PncaCallKind::Nucleotide { wt_base: b'A', query_base: Some(b'T') },
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
}
