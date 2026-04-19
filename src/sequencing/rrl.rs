
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// A single macrolide-resistance SNP position in the M. abscessus 23S rRNA (rrl).
/// `query_base` is `None` when the position is not covered by the read.
#[derive(Clone, Debug)]
pub struct RrlSnpCall {
    /// 0-based position in the rrl reference sequence (MAB_r5052).
    pub ref_pos: usize,
    /// Base observed in the query at this position, or `None` if not covered.
    pub query_base: Option<u8>,
    /// Wild-type base at this position.
    pub wt_base: u8,
    /// All resistance-conferring bases at this position (sorted).
    pub resistance_bases: Vec<u8>,
}

impl RrlSnpCall {
    /// "NA", "<base> (wt)", "<base> (resistance)", or "<base> (mutation)".
    pub fn call_tag(&self) -> String {
        match self.query_base {
            None => "NA".to_string(),
            Some(b) if b == self.wt_base => format!("{} (wt)", self.wt_base as char),
            Some(b) if self.resistance_bases.contains(&b) => format!("{} (resistance)", b as char),
            Some(b) => format!("{} (mutation)", b as char),
        }
    }
}

/// Compute a call for every rrl resistance SNP position.
/// Returns one entry per unique position; `query_base` is `None` when not covered.
pub fn call_rrl_snps(query: &[u8], alignment_offset: isize) -> Vec<RrlSnpCall> {
    RRL_RESISTANCE_SNPS
        .iter()
        .map(|(&ref_pos, (wt_base, resistance_bases))| {
            let query_pos = ref_pos as isize - alignment_offset;
            let query_base = if query_pos >= 0 && (query_pos as usize) < query.len() {
                Some(query[query_pos as usize].to_ascii_uppercase())
            } else {
                None
            };
            RrlSnpCall { ref_pos, query_base, wt_base: *wt_base, resistance_bases: resistance_bases.clone() }
        })
        .collect()
}

#[derive(Debug, Deserialize, Clone)]
struct AbscessusResistanceVariants {
    #[serde(rename = "Gene")]
    gene: String,
    #[serde(rename = "Mutation")]
    mutation: String,
    #[serde(rename = "Drug")]
    drug: String,
    #[serde(rename = "Confers")]
    confers: String,
    #[serde(rename = "Interaction")]
    interaction: String,
    #[serde(rename = "Literature")]
    literature: String,
}

/// Maps each 0-based ref_pos to `(wt_base, sorted_resistance_bases)` for rrl entries in
/// abscessus_resistance_variants.csv. Parsed from HGVS strings like "n.2270A>C".
/// Multiple alts at the same position (e.g. A>C, A>G, A>T) are grouped under one key.
pub static RRL_RESISTANCE_SNPS: LazyLock<BTreeMap<usize, (u8, Vec<u8>)>> =
    LazyLock::new(|| {
        let mut rdr = csv::Reader::from_reader(
            include_str!("../../res/abscessus_resistance_variants.csv").as_bytes(),
        );
        let mut map: BTreeMap<usize, (u8, Vec<u8>)> = BTreeMap::new();
        for row in rdr.deserialize::<AbscessusResistanceVariants>() {
            let row = row.unwrap();
            if row.gene.trim() != "rrl" {
                continue;
            }
            if row.confers.trim() != "resistance" {
                continue;
            }
            let m = row.mutation.trim();
            if let Some(rest) = m.strip_prefix("n.") {
                let digits_end =
                    rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                if let Ok(pos1) = rest[..digits_end].parse::<usize>() {
                    let after_pos = &rest[digits_end..];
                    if let (Some(wt), Some(alt)) = (
                        after_pos.bytes().next(),
                        after_pos
                            .strip_prefix(|_: char| true)
                            .and_then(|s| s.strip_prefix('>'))
                            .and_then(|s| s.bytes().next()),
                    ) {
                        let entry = map.entry(pos1 - 1).or_insert_with(|| (wt, Vec::new()));
                        if !entry.1.contains(&alt) {
                            entry.1.push(alt);
                        }
                    }
                }
            }
        }
        for (_, (_, alts)) in map.iter_mut() {
            alts.sort_unstable();
        }
        map
    });
