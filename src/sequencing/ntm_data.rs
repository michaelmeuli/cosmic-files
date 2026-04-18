
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

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

/// (0-based ref pos, wt_base) pairs derived from rrl entries in abscessus_resistance_variants.csv.
/// Parsed from HGVS mutation strings like "n.2270A>C" → (2269, b'A').
pub static RRL_RESISTANCE_SNPS: LazyLock<Vec<(usize, u8)>> = LazyLock::new(|| {
    let mut rdr =
        csv::Reader::from_reader(include_str!("../../res/abscessus_resistance_variants.csv").as_bytes());
    let mut seen = std::collections::BTreeSet::new();
    for row in rdr.deserialize::<AbscessusResistanceVariants>() {
        let row = row.unwrap();
        if row.gene.trim() != "rrl" {
            continue;
        }
        // Parse "n.2270A>C" → pos=2270 (1-based), wt=b'A'
        let m = row.mutation.trim();
        if let Some(rest) = m.strip_prefix("n.") {
            let digits_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            if let Ok(pos1) = rest[..digits_end].parse::<usize>() {
                if let Some(wt) = rest[digits_end..].bytes().next() {
                    seen.insert((pos1 - 1, wt));
                }
            }
        }
    }
    seen.into_iter().collect()
});