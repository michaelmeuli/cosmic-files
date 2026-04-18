
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

/// (0-based ref pos, wt_base, resistance_base) triples derived from rrl entries in
/// abscessus_resistance_variants.csv. Parsed from HGVS strings like "n.2270A>C" → (2269, b'A', b'C').
pub static RRL_RESISTANCE_SNPS: LazyLock<Vec<(usize, u8, u8)>> = LazyLock::new(|| {
    let mut rdr =
        csv::Reader::from_reader(include_str!("../../res/abscessus_resistance_variants.csv").as_bytes());
    let mut seen = std::collections::BTreeSet::new();
    for row in rdr.deserialize::<AbscessusResistanceVariants>() {
        let row = row.unwrap();
        if row.gene.trim() != "rrl" {
            continue;
        }
        // Parse "n.2270A>C" → pos1=2270, wt=b'A', alt=b'C'
        let m = row.mutation.trim();
        if let Some(rest) = m.strip_prefix("n.") {
            let digits_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            if let Ok(pos1) = rest[..digits_end].parse::<usize>() {
                let after_pos = &rest[digits_end..];
                if let (Some(wt), Some(alt)) = (
                    after_pos.bytes().next(),
                    after_pos.strip_prefix(|_: char| true).and_then(|s| s.strip_prefix('>')).and_then(|s| s.bytes().next()),
                ) {
                    seen.insert((pos1 - 1, wt, alt));
                }
            }
        }
    }
    seen.into_iter().collect()
});