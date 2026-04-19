
use serde::Deserialize;
use std::collections::BTreeMap;
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
