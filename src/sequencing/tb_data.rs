//! Deserialization of TBProfiler's `*.results.json` output, and the TB→*E. coli* mutation
//! coordinate lookup used to display resistance mutations in the nomenclature most literature
//! references (see [`TB_ECOLI_MAPPING`]).

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Ranks a WHO-catalogue confidence label from strongest resistance evidence (0) to weakest /
/// unknown (5). Shared across modules so every gene's susceptibility call uses the same scale.
pub(crate) fn confidence_rank(conf: &str) -> u8 {
    match conf {
        "Assoc w R" => 0,
        "Assoc w R - Interim" => 1,
        "Uncertain significance" => 2,
        "Not assoc w R - Interim" => 3,
        "Not assoc w R" => 4,
        _ => 5, // unknown / fallback
    }
}
/// Top-level shape of a TBProfiler `*.results.json` report.
#[derive(Debug, Deserialize, Clone)]
pub struct TbProfilerJson {
    pub pipeline: Pipeline,
    /// Drug-resistance variants called by TBProfiler; absent/empty when none were found.
    #[serde(default)]
    pub dr_variants: Vec<DrVariant>,
}

impl std::fmt::Display for TbProfilerJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TbProfilerJson")
            .field("pipeline", &self.pipeline)
            .field("dr_variants", &self.dr_variants)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Pipeline {
    pub db_version: DbVersion,
}

/// Identifies which resistance database (and its schema/tool version) produced the report,
/// shown in the UI so results can be traced back to a specific TBProfiler DB build.
#[derive(Debug, Deserialize, Clone)]
pub struct DbVersion {
    pub name: String,
    pub commit: String,
    #[serde(rename = "db-schema-version", default)]
    pub db_schema_version: Option<String>,
    #[serde(rename = "tb-profiler-version")]
    pub tb_profiler_version: String,
}

/// A single drug-resistance variant called by TBProfiler for one gene.
#[derive(Debug, Deserialize, Clone)]
pub struct DrVariant {
    pub gene_id: String,
    pub gene_name: String,
    /// HGVS-style mutation description (e.g. `p.Ser450Leu`).
    pub change: String,
    /// Per-drug confidence entries; empty if TBProfiler didn't associate this variant with a
    /// drug.
    #[serde(default)]
    pub drugs: Vec<Drugs>,
}

impl DrVariant {
    /// Strongest (lowest-numbered) [`confidence_rank`] among this variant's drugs, or `5`
    /// (unknown) if it has none.
    pub fn highest_confidence_rank(&self) -> u8 {
        self.drugs
            .iter()
            .map(|d| confidence_rank(d.confidence.as_str()))
            .min() // strongest (lowest number)
            .unwrap_or(5)
    }
    /// Whether the strongest evidence among this variant's drugs falls at or below "Uncertain
    /// significance" — i.e. the variant isn't confidently resistance-conferring. A variant with
    /// no drugs listed is treated as susceptible.
    pub fn is_susceptible(&self) -> bool {
        self.drugs
            .iter()
            .map(|d| confidence_rank(d.confidence.as_str()))
            .min() // strongest (lowest rank)
            .map(|rank| rank >= 2)
            .unwrap_or(true) // if no drugs listed, treat as susceptible
    }
}

/// One drug association for a [`DrVariant`], with its WHO-catalogue confidence label (see
/// [`confidence_rank`]).
#[derive(Debug, Deserialize, Clone)]
pub struct Drugs {
    pub drug: String,
    pub confidence: String,
}

/// One row of `res/tb_ecoli_mapping.csv`.
#[derive(Debug, Deserialize, Clone)]
struct TBMappingRow {
    ecoli: String,

    #[serde(rename = "Mutation")]
    mutation: String,
    #[serde(rename = "Gene")]
    gene: String,
}

/// Maps `(gene, TB mutation)` to the equivalent mutation in *E. coli* numbering, parsed once
/// from `res/tb_ecoli_mapping.csv`. Many resistance references (e.g. WHO catalogue, rrs/rrl
/// literature) number positions against the *E. coli* reference rather than the TB genome, so
/// this lets the UI show both.
pub static TB_ECOLI_MAPPING: LazyLock<HashMap<(String, String), String>> = LazyLock::new(|| {
    let mut rdr =
        csv::Reader::from_reader(include_str!("../../res/tb_ecoli_mapping.csv").as_bytes());
    let mut map = HashMap::new();
    for row in rdr.deserialize::<TBMappingRow>() {
        let row = row.unwrap();
        map.insert(
            (row.gene.trim().to_string(), row.mutation.trim().to_string()),
            row.ecoli.trim().to_string(),
        );
    }
    map
});
