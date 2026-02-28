use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

const TB_ECOLI_MAPPING_CSV: &str = include_str!("../../res/tb_ecoli_mapping.csv");

#[derive(Debug, Deserialize, Clone)]
pub struct TbProfilerJson {
    pub pipeline: Pipeline,
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

#[derive(Debug, Deserialize, Clone)]
pub struct DbVersion {
    pub name: String,
    pub commit: String,
    #[serde(rename = "db-schema-version", default)]
    pub db_schema_version: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DrVariant {
    pub gene_id: String,
    pub gene_name: String,
    pub change: String,
    #[serde(default)]
    pub drugs: Vec<Drugs>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Drugs {
    pub drug: String,
    pub confidence: String,
}

#[derive(Debug, Deserialize, Clone)]
struct TBMappingRow {
    ecoli: String,

    #[serde(rename = "Mutation")]
    mutation: String,
    #[serde(rename = "Gene")]
    gene: String,
}

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
