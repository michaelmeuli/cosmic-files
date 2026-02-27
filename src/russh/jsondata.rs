use serde::Deserialize;

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