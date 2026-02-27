use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const TBDB_COMMIT: &str = "72ef6fa";

#[derive(Debug, Deserialize, Serialize)]
struct Record {
    #[serde(rename = "Gene")]
    gene: String,

    #[serde(rename = "Mutation")]
    mutation: String,

    #[serde(rename = "type")]
    mutation_type: String,

    #[serde(rename = "drug")]
    drug: String,

    #[serde(rename = "original_mutation")]
    original_mutation: String,

    #[serde(rename = "confidence")]
    confidence: String,

    #[serde(rename = "source")]
    source: String,

    #[serde(rename = "comment")]
    comment: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = format!(
        "https://raw.githubusercontent.com/jodyphelan/tbdb/{}/mutations.csv",
        TBDB_COMMIT
    );
    let resp = reqwest::get(&url).await?.error_for_status()?;
    let bytes = resp.bytes().await?;

    let mut rdr = csv::ReaderBuilder::new().from_reader(bytes.as_ref());

    let mut confidence_values = HashSet::new();
    let mut n = 0usize;

    for result in rdr.deserialize::<Record>() {
        let row = result?;
        confidence_values.insert(row.confidence);
        n += 1;
    }

    println!("Parsed {n} rows\n");

    println!("Unique confidence values:");
    let mut values: Vec<_> = confidence_values.into_iter().collect();
    values.sort();
    for value in values {
        println!("  - {}", value);
    }

    Ok(())
}