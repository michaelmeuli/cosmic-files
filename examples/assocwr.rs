use serde::{Deserialize, Serialize};
use std::error::Error;

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

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = "tbprofiler/mutations.csv";
    let output_path = "tbprofiler/filtered_mutations.csv";

    let mut reader = csv::Reader::from_path(input_path)?;
    let mut writer = csv::Writer::from_path(output_path)?;

    for result in reader.deserialize() {
        let record: Record = result?;

        if record.confidence == "Assoc w R" {
            writer.serialize(record)?;
        }
    }

    writer.flush()?;
    println!("Filtering complete.");

    Ok(())
}
