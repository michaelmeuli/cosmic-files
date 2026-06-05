use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Clone)]
pub struct BarcodeRecord {
    pub chrom: String,
    pub start: u64,   // 0-based, BED convention
    pub end: u64,
    pub subspecies: String,
    pub allele: char,
}

pub fn parse_barcode_bed(path: &str) -> anyhow::Result<Vec<BarcodeRecord>> {
    let reader = BufReader::new(File::open(path)?);
    let mut records = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 5 {
            continue;
        }
        records.push(BarcodeRecord {
            chrom: cols[0].to_string(),
            start: cols[1].parse()?,
            end:   cols[2].parse()?,
            subspecies: cols[3].to_string(),
            allele: cols[4].chars().next().unwrap_or('N'),
        });
    }
    Ok(records)
}

