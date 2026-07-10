//! Parser for BED-like subspecies barcode files (5-column, tab-separated).

use std::fs::File;
use std::io::{BufRead, BufReader};

/// One row of a barcode BED file: a genomic position diagnostic for a given subspecies/allele.
#[derive(Debug, Clone)]
pub struct BarcodeRecord {
    pub chrom: String,
    /// 0-based, BED convention.
    pub start: u64,
    pub end: u64,
    pub subspecies: String,
    /// Expected base at this position for `subspecies`.
    pub allele: char,
}

/// Parses a 5-column barcode BED file (`chrom start end subspecies allele`).
///
/// Blank lines and lines starting with `#` are skipped; rows with fewer than 5 tab-separated
/// columns are silently dropped rather than treated as an error.
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
            end: cols[2].parse()?,
            subspecies: cols[3].to_string(),
            allele: cols[4].chars().next().unwrap_or('N'),
        });
    }
    Ok(records)
}
