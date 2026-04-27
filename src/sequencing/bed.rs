use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashMap;

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

fn call_bed_subspecies(
    records: &[BarcodeRecord],
    observed: &HashMap<u64, char>,  // position (0-based) -> base
) -> String {
    let mut hits: HashMap<&str, usize> = HashMap::new();
    let mut total: HashMap<&str, usize> = HashMap::new();

    for rec in records {
        let counter = total.entry(&rec.subspecies).or_insert(0);
        *counter += 1;

        if let Some(&base) = observed.get(&rec.start) {
            if base == rec.allele {
                *hits.entry(&rec.subspecies).or_insert(0) += 1;
            }
        }
    }

    // Pick subspecies with the highest hit fraction
    hits.iter()
        .map(|(&subsp, &h)| {
            let t = *total.get(subsp).unwrap_or(&1) as f64;
            (subsp, h as f64 / t)
        })
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .map(|(s, _)| s.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn build_position_index(records: &[BarcodeRecord])
    -> HashMap<u64, Vec<&BarcodeRecord>>
{
    let mut idx: HashMap<u64, Vec<&BarcodeRecord>> = HashMap::new();
    for rec in records {
        idx.entry(rec.start).or_default().push(rec);
    }
    idx
}