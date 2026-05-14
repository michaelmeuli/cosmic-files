use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};
use xdgen::{App, Context, FluentString};

#[derive(serde::Deserialize)]
struct SequencesConfig {
    #[serde(default)]
    genome: Vec<GenomeEntry>,
    #[serde(default)]
    append: Vec<AppendEntry>,
}

#[derive(serde::Deserialize)]
struct GenomeEntry {
    accession: String,
    output: String,
    locus_tag: Option<String>,
    seq_start: Option<u64>,
    seq_stop: Option<u64>,
}

#[derive(serde::Deserialize)]
struct AppendEntry {
    accession: String,
    fasta: String,
    // genome-extraction fields (mirrors [[genome]] in sequences.toml)
    locus_tag: Option<String>,
    seq_start: Option<u64>,
    seq_stop: Option<u64>,
}

fn ncbi_url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            ' ' => out.push_str("%20"),
            '[' => out.push_str("%5B"),
            ']' => out.push_str("%5D"),
            '/' => out.push_str("%2F"),
            ':' => out.push_str("%3A"),
            '"' => out.push_str("%22"),
            '(' => out.push_str("%28"),
            ')' => out.push_str("%29"),
            c => out.push(c),
        }
    }
    out
}

fn ncbi_bulk_download(
    base: &str,
    email: &str,
    api_key: Option<&str>,
    query: &str,
    output: &str,
    batch: usize,
) -> Result<usize, String> {
    let ak = api_key.map(|k| format!("&api_key={}", k)).unwrap_or_default();
    let encoded = ncbi_url_encode(query);

    let search_url = format!(
        "{}/esearch.fcgi?db=nucleotide&term={}&usehistory=y&retmax=0&retmode=json&email={}{}",
        base, encoded, email, ak
    );
    let resp: serde_json::Value = ureq::get(&search_url)
        .call()
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;

    let total: usize = resp["esearchresult"]["count"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    if total == 0 {
        return Err("no sequences found".into());
    }

    let web_env = resp["esearchresult"]["webenv"]
        .as_str()
        .ok_or("missing webenv in esearch response")?
        .to_string();
    let query_key = resp["esearchresult"]["querykey"]
        .as_str()
        .unwrap_or("1")
        .to_string();

    let delay_ms = if api_key.is_some() { 120 } else { 350 };
    let mut fasta = String::new();
    let mut retstart = 0usize;

    while retstart < total {
        let batch_size = batch.min(total - retstart);
        let fetch_url = format!(
            "{}/efetch.fcgi?db=nucleotide&WebEnv={}&query_key={}\
             &retstart={}&retmax={}&rettype=fasta&retmode=text&email={}{}",
            base, web_env, query_key, retstart, batch_size, email, ak
        );
        let chunk = ureq::get(&fetch_url)
            .call()
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|e| e.to_string())?;
        let count = chunk.matches('>').count();
        if count == 0 {
            break;
        }
        fasta.push_str(&chunk);
        retstart += batch_size;
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
    }

    if let Some(parent) = std::path::Path::new(output).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(output, &fasta).map_err(|e| e.to_string())?;
    Ok(fasta.matches('>').count())
}

fn ncbi_fetch_single(
    base: &str,
    email: &str,
    api_key: Option<&str>,
    accession: &str,
) -> Result<String, String> {
    let ak = api_key.map(|k| format!("&api_key={}", k)).unwrap_or_default();
    let url = format!(
        "{}/efetch.fcgi?db=nuccore&id={}&rettype=fasta&retmode=text&email={}{}",
        base, accession, email, ak
    );
    let text = ureq::get(&url)
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    if text.contains('>') {
        Ok(text)
    } else {
        Err(format!("no FASTA returned for {}", accession))
    }
}

// Returns (start, stop, strand) — coordinates are 1-based inclusive, strand 1=fwd 2=rev.
// Mirrors parse_feature_table() in scripts/fetch_sequences.py.
fn parse_feature_table(ft: &str, locus_tag: &str) -> Result<(u64, u64, u8), String> {
    let mut cur_start: Option<u64> = None;
    let mut cur_stop: Option<u64> = None;
    let mut cur_strand: u8 = 1;

    for line in ft.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('>') {
            continue;
        }
        if !line.starts_with('\t') {
            let parts: Vec<&str> = stripped.split('\t').collect();
            if parts.len() >= 2 {
                let a: Option<u64> = parts[0].trim_start_matches(['<', '>']).parse().ok();
                let b: Option<u64> = parts[1].trim_start_matches(['<', '>']).parse().ok();
                if let (Some(a), Some(b)) = (a, b) {
                    cur_start = Some(a.min(b));
                    cur_stop = Some(a.max(b));
                    cur_strand = if a > b { 2 } else { 1 };
                } else {
                    cur_start = None;
                    cur_stop = None;
                }
            }
        } else {
            let parts: Vec<&str> = stripped.split('\t').collect();
            if parts.len() >= 2 && parts[0] == "locus_tag" && parts[1] == locus_tag {
                if let (Some(s), Some(e)) = (cur_start, cur_stop) {
                    return Ok((s, e, cur_strand));
                }
            }
        }
    }
    Err(format!("locus_tag {:?} not found in feature table", locus_tag))
}

fn ncbi_fetch_genome_gene(
    base: &str,
    email: &str,
    api_key: Option<&str>,
    accession: &str,
    locus_tag: Option<&str>,
    seq_start: Option<u64>,
    seq_stop: Option<u64>,
) -> Result<String, String> {
    let ak = api_key.map(|k| format!("&api_key={}", k)).unwrap_or_default();
    let delay_ms = if api_key.is_some() { 120u64 } else { 350 };

    let (start, stop, strand) = if let Some(tag) = locus_tag {
        let ft_url = format!(
            "{}/efetch.fcgi?db=nuccore&id={}&rettype=ft&retmode=text&email={}{}",
            base, accession, email, ak
        );
        let ft = ureq::get(&ft_url)
            .call()
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|e| e.to_string())?;
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        parse_feature_table(&ft, tag)?
    } else {
        match (seq_start, seq_stop) {
            (Some(s), Some(e)) => (s, e, 1u8),
            _ => return Err("must specify locus_tag or both seq_start and seq_stop".into()),
        }
    };

    let url = format!(
        "{}/efetch.fcgi?db=nuccore&id={}&rettype=fasta&retmode=text\
         &seq_start={}&seq_stop={}&strand={}&email={}{}",
        base, accession, start, stop, strand, email, ak
    );
    let text = ureq::get(&url)
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    if text.contains('>') {
        Ok(text)
    } else {
        Err(format!("no FASTA returned for {}:{}-{}", accession, start, stop))
    }
}

fn fetch_myco_sequences() {
    const BASE: &str = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils";
    const EMAIL: &str = "michael.meuli@gmail.com";
    const BATCH: usize = 200;

    // (ncbi_query, filename)
    let targets: &[(&str, &str)] = &[
        (
            "Mycobacteriaceae[Organism] AND (16S[Title] OR rrs[Gene Name]) AND 400:3000[SLEN] AND type_material[Filter]",
            "myco_rrs.fasta",
        ),
        (
            "Mycobacteriaceae[Organism] AND (hsp65[Gene Name] OR groEL2[Gene Name]) AND 400:3000[SLEN] AND type_material[Filter]",
            "myco_hsp65.fasta",
        ),
        (
            "Mycobacteriaceae[Organism] AND rpoB[Gene Name] AND 400:3000[SLEN] AND type_material[Filter]",
            "myco_rpob.fasta",
        ),
        (
            "Mycobacteriaceae[Organism] AND erm(41)[Gene Name] AND 400:3000[SLEN]",
            "myco_erm41.fasta",
        ),
        (
            "Mycobacteriaceae[Organism] AND (23S ribosomal RNA[Title] OR rrl[Gene Name]) AND 400:3000[SLEN] AND type_material[Filter]",
            "myco_rrl.fasta",
        ),
    ];

    let api_key = std::env::var("NCBI_API_KEY").ok();
    println!("cargo:rerun-if-env-changed=NCBI_API_KEY");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let seq_dir = manifest_dir.join("res/sequences");

    for &(query, filename) in targets {
        let path = seq_dir.join(filename);
        println!("cargo:rerun-if-changed=res/sequences/{}", filename);

        let needs_download = !path.exists()
            || path.metadata().map(|m| m.len() == 0).unwrap_or(true);

        if needs_download {
            println!("cargo:warning=fetch_myco: downloading {}", filename);
            match ncbi_bulk_download(BASE, EMAIL, api_key.as_deref(), query, path.to_str().unwrap(), BATCH) {
                Ok(n) => println!("cargo:warning=fetch_myco: wrote {} sequences → {}", n, filename),
                Err(e) => println!("cargo:warning=fetch_myco: failed for {}: {}", filename, e),
            }
        }
    }

    // User-defined accessions from sequences.toml [[append]] entries.
    // Each entry names an accession and a target fasta filename; the sequence
    // is fetched and appended if the accession is not already present.
    let toml_path = seq_dir.join("sequences.toml");
    println!("cargo:rerun-if-changed=res/sequences/sequences.toml");
    if let Ok(toml_str) = fs::read_to_string(&toml_path) {
        match toml::from_str::<SequencesConfig>(&toml_str) {
            Ok(config) => {
                let delay_ms = if api_key.is_some() { 120u64 } else { 350 };
                for entry in &config.genome {
                    let out_path = seq_dir.join(&entry.output);
                    println!("cargo:rerun-if-changed=res/sequences/{}", entry.output);
                    if out_path.exists() && out_path.metadata().map(|m| m.len() > 0).unwrap_or(false) {
                        println!("cargo:warning=fetch_myco: {} exists — skip", entry.output);
                        continue;
                    }
                    println!("cargo:warning=fetch_myco: fetching genome gene → {}", entry.output);
                    if let Some(parent) = out_path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    match ncbi_fetch_genome_gene(
                        BASE, EMAIL, api_key.as_deref(), &entry.accession,
                        entry.locus_tag.as_deref(), entry.seq_start, entry.seq_stop,
                    ) {
                        Ok(seq) => {
                            match fs::write(&out_path, seq.as_bytes()) {
                                Ok(_) => println!("cargo:warning=fetch_myco: wrote {}", entry.output),
                                Err(e) => println!("cargo:warning=fetch_myco: write error for {}: {e}", entry.output),
                            }
                        }
                        Err(e) => println!("cargo:warning=fetch_myco: failed to fetch {}: {e}", entry.output),
                    }
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
                for entry in &config.append {
                    let fasta_path = seq_dir.join(&entry.fasta);
                    let existing = if fasta_path.exists() {
                        fs::read_to_string(&fasta_path).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    if existing.contains(entry.accession.as_str()) {
                        println!("cargo:warning=fetch_myco: {} already in {} — skip", entry.accession, entry.fasta);
                        continue;
                    }
                    println!("cargo:warning=fetch_myco: appending {} → {}", entry.accession, entry.fasta);
                    let is_genome = entry.locus_tag.is_some() || entry.seq_start.is_some();
                    let fetch_result = if is_genome {
                        ncbi_fetch_genome_gene(
                            BASE, EMAIL, api_key.as_deref(), &entry.accession,
                            entry.locus_tag.as_deref(), entry.seq_start, entry.seq_stop,
                        )
                    } else {
                        ncbi_fetch_single(BASE, EMAIL, api_key.as_deref(), &entry.accession)
                    };
                    match fetch_result {
                        Ok(seq) => {
                            match fs::OpenOptions::new().append(true).create(true).open(&fasta_path) {
                                Ok(mut f) => {
                                    if let Err(e) = f.write_all(seq.as_bytes()) {
                                        println!("cargo:warning=fetch_myco: write error for {}: {e}", entry.accession);
                                    } else {
                                        println!("cargo:warning=fetch_myco: appended {}", entry.accession);
                                    }
                                }
                                Err(e) => println!("cargo:warning=fetch_myco: open error for {}: {e}", entry.fasta),
                            }
                        }
                        Err(e) => println!("cargo:warning=fetch_myco: failed to fetch {}: {e}", entry.accession),
                    }
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
            }
            Err(e) => println!("cargo:warning=fetch_myco: failed to parse sequences.toml: {e}"),
        }
    }
}


fn reverse_complement_bytes(seq: &[u8]) -> Vec<u8> {
    seq.iter().rev().map(|&b| match b.to_ascii_uppercase() {
        b'A' => b'T', b'T' => b'A',
        b'G' => b'C', b'C' => b'G',
        _ => b'N',
    }).collect()
}

fn load_genome_fasta(path: &std::path::Path) -> std::collections::HashMap<String, Vec<u8>> {
    let mut map = std::collections::HashMap::new();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return map,
    };
    let mut cur_name = String::new();
    let mut cur_seq: Vec<u8> = Vec::new();
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix('>') {
            if !cur_name.is_empty() {
                map.insert(std::mem::take(&mut cur_name), std::mem::take(&mut cur_seq));
            }
            cur_name = rest.split_whitespace().next().unwrap_or("").to_string();
        } else {
            cur_seq.extend_from_slice(line.trim().as_bytes());
        }
    }
    if !cur_name.is_empty() {
        map.insert(cur_name, cur_seq);
    }
    map
}

struct GffFeature {
    seqname: String,
    ftype:   String,
    start:   usize,
    stop:    usize,
    strand:  char,
    attrs:   std::collections::HashMap<String, String>,
}

fn parse_gff(path: &std::path::Path) -> Vec<GffFeature> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut features = Vec::new();
    for line in content.lines() {
        if line.starts_with('#') || line.is_empty() { continue; }
        let cols: Vec<&str> = line.splitn(9, '\t').collect();
        if cols.len() < 9 { continue; }
        let start = match cols[3].parse::<usize>() { Ok(v) => v, Err(_) => continue };
        let stop  = match cols[4].parse::<usize>() { Ok(v) => v, Err(_) => continue };
        let strand = cols[6].chars().next().unwrap_or('+');
        let mut attrs = std::collections::HashMap::new();
        for pair in cols[8].split(';') {
            if let Some((k, v)) = pair.split_once('=') {
                attrs.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        features.push(GffFeature { seqname: cols[0].to_string(), ftype: cols[2].to_string(), start, stop, strand, attrs });
    }
    features
}

fn gff_feature_matches(f: &GffFeature, gene: &str) -> bool {
    let name    = f.attrs.get("Name").map(String::as_str).unwrap_or("");
    let gene_kv = f.attrs.get("gene").map(String::as_str).unwrap_or("");
    let product = f.attrs.get("product").map(String::as_str).unwrap_or("");
    match gene {
        "rrs"  => name == "rrs"  || (f.ftype == "rRNA" && product.contains("16S ribosomal RNA")),
        "rrl"  => name == "rrl"  || (f.ftype == "rRNA" && product.contains("23S ribosomal RNA")),
        "rpoB" => name == "rpoB" || gene_kv == "rpoB",
        "erm"  => !name.is_empty() && name.to_ascii_lowercase().contains("erm"),
        _ => false,
    }
}

fn extract_ntm_db_sequences(seq_dir: &std::path::Path) {
    use std::collections::HashSet;

    struct Target { gene: &'static str, fasta: &'static str }
    let targets = [
        Target { gene: "rrs",  fasta: "myco_rrs.fasta"  },
        Target { gene: "rrl",  fasta: "myco_rrl.fasta"  },
        Target { gene: "rpoB", fasta: "myco_rpob.fasta" },
        Target { gene: "erm",  fasta: "myco_erm41.fasta" },
    ];

    let db_dir = seq_dir.join("ntm-db/db");
    let entries = match fs::read_dir(&db_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let species_path = entry.path();
        if !species_path.is_dir() { continue; }
        let dir_name = entry.file_name().to_string_lossy().into_owned();
        let species_name = dir_name.replace('_', " ");

        let gff_path   = species_path.join("genome.gff");
        let fasta_path = species_path.join("genome.fasta");
        println!("cargo:rerun-if-changed=res/sequences/ntm-db/db/{}/genome.gff", dir_name);
        if !gff_path.exists() || !fasta_path.exists() { continue; }

        let genome   = load_genome_fasta(&fasta_path);
        let features = parse_gff(&gff_path);

        for target in &targets {
            let target_path = seq_dir.join(target.fasta);
            let existing = if target_path.exists() {
                fs::read_to_string(&target_path).unwrap_or_default()
            } else {
                String::new()
            };

            let mut seen: HashSet<(String, usize, usize)> = HashSet::new();
            for feature in &features {
                if !gff_feature_matches(feature, target.gene) { continue; }
                let coord_key = (feature.seqname.clone(), feature.start, feature.stop);
                if !seen.insert(coord_key) { continue; }

                let coord_str = format!("{}:{}-{}", feature.seqname, feature.start, feature.stop);
                if existing.contains(&coord_str) { continue; }

                let contig = match genome.get(&feature.seqname) {
                    Some(c) => c,
                    None => {
                        println!("cargo:warning=ntm-db: contig {} not found in {}", feature.seqname, dir_name);
                        continue;
                    }
                };
                if feature.start == 0 || feature.stop > contig.len() {
                    println!("cargo:warning=ntm-db: coords out of range {} in {}", coord_str, dir_name);
                    continue;
                }

                let mut seq = contig[feature.start - 1..feature.stop].to_vec();
                if feature.strand == '-' { seq = reverse_complement_bytes(&seq); }

                let mut fasta_entry = format!(">{} {} {}\n", coord_str, species_name, target.gene).into_bytes();
                for chunk in seq.chunks(70) {
                    fasta_entry.extend_from_slice(chunk);
                    fasta_entry.push(b'\n');
                }

                match fs::OpenOptions::new().append(true).create(true).open(&target_path) {
                    Ok(mut f) => match f.write_all(&fasta_entry) {
                        Ok(_)  => println!("cargo:warning=ntm-db: {} {} → {}", species_name, target.gene, target.fasta),
                        Err(e) => println!("cargo:warning=ntm-db: write error {}: {e}", target.fasta),
                    },
                    Err(e) => println!("cargo:warning=ntm-db: open error {}: {e}", target.fasta),
                }
            }
        }
    }
}

/// Accessions that must be present in myco_hsp65.fasta for SNP dispatch to work.
/// Keep in sync with the constants in src/sequencing/hsp65.rs.
const HSP65_REQUIRED_ACCS: &[&str] = &["AF547836", "AF547849", "AY299134", "AY299145"];

fn check_hsp65_integrity(seq_dir: &std::path::Path) {
    let path = seq_dir.join("myco_hsp65.fasta");
    let fasta = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => panic!("cannot read myco_hsp65.fasta: {e}"),
    };
    let present: std::collections::HashSet<&str> = fasta
        .lines()
        .filter(|l| l.starts_with('>'))
        .filter_map(|l| l[1..].split_whitespace().next())
        .map(|id| id.split('.').next().unwrap_or(id))
        .collect();
    for acc in HSP65_REQUIRED_ACCS {
        assert!(
            present.contains(acc),
            "myco_hsp65.fasta is missing required accession {acc} — SNP dispatch will not work"
        );
    }
}

fn main() {
    fetch_myco_sequences();

    let manifest_dir_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    extract_ntm_db_sequences(&manifest_dir_path.join("res/sequences"));
    check_hsp65_integrity(&manifest_dir_path.join("res/sequences"));

    // Embed the ntm-db submodule commit hash so the UI can display it.
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD:res/sequences/ntm-db"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim()[..7].to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=NTM_DB_COMMIT={}", commit);
    println!("cargo:rerun-if-changed=.git/modules/res/sequences/ntm-db/HEAD");

    let id = "com.system76.CosmicFiles";
    let ctx = Context::new("i18n", env::var("CARGO_PKG_NAME").unwrap()).unwrap();
    let app = App::new(FluentString("cosmic-files"))
        .comment(FluentString("comment"))
        .keywords(FluentString("keywords"));
    let output = PathBuf::from("target/xdgen");
    fs::create_dir_all(&output).unwrap();
    fs::write(
        output.join(format!("{}.desktop", id)),
        app.expand_desktop(format!("res/{}.desktop", id), &ctx)
            .unwrap(),
    )
    .unwrap();
    fs::write(
        output.join(format!("{}.metainfo.xml", id)),
        app.expand_metainfo(format!("res/{}.metainfo.xml", id), &ctx)
            .unwrap(),
    )
    .unwrap();
}
