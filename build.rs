use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};
use xdgen::{App, Context, FluentString};

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

fn fetch_myco_sequences() {
    const BASE: &str = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils";
    const EMAIL: &str = "michael.meuli@gmail.com";
    const BATCH: usize = 200;

    // (const_name, ncbi_query, filename)
    let targets: &[(&str, &str, &str)] = &[
        (
            "REF_MYCO_RRS",
            "Mycobacteriaceae[Organism] AND (16S[Title] OR rrs[Gene Name]) AND 400:3000[SLEN] AND type_material[Filter]",
            "myco_rrs.fasta",
        ),
        (
            "REF_MYCO_HSP65",
            "Mycobacteriaceae[Organism] AND (hsp65[Gene Name] OR groEL2[Gene Name]) AND 400:3000[SLEN] AND type_material[Filter]",
            "myco_hsp65.fasta",
        ),
        (
            "REF_MYCO_RPOB",
            "Mycobacteriaceae[Organism] AND rpoB[Gene Name] AND 400:3000[SLEN] AND type_material[Filter]",
            "myco_rpoB.fasta",
        ),
        (
            "REF_MYCO_ERM41",
            "Mycobacteriaceae[Organism] AND erm(41)[Gene Name] AND 400:3000[SLEN]",
            "myco_erm41.fasta",
        ),
        (
            "REF_MYCO_RRL",
            "Mycobacteriaceae[Organism] AND (23S ribosomal RNA[Title] OR rrl[Gene Name]) AND 400:3000[SLEN] AND type_material[Filter]",
            "myco_rrl.fasta",
        ),
    ];

    let api_key = std::env::var("NCBI_API_KEY").ok();
    println!("cargo:rerun-if-env-changed=NCBI_API_KEY");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let seq_dir = manifest_dir.join("res/sequences");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let mut codegen = String::new();

    for &(const_name, query, filename) in targets {
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

        // Emit include_str! when the file has content; fall back to empty string so
        // the build succeeds even when the network is unavailable.
        if path.exists() && path.metadata().map(|m| m.len() > 0).unwrap_or(false) {
            let abs = path.to_str().unwrap().replace('\\', "/");
            codegen.push_str(&format!("const {const_name}: &str = include_str!(\"{abs}\");\n"));
        } else {
            codegen.push_str(&format!("const {const_name}: &str = \"\";\n"));
        }
    }

    fs::write(out_dir.join("myco_sequences.rs"), &codegen)
        .expect("failed to write myco_sequences.rs to OUT_DIR");
}

fn fetch_sequences() {
    println!("cargo:rerun-if-changed=res/sequences/sequences.toml");
    println!("cargo:rerun-if-changed=scripts/fetch_sequences.py");

    let candidates: &[&str] = if cfg!(windows) {
        &["python", "py", "python3"]
    } else {
        &["python3", "python"]
    };

    for &py in candidates {
        let result = Command::new(py)
            .args(["scripts/fetch_sequences.py"])
            .status();
        match result {
            Ok(s) if s.success() => return,
            Ok(s) => {
                println!("cargo:warning=fetch_sequences.py exited with {s}");
                return;
            }
            Err(_) => continue,
        }
    }
    println!(
        "cargo:warning=Python interpreter not found; \
         FASTA files in res/sequences/ must already exist"
    );
}

fn main() {
    fetch_myco_sequences();
    fetch_sequences();

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
