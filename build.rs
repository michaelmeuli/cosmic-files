use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};
use xdgen::{App, Context, FluentString};

#[derive(serde::Deserialize)]
struct SequencesConfig {
    #[serde(default)]
    append: Vec<AppendEntry>,
}

#[derive(serde::Deserialize)]
struct AppendEntry {
    accession: String,
    fasta: String,
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

const DAI2011_HSP65_ACCESSIONS: &[&str] = &[
    // M. abscessus (NC_010397 omitted — whole genome)
    "AY458075", "AF547802", "EF486338", "AY498743", "JF491290",
    // M. africanum
    "AF547803", "FJ617583", "JF491313",
    // M. agri
    "AY438080",
    // M. aichiense
    "AY299147", "AF547804",
    // M. alvei
    "AF547805",
    // M. aromaticivorans
    "DQ841182",
    // M. arosiense
    "JF491321", "EU370531", "GQ153297",
    // M. arupense
    "EU191917", "GQ214503", "JF491325", "DQ168662",
    // M. asiaticum
    "AY299133", "GU362517",
    // M. aubagnense
    "AY859677", "DQ987727",
    // M. aurum
    "AF350414", "FJ172326", "AY438081",
    // M. austroafricanum
    "AF547807",
    // M. avium subsp. avium
    "AF126030", "EU239779", "GQ153289", "JF491291", "AF547808",
    // M. avium subsp. paratuberculosis
    "AF547809", "AY299137",
    // M. avium subsp. silvaticum
    "EU239781", "AF547810",
    // M. boenickei
    "AY943195",
    // M. bohemicum
    "AF547811",
    // M. bolletii
    "DQ987724", "EU266576", "AY859675", "FJ607778",
    // M. botniense
    "AF547812",
    // M. bouchedurhonense
    "HM602039",
    // M. bovis
    "AF547813", "JF491332",
    // M. branderi
    "AF547815",
    // M. brisbanense
    "AB456564", "JF491333", "AY943196",
    // M. brumae
    "AF547816",
    // M. canariasense
    "AY255477", "JF491316",
    // M. caprae
    "AF547884",
    // M. celatum
    "AY299180", "JF491292", "AF547817",
    // M. chelonae
    "AF547818", "AY458074", "JF491293",
    // M. chimaera
    "GQ153296", "AY943198", "EU239783",
    // M. chitae
    "AF547819", "AY299149",
    // M. chlorophenolicum
    "AF547820",
    // M. chubuense
    "AF547821",
    // M. colombiense
    "EU239785", "GQ153298",
    // M. conceptionense
    "AM902957", "EU191920", "AY859678",
    // M. confluentis
    "AF547822",
    // M. conspicuum
    "AF547823",
    // M. cookie
    "AF547824",
    // M. cosmeticum
    "AY449730", "DQ124111",
    // M. crocinum
    "DQ533998",
    // M. diernhoferi
    "AF547825",
    // M. doricum
    "AF547826",
    // M. duvalii
    "AF547827",
    // M. elephantis
    "AF547828",
    // M. fallax
    "AF547829", "JF491294",
    // M. farcinogenes
    "AY299150", "AF547830", "AY458073",
    // M. flavescens
    "AF350413", "GU362519",
    // M. florentinum
    "DQ350162", "JF491317",
    // M. fluoranthenivorans
    "DQ350157", "JF491318",
    // M. fortuitum subsp. acetamidolyticum
    "AF547832", "JF491314",
    // M. fortuitum subsp. fortuitum
    "AF547833", "JF491295",
    // M. frederiksbergense
    "AF547834",
    // M. gadium
    "AF547835",
    // M. gastri
    "AF547836", "JF491315",
    // M. genavense
    "AF547837",
    // M. gilvum
    "AF547838",
    // M. goodii
    "AF547839", "AY458071",
    // M. gordonae
    "AF547840", "AF434734",
    // M. haemophilum
    "AF547841", "AY299185", "GQ245967", "JF491296",
    // M. hassiacum
    "AF547842",
    // M. heckeshornense
    "AF547843",
    // M. heidelbergense
    "AF547844",
    // M. hiberniae
    "AY438083", "JF491297",
    // M. hodleri
    "AF547845",
    // M. holsaticum
    "AY438084",
    // M. houstonense
    "AY458077", "DQ987725",
    // M. immunogenum
    "AY458081", "EU266577",
    // M. insubricum
    "JF491319", "EF584487",
    // M. interjectum
    "AF547846", "JF491298",
    // M. intermedium
    "AF547847", "AY299187",
    // M. intracellulare
    "AF126035", "DQ284774", "GQ153290", "JF491299", "U85633",
    // M. kansasii
    "AF547849", "AF434739", "AY299189", "JF491300",
    // M. komossense
    "AY438649",
    // M. kubicae
    "AF547850", "AY373458",
    // M. kumamotonense
    "AB239920", "EU191915", "JF491323",
    // M. kyorinense
    "AB370171", "HM602040",
    // M. lacus
    "AY438090",
    // M. lepraemurium (TS130; M. leprae TN is NC_002677 — omitted)
    "AY550232",
    // M. lentiflavum
    "AF547851",
    // M. llatzerense
    "AM421341", "JF491330",
    // M. madagascariense
    "AF547852",
    // M. mageritense
    "AY458070", "AF547853",
    // M. malmoense
    "AF547854", "GQ153293", "JF491301",
    // M. mantenii
    "FJ232523", "HM602041",
    // M. marinum
    "AY299134", "AF456470", "AB548715", "AF271346", "AF547855",
    // M. marseillense
    "EU239787", "HM602037",
    // M. massiliense
    "EU191919", "EF486339", "EU266578", "AY596465",
    // M. microti
    "AF547856", "AY299135",
    // M. monacense
    "EU191918", "JF491320",
    // M. montefiorense
    "AY943204", "AY027785",
    // M. moriokaense
    "AF547857", "AY859680",
    // M. mucogenicum
    "AY299155", "AY458079",
    // M. murale
    "AF547859",
    // M. nebraskense
    "DQ124110", "GQ153294", "AY368457",
    // M. neoaurum
    "AY299156", "FJ172320", "JF491302", "AF547860",
    // M. neworleansense
    "AY943199", "AY458076", "AY496143",
    // M. nonchromogenicum
    "AF547861", "AY299136", "AF434732", "JF491303",
    // M. noviomagense
    "EU600390",
    // M. novocastrense
    "AF547862",
    // M. obuense
    "AF547863",
    // M. pallens
    "DQ533997",
    // M. palustre
    "AY943200",
    // M. paraffinicum
    "GQ153287",
    // M. parafortuitum
    "AF547864",
    // M. parascrofulaceum
    "AY337274", "GQ153295", "AY943201",
    // M. paraseoulense
    "HM602042", "JF491324", "DQ536402",
    // M. parmense
    "HM022199",
    // M. peregrinum
    "AM902953", "AY458069", "AF547865", "AY299159",
    // M. phlei
    "AY299158", "AF547866",
    // M. phocaicum
    "DQ987726", "AY859676", "EU266579",
    // M. porcinum
    "AY496137", "JF491326",
    // M. poriferae
    "AF547868",
    // M. pseudoshottsii
    "AM902956", "DQ987722", "AY571788",
    // M. psychrotolerans
    "HM602035",
    // M. pulveris
    "AF547869",
    // M. pyrenivorans
    "JF510463",
    // M. rhodesiae
    "AF547870",
    // M. riyadhense
    "EU921671",
    // M. rufum
    "DQ841181",
    // M. rutilum
    "DQ841180",
    // M. salmoniphilum
    "DQ866777",
    // M. saskatchewanense
    "AY208858", "AY943203", "JF491331",
    // M. scrofulaceum
    "GQ153288", "AF434733", "AY299138", "JF491304", "AF547871",
    // M. senegalense
    "AM902954", "AY684045", "JF491327",
    // M. senuense
    "FJ268582", "JF491328", "DQ536409",
    // M. seoulense
    "EU191916", "JF491322",
    // M. septicum
    "AY373457", "AY496142", "JF491329",
    // M. setense
    "EU371505",
    // M. shimoidei
    "AF547874", "JF491305",
    // M. shottsii
    "AM902955", "DQ987723", "AY550225", "EU619895",
    // M. simiae
    "AF547875", "GQ153292", "AF434730", "JF491306",
    // M. smegmatis
    "AY458065", "JF491307", "AF547876",
    // M. sphagni
    "AF547877",
    // M. stomatepiae
    "AM902968",
    // M. szulgai
    "AF350412", "AY299141", "JF491308", "AF547878",
    // M. terrae
    "AF257468", "AF434736", "AY299142", "AF547879",
    // M. thermoresistibile
    "AF547880",
    // M. timonense
    "HM602038",
    // M. tokaiense
    "AF547881", "JF491309",
    // M. triplex
    "AY027786", "GQ153291", "AF547882",
    // M. triviale
    "AF547883", "AF434737", "AY299143", "JF491310",
    // M. tuberculosis (NC_000962 omitted — whole genome)
    "AY299144", "JF491311",
    // M. tusciae
    "AF547887",
    // M. ulcerans
    "AY299145", "AB548723", "AF271096",
    // M. vaccae
    "AF547889", "JF491312",
    // M. vanbaalenii (NC_008726 omitted — whole genome)
    "AY438091",
    // M. vulneris
    "EU834054",
    // M. wolinskyi
    "AF547890", "AY299164", "AY458064",
    // M. xenopi
    "AF547891", "AF434738", "AY373454",
];

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

    // Dai 2011 curated hsp65 reference set (Dai, Chen & Lauzardo, JCM 49:2296-2303)
    let dai2011_filename = "myco_hsp65_dai2011.fasta";
    let dai2011_path = seq_dir.join(dai2011_filename);
    println!("cargo:rerun-if-changed=res/sequences/{}", dai2011_filename);

    let dai2011_needs_download = !dai2011_path.exists()
        || dai2011_path.metadata().map(|m| m.len() == 0).unwrap_or(true);

    if dai2011_needs_download {
        println!("cargo:warning=fetch_myco: downloading {}", dai2011_filename);
        let delay_ms = if api_key.is_some() { 120u64 } else { 350 };
        let ak = api_key.as_deref().map(|k| format!("&api_key={k}")).unwrap_or_default();
        let mut fasta = String::new();
        let mut ok = true;

        for chunk in DAI2011_HSP65_ACCESSIONS.chunks(100) {
            let ids = chunk.join(",");
            let url = format!(
                "{BASE}/efetch.fcgi?db=nuccore&id={ids}&rettype=fasta&retmode=text&email={EMAIL}{ak}"
            );
            match ureq::get(&url).call() {
                Ok(resp) => match resp.into_string() {
                    Ok(text) => fasta.push_str(&text),
                    Err(e) => {
                        println!("cargo:warning=fetch_myco: dai2011 read error: {e}");
                        ok = false;
                        break;
                    }
                },
                Err(e) => {
                    println!("cargo:warning=fetch_myco: dai2011 fetch error: {e}");
                    ok = false;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }

        if ok {
            match fs::write(&dai2011_path, &fasta) {
                Ok(_) => println!(
                    "cargo:warning=fetch_myco: wrote {} sequences → {}",
                    fasta.matches('>').count(),
                    dai2011_filename
                ),
                Err(e) => println!("cargo:warning=fetch_myco: failed to write {dai2011_filename}: {e}"),
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
                for entry in &config.append {
                    let fasta_path = seq_dir.join(&entry.fasta);
                    let existing = if fasta_path.exists() {
                        fs::read_to_string(&fasta_path).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    if existing.contains(entry.accession.as_str()) {
                        continue;
                    }
                    println!("cargo:warning=fetch_myco: appending {} → {}", entry.accession, entry.fasta);
                    match ncbi_fetch_single(BASE, EMAIL, api_key.as_deref(), &entry.accession) {
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
