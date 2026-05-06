use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};
use xdgen::{App, Context, FluentString};

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
