# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a fork of [cosmic-files](https://github.com/pop-os/cosmic-files) (System76's COSMIC desktop file manager) extended with TB (Tuberculosis) Profiler integration for genomic sequence analysis. The file manager features tabs, SSH/SFTP support, file operations with progress tracking, thumbnail caching, and a custom `sequencing/` module for bacterial resistance prediction from AB1 capillary sequencing files.

## Commands

```bash
# Build & run
just build-debug          # Debug build
just build-release        # Release build
just run                  # Release build + run with RUST_LOG=cosmic_files=debug
just dev                  # cargo fmt + run with debug logs

# Lint & format
just check                # cargo clippy --all-features (pedantic lints)
cargo fmt                 # Format code

# Test
just test                 # cargo test
cargo test -p cosmic-files -- sequencing  # Run only sequencing tests

# Docs
cargo doc --document-private-items --open  # Also used in CI (docs.yml)
```

**Feature flags:** Default features include `russh`. Other notable flags: `dbus-config`, `desktop`, `gvfs`, `io-uring`, `jemalloc`, `notify`, `wayland`, `wgpu`.

## Architecture

The app follows a message-driven state machine (Elm-style) via `libcosmic` (Iced-based GUI framework):

- **`app.rs`** — Core `App` struct and `Message` enum (~100+ variants). All UI events flow through `update(message)`.
- **`tab.rs`** — `Tab` struct: file listing view model, sorting, selection, search, gallery. `Location` enum covers local paths, Trash, Recents, Network (SSH/SMB), Desktop.
- **`operation/`** — Async file operations (copy/move/delete/archive) with a progress-tracking `Controller` state machine. Recursive operations are handled in `recursive.rs`.
- **`dialog.rs`** — Modal dialogs for file conflicts, open-with, and confirmations.
- **`config.rs`** — Persists settings via `cosmic_config::Config` (XDG on Linux, registry on Windows).
- **`sequencing/`** — TB Profiler genomic analysis (see below).
- **`russh/`** — Optional SSH/SFTP client (feature-gated).
- **`mounter/`** — GVFS mount management.
- **`thumbnail_cacher.rs`** — Semaphore-limited (4 workers) async thumbnail generation with size-categorized JPEG caching.

### Sequencing Module (`src/sequencing/`)

The core unique feature of this fork. Parses AB1 capillary sequencer files and identifies mycobacterial species/resistance:

- **`mod.rs`** — AB1 chromatogram parsing, Phred-quality trimming, `align_to_ref` (semiglobal alignment via rust-bio's `pairwise::Aligner`; match +1, mismatch −1, gap open −5, gap extend −1; identity = matches / reference span; gene modules call it on both forward and reverse complement and keep the better hit), `trim_alignment_ends` (sliding-window trimming of low-identity alignment ends), pairwise alignment formatting, FASTA database lookup.
- **`tb_data.rs`** — Deserializes TBProfiler JSON output (`*.results.json`); confidence ranking (strongest: "Assoc w R" → weakest: "Not assoc w R").
- **`erm41.rs`** — erm(41) loss-of-function calls for *M. abscessus* macrolide resistance (13 LOF positions; C28 = susceptible, T28 = inducible resistance).
- **`rrl.rs`** — 23S rRNA macrolide resistance at positions 2057–2058 (wildtype A2057/A2058 = susceptible).
- **`rrs.rs`** — 16S rRNA species identification.
- **`rrs3end.rs`** — 16S rRNA 3′-end analysis: position 1248 discriminates *M. marinum* (A1248) from *M. ulcerans* (G1248); otherwise mirrors `rrs.rs`'s aminoglycoside resistance-SNP calling (kept separate via `rrs_snp_calls_3end`).
- **`rpob.rs`** — rpoB species identification only (no diagnostic SNP calls). `RpoBRegion` (NTM 2573f/3337r, Mtb RRDR, Mtb 5′, Mtb Xpert) selects a region-specific reference pool; NTM keeps the `"rpoB"` gene label, the Mtb regions are labelled `"rpoB RRDR"`, `"rpoB 5'"`, `"rpoB Xpert"`.
- **`pnca.rs`** — pncA pyrazinamide resistance for *M. tuberculosis* complex; parses the WHO catalogue (`tbprofiler/mutations.csv`) at startup into per-position nucleotide/amino-acid maps (gene + 50 bp promoter flank) and calls every listed site (`is_susceptible_pnca` combines them into one verdict).
- **`hsp65.rs`** — hsp65/groEL2 SNP calls for *M. kansasii/gastri* and *M. marinum/ulcerans* discrimination. SNP positions are 0-based offsets into four specific GenBank partial-cds entries (`AF547836`/`AF547849`, `AY299134`/`AY299145`) defined in **`hsp65_snp_refs.rs`**, which is shared with `build.rs` via `include!`. `check_hsp65_integrity` verifies their length and their alleles at every SNP position. Only hits on exactly those accessions get SNP calls, and `HSP65_REFS` exempts them from substring dedup.
- **`bed.rs`** — BED file format utilities.
- **`ab1_filename.rs`** — `parse_ab1_filename` → `(sample_id, Option<Ab1Gene>)`: the single source of AB1 filename → gene dispatch for both the batch scan and the preview pane. Rules follow kansasii-docs `SANGER_LABNUMBERS.md` / `SANGER_RPOB.md` and cosmic-seq `PRIMERS.md`; rpoB reads get an `RpoBRegion` (MAB, marinum and other-genus rpoB reads get `None`).
- **`microsynth.rs`** (feature `russh`) — Downloads per-order `.zip` archives from Microsynth's secure download area (SFTP `shop.microsynth.com:22`, webshop login; password in the OS keyring) and extracts their `.ab1` files flat into `ab1_scan_path` (no subfolders; newest file wins on name clashes) (already-extracted archives tracked in `.microsynth_sync.json`) before each periodic scan (`Message::SyncMicrosynth` → `ScanAb1Directory`).

Reference FASTA sequences (`res/sequences/myco_*.fasta`, gitignored, re-downloaded only when missing or empty) are assembled **at build time** by `build.rs` from three sources:
- NCBI bulk `type_material` fetches per gene (`fetch_myco_sequences`).
- Single-gene NCBI ESearch/EFetch fetches driven by `res/sequences/sequences.toml` (`[[genome]]`/`[[append]]` entries, via `locus_tag` or explicit `seq_start`/`seq_stop` coordinates).
- The vendored [`pathogen-profiler/ntm-db`](https://github.com/pathogen-profiler/ntm-db) git submodule at `res/sequences/ntm-db`, whose per-species `db/<Genus>_<species>/{genome.fasta,genome.gff}` pairs are parsed (`parse_gff`/`gff_feature_matches`, walked by `build.rs::extract_species_gff_sequences()`) and matched genes appended into the pooled FASTAs.

Additionally, `res/sequences/references/` holds committed amplicon-level references generated by the [cosmic-seq](https://github.com/michaelmeuli/cosmic-seq) pipeline (headers `ACC|amplicon|N Genus species [...]`). One file per module is merged into the pooled references at runtime (hsp65, rpoB, rrs, rrs3end, rrl; see the `REF_AMPLICON_*` consts in `sequencing/mod.rs`). They are short, so they only help species identification: SNP calls still require the full-length ntm-db entries (accession contains `:`), whose absolute positions match `variants.csv`. Identity ties between short and long references go to the longer one (`sort_hits_by_identity`). For five *M. kansasii*-complex species (persicum, pseudokansasii, ostraviense, innocens, attenuatum), these amplicons are the **only** references; neither NCBI nor ntm-db has them. Reads from a primer set that isn't wired into `REF_AMPLICON_*` therefore can't be identified as those species.

Key types:
```rust
SeqData          // Full result for one AB1 file
Ab1Channels      // Raw chromatogram traces + basecalls + peak positions
SeqIdHit         // Species match with identity %, SNP calls, alignment
Erm41Position28  // C28 | T28 | G28 | A28 | Undetermined
```

### Conventions

- **`FxOrderMap<K, V>`** — type alias for `OrderMap` with `FxBuildHasher`; used throughout for ordered, fast maps.
- **`LazyLock` singletons** for widget IDs (e.g., `PERMANENT_DELETE_BUTTON_ID`).
- **`#[cfg(not(windows))]` / `#[cfg(windows)]`** gates throughout; platform-specific deps (`fork`, `uzers`, `procfs`) only on Unix.
- Async I/O uses **compio** (io_uring on Linux, IOCP on Windows), not tokio's fs.
- Localization via **Fluent** `.ftl` files in `i18n/`; language-aware sorting via ICU.
- `res/tb_ecoli_mapping.csv` maps TB gene mutations to *E. coli* coordinates.

## Testing Notes

`TESTING.md` contains a manual QA regression checklist. Unit tests exist in `tab.rs` and `mime_app.rs`. The `sequencing/` module has inline tests for alignment and resistance calls.

CI (`ci.yml`) runs tests with `--no-default-features`, default features, and `--all-features` on Ubuntu.
