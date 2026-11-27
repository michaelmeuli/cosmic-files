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
- **`erm41.rs`** — erm(41) for *M. abscessus* macrolide resistance: position 28 (C/G/A28 = susceptible, T28 = inducible resistance) plus loss-of-function SNPs from ntm-db `variants.csv`, which override position 28 and give susceptible. *M. abscessus* subsp. *massiliense* is always susceptible. The combined verdict (erm41 → rrl → rrs → rrs3end → rrs_mtb → pncA → rpoB, first `Some` wins) comes from `batch::susceptibility_from_hits`, shared by the batch scan and the preview.
- **`rrl.rs`** — 23S rRNA macrolide resistance at *E. coli* positions 2058/2059 (wildtype A2058/A2059 = susceptible) plus ntm-db catalogue SNPs.
- **`rrs.rs`** — 16S rRNA species identification plus aminoglycoside-resistance SNPs from ntm-db `variants.csv`.
- **`rrs3end.rs`** — 16S rRNA 3′-end analysis: position 1248 discriminates *M. marinum* (A1248) from *M. ulcerans* (G1248); otherwise mirrors `rrs.rs`'s aminoglycoside resistance-SNP calling (kept separate via `rrs_snp_calls_3end`).
- **`rrs_mtb.rs`** — *M. tuberculosis* complex rrs (#289/#261, protocol 32.43613): WHO-catalogue calls at H37Rv 1401, 1402, 1403, 1483, 1484 (`res/sequences/rrs/rrs_h37rv.fasta`), stored in their own `rrs_mtb` calls (`RrsMtbSnpCall`, `rrs_mtb_snp_calls`). Resistant or undetermined only; a wild-type read deliberately gets no susceptible verdict. Bact-1098s/1525a reads stay in `rrs3end.rs`.
- **`rpob.rs`** — rpoB species identification, plus WHO-catalogue rifampicin calls for the Mtb regions: the read is aligned to the H37Rv rpoB CDS (`res/sequences/rpob/rpob_h37rv.fasta`) and every RRDR codon 426–452 (any missense = resistant), V170F/I491F and in-frame RRDR indels are called (`is_susceptible_rpob`; susceptible needs the full RRDR wildtype; non-*M. tuberculosis* species are called but flagged via `species_validated`). `RpoBRegion` (NTM 2573f/3337r, Mtb RRDR, Mtb 5′, Mtb Xpert) selects a region-specific reference pool; NTM keeps the `"rpoB"` gene label, the Mtb regions are labelled `"rpoB RRDR"`, `"rpoB 5'"`, `"rpoB Xpert"`.
- **`pnca.rs`** — pncA pyrazinamide resistance for *M. tuberculosis* complex; parses the WHO catalogue (`tbprofiler/mutations.csv`) at startup into per-position nucleotide/amino-acid maps (gene + 50 bp promoter flank) and calls every listed site (`is_susceptible_pnca` combines them into one verdict).
- **`hsp65.rs`** — hsp65/groEL2 species identification. The only references are the committed TB11/TB12 amplicons (`REF_AMPLICON_HSP65`). There are no SNP calls and no NCBI/ntm-db hsp65 FASTA.
- **`bed.rs`** — BED file format utilities.
- **`disk_cache.rs`** — SQLite (`rusqlite`, bundled) on-disk cache of analysed AB1 files, one row per canonical path checked against mtime, size and `ANALYSIS_VERSION`; batched upserts during a scan, pruning of unseen files under the scan dir. All caches store only hits with identity ≥ 98 % (`CACHE_MIN_IDENTITY`), at most 10 per source (`MAX_HITS_PER_SOURCE`, `retain_cacheable`). The record's species and calls come from the unfiltered hits. The preview's "Show alignments below 98% identity" button re-aligns (`analyse_ab1_all_hits`) without caching. See `sequencing/CACHE.md`.
- **`ab1_filename.rs`** — `parse_ab1_filename` → `(sample_id, Option<Ab1Gene>)`: the single source of AB1 filename → gene dispatch for both the batch scan and the preview pane. Rules follow kansasii-docs `SANGER_LABNUMBERS.md` / `SANGER_RPOB.md` and cosmic-seq `PRIMERS.md`; rpoB reads get an `RpoBRegion` (MAB, marinum and other-genus rpoB reads get `None`).
- **`microsynth.rs`** (feature `russh`) — Downloads per-order `.zip` archives from Microsynth's secure download area (SFTP `shop.microsynth.com:22`, webshop login; password in the OS keyring) and extracts their `.ab1` files flat into `ab1_scan_path` (no subfolders; newest file wins on name clashes) (already-extracted archives tracked in `.microsynth_sync.json`) before each periodic scan (`Message::SyncMicrosynth` → `ScanAb1Directory`).

- **`kansasii_align_pdf.rs`** / **`email_notify.rs`** (`email_notify` needs feature `russh`) — the "new Microsynth files" mail. `sync_ab1` returns the `.ab1` files it wrote (`SyncSummary::new_files`); `MicrosynthSyncComplete` stores them in `App::pending_new_ab1`, and the next `Ab1ScanComplete` calls `App::report_new_files`: `build_new_files_report_pdf` (only those records, no age filter) plus `build_kansasii_alignment_pdf` (port of sanger-microsynth `refalign.py::write_pdf`, built from each record's GTDB `seq_id_hits` for the *M. kansasii* complex species) are saved next to the PDF report and emailed over SMTP (`TBConfig::smtp_*` / `email_*`; password in the keyring). Nothing is sent when the sync wrote no files or SMTP is unconfigured.

Reference FASTA sequences (`res/sequences/myco_*.fasta`, gitignored, re-downloaded only when missing or empty) are assembled **at build time** by `build.rs` from three sources:
- NCBI bulk `type_material` fetches per gene (`fetch_myco_sequences`).
- Single-gene NCBI ESearch/EFetch fetches driven by `res/sequences/sequences.toml` (`[[genome]]`/`[[append]]` entries, via `locus_tag` or explicit `seq_start`/`seq_stop` coordinates).
- The vendored [`pathogen-profiler/ntm-db`](https://github.com/pathogen-profiler/ntm-db) git submodule at `res/sequences/ntm-db`, whose per-species `db/<Genus>_<species>/{genome.fasta,genome.gff}` pairs are parsed (`parse_gff`/`gff_feature_matches`, walked by `build.rs::extract_species_gff_sequences()`) and matched genes appended into the pooled FASTAs.

Additionally, `res/sequences/references/` holds committed amplicon-level references generated by the [cosmic-seq](https://github.com/michaelmeuli/cosmic-seq) pipeline (headers `ACC|amplicon|N Genus species [...]`). At runtime one file per module is added to the reference pool as a separate **GTDB** source (`RefSource::Gtdb`, built by `ref_pool`), next to the **NCBI** source (`myco_*.fasta`, which includes ntm-db). Modules: rpoB, rrs, rrs3end, rrl; for hsp65 and the Mtb rpoB regions the GTDB amplicons are the only references. See the `REF_AMPLICON_*` consts in `sequencing/mod.rs`. The two sources are kept apart end to end:
- deduplication and per-source top-N truncation (`truncate_per_source`);
- species/identity in the record, CSV and PDF (`species`/`identity` = NCBI, `species_gtdb`/`identity_gtdb`);
- separate sections in the preview.

The amplicons are short, so they only help species identification: SNP calls still require the full-length ntm-db entries (accession contains `:`), whose absolute positions match `variants.csv`. `best_snp_hit` therefore anchors on the best NCBI species. Identity ties between short and long references go to the longer one (`sort_hits_by_identity`). For five *M. kansasii*-complex species (persicum, pseudokansasii, ostraviense, innocens, attenuatum), these amplicons are the **only** references; neither NCBI nor ntm-db has them. Reads from a primer set that isn't wired into `REF_AMPLICON_*` therefore can't be identified as those species.

`res/sequences/references/` is synced from the cosmic-seq export bundle by hand, never by a build step (`build.rs` does not touch it): `uv run --no-project python scripts/sync_cosmic_seq.py --dry-run --remote mimeul@cluster.s3it.uzh.ch:/shares/sander.imm.uzh/MM/kansasii/output/cosmic-seq/results/cosmic_files`, then the same without `--dry-run` (or `--from <dir>` for a local copy); never copy files by hand. The bundle includes `species_groups.tsv` (species → complex label; NCBI species groups, the chelonae-abscessus complex as NCBI genus *Mycobacteroides* (taxid 670516), and the curated kansasii complex; NCBI subspecies are also listed under their former species names, e.g. *M. intracellulare* subsp. *chimaera* as "Mycobacterium chimaera", since old deflines use those), which `species_from_16s_hits` uses to name 16S calls by their complex (`species_group` in `mod.rs`). The table uses GTDB's genus *Mycobacterium*; the lookup (`canonical_binomial`) maps NCBI's split genera (`MYCOBACTERIUM_SYNONYMS`: Mycobacteroides, Mycolicibacterium, …) and bracketed `[Mycobacterium]` to it, so either spelling matches. Displayed species names stay as each reference writes them (`item/metadata.rs` compares exact "Mycobacteroides abscessus subsp. …" descriptions). Groups are edited in cosmic-seq (`species_groups.tsv` at its repo root), not here. Bump `ANALYSIS_VERSION` when the calls change.

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
