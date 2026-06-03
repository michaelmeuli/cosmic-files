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

- **`mod.rs`** — AB1 chromatogram parsing, Phred-quality trimming, k-mer seeding alignment (word size 11, FNV-1a hashing), pairwise alignment formatting, FASTA database lookup.
- **`tb_data.rs`** — Deserializes TBProfiler JSON output (`*.results.json`); confidence ranking (strongest: "Assoc w R" → weakest: "Not assoc w R").
- **`erm41.rs`** — erm(41) loss-of-function calls for *M. abscessus* macrolide resistance (13 LOF positions; C28 = susceptible, T28 = inducible resistance).
- **`rrl.rs`** — 23S rRNA macrolide resistance at positions 2057–2058 (wildtype A2057/A2058 = susceptible).
- **`rrs.rs`** — 16S rRNA species identification.
- **`hsp65.rs`** — hsp65/groEL2 SNP calls for *M. kansasii/gastri* and *M. marinum/ulcerans* discrimination.
- **`bed.rs`** — BED file format utilities.

Reference FASTA sequences are fetched from NCBI **at build time** (`build.rs` using ESearch/EFetch API) and embedded in the binary. The sequence database config lives in `res/sequences.toml`.

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
