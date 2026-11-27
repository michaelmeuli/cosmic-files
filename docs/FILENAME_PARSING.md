# AB1 file name parsing

An AB1 file's name decides which sample the read belongs to and which analysis it gets. Both
come from one function, `parse_ab1_filename` in
[`src/sequencing/ab1_filename.rs`](../src/sequencing/ab1_filename.rs). The batch scan, the disk
caches and the preview pane all use it, so they cannot disagree about a file's gene.

This document describes the parser, the types it produces and where they are used afterwards.
The naming conventions behind the rules are described in kansasii-docs
[`SANGER_LABNUMBERS.md`](https://github.com/michaelmeuli/kansasii-docs/blob/master/docs/SANGER_LABNUMBERS.md)
and [`SANGER_RPOB.md`](https://github.com/michaelmeuli/kansasii-docs/blob/master/docs/SANGER_RPOB.md),
and primer names in cosmic-seq
[`PRIMERS.md`](https://github.com/michaelmeuli/cosmic-seq/blob/master/docs/PRIMERS.md).

## Overview

```text
file name
   │  parse_ab1_filename
   ▼
(sample_id: String, gene: Option<Ab1Gene>)
   │
   ├─ batch::align_ab1 ──────► identify_sequence_* ──► Vec<SeqIdHit>
   │      └─ analyse_ab1_file ──► SampleSusceptibilityRecord
   │                                 ├─ SQLite disk cache
   │                                 ├─ CSV reports and PDF reports
   │                                 └─ new-files e-mail (alignment PDF)
   │
   └─ Item::ab1_gene / sibling_16s_hits ──► preview pane
```

The tuple itself is never stored. The preview re-parses the name each time it needs it, and the
scan copies the two values into a `SampleSusceptibilityRecord`.

## Parsing

A typical name is

```text
<lab number><sep><marker/primer part>[_<run date>_<time>_<well>].ab1
```

for example `2014500121_clr_mclr_21r_2014-08-04_12-04-17_H05.ab1` or
`2025500747 rpoB_rpoB-2573f.ab1`.

`parse_ab1_filename(name)` works in four steps:

1. Take the file stem (the name without its last extension).
2. `find_lab_number`: locate the lab number and the byte range it occupies.
3. `marker_part`: reduce the stem to the lowercase marker/primer text.
4. `gene_from_marker`: match keywords in that text.

It never fails. An unrecognized name gives `gene = None`, and a name without a lab number gives
the whole stem as `sample_id`.

### Step 2: lab number

The forms are tried in this order, each over the whole stem. A digit run counts only if it is
not part of a longer run of digits.

| Form in the name | Example | `sample_id` |
|---|---|---|
| 10 digits starting with `20` | `2014500121` | `2014500121` |
| `YYYY_NNNNNN` or `YYYY NNNNNN`, year starting with `20` | `2010_500249` | `2010500249` |
| `NNNNNN-YY` | `176104-08` | `2008176104` |
| none of the above | `12345`, `176797_12w_hsp65_…` | the whole stem |

Six-digit numbers without a year are not unique across years, so they are not treated as lab
numbers. The same holds for malformed numbers such as the 9-digit `202300268`.

### Step 3: marker part

`marker_part` prepares the text that the gene rules see:

- lowercases it (ASCII only, which keeps byte offsets valid);
- replaces the lab number with a space;
- cuts everything from the first `_YYYY-MM-DD` or ` YYYY-MM-DD` onwards (the run date, time and
  well);
- replaces `_peaktraced` with a space.

This keeps digits of the lab number or run date from triggering a rule. For example, the `81`
in `2026338109` is not read as the rpoB 81 bp marker.

### Step 4: gene

`gene_from_marker` uses two views of the marker text besides the text itself:

- **tokens**: split on `_`, space and `.`, with `- ( ) # ` '` removed from each token
  (`rpoB-2573f` → `rpob2573f`, `TB-12w` → `tb12w`);
- **compact**: all ASCII alphanumerics joined together.

The rules are checked in this order and the first match wins.

| # | Matches | Result |
|---|---|---|
| 1 | token `erm`, `erm41…`, `ermprom…`, or `erm` + `f`/`r` + at most two more characters | `Erm41` |
| 2 | compact contains `hsp65` or `65kda`, or a token starts with `tb11` / `tb12` | `Hsp65` |
| 3 | text contains `rpo`, `81bp`, `81 bp`, `tb176` (no digit after), or `tr` + optional space + digit | rpoB, see below |
| 4 | token starts with `mbak` | `Rrs16S` |
| 5 | compact contains `1098s` or `1525a` | `Rrs3End` |
| 6 | `#289` / `#261`, or an `rrs…` token plus a standalone `289` / `261` | `RrsMtb` |
| 7 | any other `rrs…` token | `Rrs3End` |
| 8 | token starts with `sp1` / `sp2`, not followed by a further digit | `RrlMtb` |
| 9 | token starts with `rrl`, `mclr` or `mcrl`, or equals `clr` | `Rrl` |
| 10 | token starts with `pnca` | `PncA` |
| – | nothing matched | `None` |

Two points about the order:

- `RrlMtb` is checked before `Rrl` because Mtb 23S names often contain `rrl` too.
- A bare `23S` matches nothing. In the routine archive it occurs only on non-mycobacterial
  reads (for example *H. pylori*).

### rpoB regions

A name selected by rule 3 is decided by `rpob_region` and never falls through to later rules,
even when the result is `None`. Again, the first match wins.

| Order | Marker text | Result |
|---|---|---|
| 1 | `strep`, `univ` or `grpob` (other genus) | `None` |
| 2 | `mab` or `marinum` (amplicons without references) | `None` |
| 3 | `tb176` | `RpoB(Mtb5Prime)` |
| 4 | `genexpert`, or `rpob-?[fr]` + exactly one digit | `RpoB(MtbXpert)` |
| 5 | standalone `81`, `tr` + digit, `core`, `mut` or `rpobc` | `RpoB(MtbRrdr)` |
| 6 | anything else | `RpoB(Ntm)` |

Known limitation: a bare `rpoB-R` from the August 2018 GeneXpert runs is the Xpert reverse
primer but is classified as NTM. Telling them apart would need the folder name.

## Types produced

### `Ab1Gene`

Defined in `ab1_filename.rs`. `label()` gives the string stored in records, caches and exports.

| Variant | `label()` | Analysis function |
|---|---|---|
| `Erm41` | `erm(41)` | `identify_sequence_erm41` |
| `Hsp65` | `hsp65` | `identify_sequence_hsp65` |
| `RpoB(Ntm)` | `rpoB` | `identify_sequence_rpob` |
| `RpoB(MtbRrdr)` | `rpoB RRDR` | `identify_sequence_rpob` |
| `RpoB(Mtb5Prime)` | `rpoB 5'` | `identify_sequence_rpob` |
| `RpoB(MtbXpert)` | `rpoB Xpert` | `identify_sequence_rpob` |
| `Rrs16S` | `16S` | `identify_sequence_16s` |
| `Rrs3End` | `16S 3'-End` | `identify_sequence_16s3end` |
| `RrsMtb` | `rrs Mtb` | `identify_sequence_rrs_mtb` |
| `Rrl` | `rrl` | `identify_sequence_rrl_ntm` |
| `RrlMtb` | `rrl Mtb` | `identify_sequence_rrl_mtb` |
| `PncA` | `pncA` | `identify_sequence_pnca` |

### `RpoBRegion`

Defined in [`rpob.rs`](../src/sequencing/rpob.rs) and re-exported by the parser module. It is
carried inside `Ab1Gene::RpoB` and used for:

- the reference pool the read is aligned against;
- `label()`, the gene string;
- `protocol()`, the heading of the preview pane;
- `is_mtb()`, which decides whether the preview shows the rifampicin calls.

### `SampleSusceptibilityRecord`

Defined in [`batch.rs`](../src/sequencing/batch.rs), one per file. `analyse_ab1_file` builds it.
These fields come from, or depend on, the file name:

| Field | Source |
|---|---|
| `sample_id` | parser |
| `gene` | `Ab1Gene::label()` as `Option<String>`, not the enum |
| `file_name` | the name that was parsed |
| `species`, `species_gtdb` | naming rule chosen by gene (`species_call`) |
| `identity`, `identity_gtdb`, `seq_id_hits` | alignment against the gene's references |
| `susceptibility_calls`, `is_susceptible` | derived from those hits |

The remaining fields (`file_path`, `file_created`, `analysis_version`) do not depend on the
name.

## Later use

### Alignment

`batch::align_ab1` parses the name, reads the file, quality-trims the sequence (Q20) and calls
the analysis function for the gene. With `gene = None` there is no alignment and the hit list is
empty. The record is still created.

`species_call` then picks the species naming rule:

| Gene | Rule |
|---|---|
| `Rrs16S` | species-group (complex) label, tied hits merged |
| `Rrs3End` | named only for *M. marinum* / *M. ulcerans*, otherwise an empty string |
| `RpoB(_)` | description of the top hit |
| all others, and `None` | description of the top hit |

`susceptibility_from_hits` does not receive the gene. It takes the first per-gene verdict that
exists in the hits.

### Caches

| Cache | Key | Role of the parsed values |
|---|---|---|
| `AB1_SEQ_CACHE` (memory) | canonical path | none |
| `SIXTEEN_S_HITS_CACHE` (memory) | `sample_id` | filled only by `Rrs16S` reads that have hits |
| SQLite scan and preview caches | canonical path | stores the whole record |

A disk-cached record is reused only if `cached_record_current` accepts it: its
`analysis_version` equals `ANALYSIS_VERSION`, and its `gene` equals the label the **current**
parser gives for its `file_name`. See [`CACHE.md`](../src/sequencing/CACHE.md) for the mtime and
size checks.

### Reports

`scan_ab1_directory` returns the records sorted by `sample_id`, highest first. This is a string
sort, so files without a lab number are ordered by their stem.

| Output | Function | Selection | Uses |
|---|---|---|---|
| Susceptibility CSV | `write_ab1_csv` | known gene, identity threshold, report age | `file_name`, `sample_id`, `gene` columns |
| Rare mutations CSV | `write_rare_mutations_csv` | as above, plus a flagged mutation | same |
| PDF report | `build_report_pdf` | same filter as the susceptibility CSV | Sample ID, Gene, Filename columns |
| New-files PDF | `build_new_files_report_pdf` | known gene and identity threshold | same |
| *M. kansasii* complex alignment PDF | `build_kansasii_alignment_pdf` | records with GTDB hits in the complex | `sample_id` labels the read |

For the new-files e-mail, `App::report_new_files` ([`app.rs`](../src/app.rs)) selects records
whose `file_name` matches a file that the Microsynth sync wrote. The match is on the name only,
not the full path.

### Preview pane

The preview does not read the record's `gene` string. `Item::ab1_gene`
([`item/sequencing.rs`](../src/item/sequencing.rs)) parses the item's name again, but only for
local files with the `.ab1` extension (any case). The predicates `is_erm41`, `is_hsp65`,
`rpob_region`, `is_16s`, `is_16s3end`, `is_rrl_ntm`, `is_rrl_mtb`, `is_rrs_mtb` and `is_pnca`
are built on it, and `app.rs` uses them to choose the `preview_*` function for the selected
item.

All other items get no gene preview, whatever their name. This includes folders and remote
(SFTP) and trashed `.ab1` files.

### Linking reads of one sample

`sample_id` is what connects the reads of a sample. `Item::sibling_16s_hits` finds the 16S read
for the file being previewed:

1. the first AB1 file in the current listing that parses to `Rrs16S` with the same
   `sample_id` and has hits;
2. if the listing has no such file, `SIXTEEN_S_HITS_CACHE`, which also covers other
   directories.

Its result feeds the 16S species lines in other genes' previews and the combined calls
`is_chelonae`, `is_marinum` and `is_ulcerans`.

Consequences:

- A file without a lab number has its stem as `sample_id`, so it is not linked to reads with
  other names.
- If a sample has several 16S reads with hits, the cache keeps whichever was inserted last.
  A read that loses all its hits on re-analysis leaves the earlier entry in place until
  restart.

## Changing the parser

1. Edit the rules in `ab1_filename.rs`. Check the rule order, since an earlier rule hides a
   later one.
2. Add real file names to the tests in that file (`routine_corpus` holds names from the routine
   archive) and run `cargo test -p cosmic-files -- ab1_filename`.
3. Consider the disk caches. A changed **gene label** invalidates a cached record
   automatically. A change that only affects **`sample_id`** does not, so bump
   `ANALYSIS_VERSION` in `batch.rs`.
4. For a new gene, add the `Ab1Gene` variant and its `label()`, the arm in `align_ab1`, the
   `species_call` rule if needed, the `Item` predicate and the preview branch in `app.rs`.

## FASTQ file names (TB Profiler)

FASTQ pairs are parsed separately and do not use the types above. The configured suffixes
`pair1_suffix` and `pair2_suffix` are stripped from each selected name, and what remains is the
sample name.

- `is_valid_fastq_selection` ([`menu.rs`](../src/menu.rs)) accepts a selection only if every
  name ends in one of the suffixes and every sample has both reads.
- `run_tbprofiler` ([`russh/client.rs`](../src/russh/client.rs)) builds the same map of sample
  name to read numbers, requires all files to be in one directory, and passes the sample names,
  comma-separated, to the cluster job.
