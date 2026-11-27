# Sequencing constants

The thresholds, sequences, names and other fixed values used by `src/sequencing/`, and what
changes when you edit them.

For how the module works, see [SEQUENCING_INTERNALS.md](SEQUENCING_INTERNALS.md). For the
reference databases and previews, see [SEQUENCING.md](SEQUENCING.md).

Identity values are percentages (0–100) unless stated otherwise. Constants defined only in
tests are not listed. Values written inline in the code, without a name, are marked *(literal)*.

## 1. Before you change a value

Cached results are not recomputed just because the code changed. Bump `ANALYSIS_VERSION`
([batch.rs](../src/sequencing/batch.rs), currently **14**) whenever an edit changes hits, species
or calls: quality or alignment thresholds, anchors, primers, reference files, species groups,
tie handling or verdict rules. A disk-cached record with another version is re-analysed. Add a
line for the new version to the history in the constant's doc comment.

## 2. Read trimming and alignment

| Name | Value | Defined in | Meaning |
|---|---|---|---|
| *(literal)* minimum quality | Phred 20 | [batch.rs](../src/sequencing/batch.rs), [item/sequencing.rs](../src/item/sequencing.rs) | `min_q` passed to `trim_to_min_quality`. Written in both places: change them together. If no window passes, the analysis uses the untrimmed read. |
| `WINDOW` | 15 bases | `trim_to_min_quality` in [mod.rs](../src/sequencing/mod.rs) | Sliding window for quality trimming. Shorter reads are scanned base by base. |
| *(literal)* match / mismatch | +1 / −1 | `align_to_ref` in [mod.rs](../src/sequencing/mod.rs) | Alignment score, case-insensitive. |
| *(literal)* gap open / extend | −5 / −1 | `align_to_ref` | Gap penalties of the semiglobal alignment. |
| `ALIGN_TRIM_WINDOW` | 15 columns | [mod.rs](../src/sequencing/mod.rs) | Sliding window of `trim_alignment_ends`. |
| `ALIGN_TRIM_MIN_IDENTITY` | 70 | [mod.rs](../src/sequencing/mod.rs) | Minimum match rate of a window at an alignment end. With 15 columns the threshold rounds to 11 matches. Deliberately looser than `MIN_SEQ_ID_IDENTITY`. |

## 3. Identity thresholds and hit limits

| Name | Value | Defined in | Meaning |
|---|---|---|---|
| `MIN_SEQ_ID_IDENTITY` | 80 | [mod.rs](../src/sequencing/mod.rs) | Reportability limit for the CSV and PDF reports; the preview panes use it too. |
| `CACHE_MIN_IDENTITY` | 98 | [mod.rs](../src/sequencing/mod.rs) | Minimum identity of a hit stored in any AB1 cache. Lower hits are re-aligned on request and never cached. Species and calls of a record come from the unfiltered hits. |
| `MAX_HITS_PER_SOURCE` | 10 | [mod.rs](../src/sequencing/mod.rs) | Hits kept per reference source (NCBI, GTDB). |
| `TIE_IDENTITY` | 0.1 | [batch.rs](../src/sequencing/batch.rs) | Hits within this many percentage points of the best 16S hit are reported together. |
| `MIN_H37RV_IDENTITY` | 80 | [rpob.rs](../src/sequencing/rpob.rs) | Minimum identity to the H37Rv rpoB CDS for any rifampicin call. NTM reads align at about 85–92 % and are still called, flagged by `species_validated`. Independent of `MIN_SEQ_ID_IDENTITY`, although both are 80. |
| `MIN_RPOB_REF_LEN` | 400 bp | [mod.rs](../src/sequencing/mod.rs) | Minimum length of NTM-region rpoB references. Not applied to the Mtb regions, whose amplicons are shorter by design. |
| `MIN_PNCA_REF_LEN` | 500 bp | [mod.rs](../src/sequencing/mod.rs) | Minimum length of pncA references. |

## 4. Primers and anchors

All matching is exact and case-insensitive: one mismatch in the read means no match.

### Primer trimming

If a primer is not found, that end of the read stays untrimmed. Both orientations are searched.

| Name | Sequence (5′→3′) | Defined in |
|---|---|---|
| `ERM41_FWD_START` | `gtgtccggccaacggtcgcg` | [mod.rs](../src/sequencing/mod.rs) |
| `ERM41_FWD_END` | `tggtgatcaggcggcgctga` | [mod.rs](../src/sequencing/mod.rs) |
| `PNCA_FWD_START` | `GCGTCGGTAGGCAAACTGCC` | [mod.rs](../src/sequencing/mod.rs) |
| `PNCA_FWD_END` | `AGTTGGTTTGCAGCTCCTGA` | [mod.rs](../src/sequencing/mod.rs) |
| `FWD_START` (hsp65) | `ATGGTGTGTCCATCGCCAAG`, `GAGGACCCGTACGAGAAGATCGGCGCTGA` | `trim_hsp65_primers` in [hsp65.rs](../src/sequencing/hsp65.rs) |
| `FWD_END` (hsp65) | `GAGCTCACCGAGGGTATGCG`, `CGCTGTCCACCCTGGTCGTC` | `trim_hsp65_primers` |

`FWD_START` and `FWD_END` name the two boundaries of the amplicon **in forward orientation**.
`FWD_END` is not a "forward primer".

### Anchors for position calls

The called bases sit between a left (`_L`) and a right (`_R`) anchor. A call needs **both**
anchors, directly adjacent to the called bases. If the read as given yields no call, its reverse
complement is tried.

| Call | Left anchor | Called | Right anchor |
|---|---|---|---|
| erm(41) position 28 (`ERM41_ANCHOR_L` / `_R`) | `GCCAACGGTCGCGACGCCAG` | 1 base | `GGGGCTGGTATCCGCTCACT` |
| rrl 2058/2059 (`RRL_ANCHOR_L` / `_R`) | `CGTTACGCGCGGCAGGACGA` | 2 bases | `AGACCCCGGGACCTTCACTA` |
| rrs 1248 (`RRS3END_ANCHOR_L` / `_R`) | `ACATGCTACAATGGCCGGT` | 1 base | `CAAAGGGCTGCGATGCCGCG` |

All anchors are defined in [mod.rs](../src/sequencing/mod.rs).

### Chromatogram display windows

Bases shown around the diagnostic position. These affect the view only, not the calls.

| Position | `LEFT` | `RIGHT` | Function |
|---|---|---|---|
| erm(41) 28 | 9 | 11 | `find_erm41_display_window` ([erm41.rs](../src/sequencing/erm41.rs)) |
| rrl 2058/2059 | 9 | 10 | `find_rrl_ntm_display_window` ([rrl.rs](../src/sequencing/rrl.rs)) |
| rrs 1248 | 10 | 10 | `find_16s3end_display_window` ([rrs3end.rs](../src/sequencing/rrs3end.rs)) |

## 5. Resistance calling

| Name | Value | Defined in | Meaning |
|---|---|---|---|
| `RRDR_CODONS` | 426–452 | [rpob.rs](../src/sequencing/rpob.rs) | Rifampicin resistance-determining region, H37Rv numbering (WHO catalogue v2). |
| `RRDR_NT` | `(426 − 1) × 3 ..= 452 × 3 − 1` | [rpob.rs](../src/sequencing/rpob.rs) | The same region as 0-based CDS indices (c.1276–c.1356). It repeats the codon numbers, so edit it together with `RRDR_CODONS`. |
| `RRDR_RULE_FALLBACK` | `"Assoc w R - Interim"` | [rpob.rs](../src/sequencing/rpob.rs) | Confidence used when neither catalogue rule row can be read. |
| `UPSTREAM_FLANK` | 50 bp | [pnca.rs](../src/sequencing/pnca.rs) | Promoter bases before the pncA start codon in the reference. **Must match** `upstream_flank` in [sequences.toml](../res/sequences/sequences.toml). |
| `AA3` | 20 three-letter codes | [pnca.rs](../src/sequencing/pnca.rs) | Amino acid codes of the catalogue's `p.` notation. |

### Confidence ranks

`confidence_rank` ([tb_data.rs](../src/sequencing/tb_data.rs)) turns a WHO catalogue label into a
number. Lower is stronger. The pncA and rpoB verdicts treat **rank < 2** *(literal)* as
resistance.

| Rank | Label |
|---|---|
| 0 | `Assoc w R` |
| 1 | `Assoc w R - Interim` |
| 2 | `Uncertain significance` |
| 3 | `Not assoc w R - Interim` |
| 4 | `Not assoc w R` |
| 5 | any other text |

## 6. Embedded reference data

All are `include_str!` constants: the file is compiled into the binary, so a changed file needs a
rebuild. Paths are relative to `res/sequences/`.

| Constant | File(s) | Source |
|---|---|---|
| `REF_MYCO_RRS` | `myco_rrs.fasta` | NCBI, assembled by `build.rs` |
| `REF_MYCO_RPOB` | `myco_rpob.fasta` | NCBI, assembled by `build.rs` |
| `REF_MYCO_RRL` | `myco_rrl.fasta` | NCBI, assembled by `build.rs` |
| `REF_ERM41_ABSCESSUS` | `erm41/erm41_abscessus_ATCC_19977.fasta` | single reference |
| `REF_ERM41_BOLLETII` | `erm41/erm41_bolletii_CIP_108541.fasta` | single reference |
| `REF_ERM41_MASSILENSE` | `erm41/erm41_massiliense_CCUG_48898.fasta` | single reference (the constant name is spelled with one "I") |
| `REF_PNCA` | `pnca/pnca_h37rv`, `pnca_bovis_AF2122_97`, `pnca_canettii_CIPT_140010059` (`.fasta`) | CDS + 50 bp promoter |
| `REF_RPOB_H37RV` | `rpob/rpob_h37rv.fasta` | H37Rv Rv0667 CDS (3519 bp), coordinate system for rifampicin calls |
| `REF_AMPLICON_HSP65` | `references/hsp65_TB11_TB12`, `hsp65_TB11_TB12w` (`.fasta`) | GTDB (cosmic-seq) |
| `REF_AMPLICON_RPOB` | `references/rpoB_2573f_3337r.fasta` | GTDB |
| `REF_AMPLICON_RPOB_RRDR` | `references/rpoB_TR1_TR2b.fasta` | GTDB |
| `REF_AMPLICON_RPOB_5PRIME` | `references/rpoB_Tb176f_Tb176r.fasta` | GTDB |
| `REF_AMPLICON_RPOB_XPERT` | `references/rpoB_Xpert_F1_R`, `_F2_R`, `_F2_R2` (`.fasta`) | GTDB |
| `REF_AMPLICON_RRS` | `references/16S_IMMF_IMMR2`, `16S_Mbak283f_Mbak259r`, `16S_Mbak283f_Mbak264r` (`.fasta`) | GTDB |
| `REF_AMPLICON_RRS_MTB` | `references/rrs_289_261.fasta` | GTDB |
| `REF_RRS_H37RV` | `rrs/rrs_h37rv.fasta` | NCBI, via `sequences.toml` |
| `REF_AMPLICON_RRS3END` | `references/16S_Bact1098s_Bact1525a.fasta` | GTDB |
| `REF_AMPLICON_RRL` | `references/23S_MCLR19F_MCLR21R.fasta` | GTDB |
| `REF_AMPLICON_RRL_MTB` | `references/23S_SP1F_SP2Rmod.fasta` | GTDB |
| `REF_RRL_H37RV` | `rrl/rrl_h37rv.fasta` | NCBI, via `sequences.toml` |
| `REF_SPECIES_GROUPS` | `references/species_groups.tsv` | species → complex label |

The `references/` folder is synced from cosmic-seq with `scripts/sync_cosmic_seq.py`; do not edit
or copy files there by hand. A file in that folder is used only if a `REF_*` constant embeds it.

The resistance catalogues (`res/sequences/ntm-db/db/<species>/variants.csv`,
`tbprofiler/mutations.csv`) and `res/tb_ecoli_mapping.csv` are embedded where they are parsed,
without a named constant.

## 7. Species names

| Name | Value | Defined in | Meaning |
|---|---|---|---|
| `DESC_ABSCESSUS` | `M. abscessus subsp. abscessus` | [mod.rs](../src/sequencing/mod.rs) | Description of erm(41) hits. |
| `DESC_BOLLETII` | `M. abscessus subsp. bolletii` | [mod.rs](../src/sequencing/mod.rs) | Same. |
| `DESC_MASSILIENSE` | `M. abscessus subsp. massiliense` | [mod.rs](../src/sequencing/mod.rs) | Same. A top hit with exactly this description is reported susceptible. |
| `MYCOBACTERIUM_SYNONYMS` | `Mycobacteroides`, `Mycolicibacterium`, `Mycolicibacter`, `Mycolicibacillus` | [mod.rs](../src/sequencing/mod.rs) | Genera read as *Mycobacterium* in the species-group lookup. Keep in sync with cosmic-seq `cosmic_seq/names.py`. |

The `DESC_*` strings are compared exactly, in the verdicts and in the preview code. Changing one
can silently change calls.

## 8. Caches and scanning

| Name | Value | Defined in | Meaning |
|---|---|---|---|
| `ANALYSIS_VERSION` | 14 | [batch.rs](../src/sequencing/batch.rs) | Version of the analysis stored with cached records (see §1). |
| `SCHEMA_VERSION` | 1 | [disk_cache.rs](../src/sequencing/disk_cache.rs) | SQLite table layout. A database with another `user_version` is recreated. |
| `BATCH_COMMIT_EVERY` | 20 | [disk_cache.rs](../src/sequencing/disk_cache.rs) | Upserts per transaction during a scan. |
| *(literal)* busy timeout | 5 s | [disk_cache.rs](../src/sequencing/disk_cache.rs) | How long SQLite waits for a lock. |
| `SYNCED_FOLDER_MARKERS` | `OneDrive`, `Dropbox`, `Google Drive`, `iCloud` | [disk_cache.rs](../src/sequencing/disk_cache.rs) | A cache path containing one of these logs a warning. |
| `SCAN_CACHE_FILE_NAME` | `ab1_scan_cache.sqlite` | [batch.rs](../src/sequencing/batch.rs) | Cache of the first scan directory. |
| `SCAN_CACHE_FILE_NAME_2` | `ab1_scan_cache_2.sqlite` | [batch.rs](../src/sequencing/batch.rs) | Cache of the second scan directory. |
| `PREVIEW_CACHE_FILE_NAME` | `ab1_preview_cache.sqlite` | [batch.rs](../src/sequencing/batch.rs) | Cache of files analysed for the preview. |
| *(literal)* scan threads | half the logical cores, 1–8 | `SCAN_POOL` in [batch.rs](../src/sequencing/batch.rs) | Alignment worker pool shared by both scans. |
| *(literal)* scan interval | 2 h | [app.rs](../src/app.rs) | Timer for each configured scan directory. |

## 9. Network and notification

| Name | Value | Defined in | Meaning |
|---|---|---|---|
| `HOST` | `shop.microsynth.com` | [microsynth.rs](../src/sequencing/microsynth.rs) | SFTP server. |
| `PORT` | 22 | [microsynth.rs](../src/sequencing/microsynth.rs) | SFTP port. |
| `MANIFEST_NAME` | `.microsynth_sync.json` | [microsynth.rs](../src/sequencing/microsynth.rs) | Records the archives already extracted. |
| `KEYRING_SERVICE` | `cosmic-files-microsynth` | [microsynth.rs](../src/sequencing/microsynth.rs) | Keyring entry of the webshop password. |
| `KEYRING_SERVICE` | `cosmic-files-smtp` | [email_notify.rs](../src/sequencing/email_notify.rs) | Keyring entry of the SMTP password. |
| `SMTPS_PORT` | 465 | [email_notify.rs](../src/sequencing/email_notify.rs) | This port uses implicit TLS; every other port uses STARTTLS. |

A bare ntfy topic name is sent to the public server `https://ntfy.sh`
([ntfy_notify.rs](../src/sequencing/ntfy_notify.rs)); a full URL selects another server.

Renaming a keyring service orphans the stored password, which then has to be entered again.

### Related configuration defaults

These are user settings (`TBConfig` in [config.rs](../src/config.rs)); the constants only set
their defaults.

| Name | Default | Meaning |
|---|---|---|
| `DEFAULT_REPORT_MAX_AGE_DAYS` | 60 | Default of `report_max_age_days` (`ab1_scan_path`) and `report_max_age_days_2` (`ab1_scan_path_2`), the age limits in days. |
| `DEFAULT_SMTP_PORT` | 587 | Default of `smtp_port`. |

A value of `0` means "no age limit" in the directory scan and the CSV, rare-mutation CSV and
PDF reports of that directory. `report_max_age_days` also limits the Microsynth download.

## 10. PDF layout

Millimetres unless stated. These affect appearance only, except the alignment-call thresholds.

### Susceptibility report ([mod.rs](../src/sequencing/mod.rs))

| Name | Value |
|---|---|
| `PDF_PAGE_W` × `PDF_PAGE_H` | 297 × 210 (A4 landscape) |
| `PDF_MARGIN_L` / `_T` / `_B` | 10 / 8 / 12 |
| `PDF_ROW_H` | 5.5 |
| `PDF_COL_X` | 0, 24, 39, 89, 139, 157, 217 (offsets from the left margin) |
| `PDF_TABLE_W` | 277 |
| `PDF_COL_HEADERS` | 7 column titles |

`PDF_COL_X` and `PDF_COL_HEADERS` must have the same number of entries.

### *M. kansasii* complex alignment ([kansasii_align_pdf.rs](../src/sequencing/kansasii_align_pdf.rs))

| Name | Value | Meaning |
|---|---|---|
| `COMPLEX` | `M. kansasii complex` | Species-group label whose reads get an alignment. Must match the label in `species_groups.tsv`. |
| `SPECIES_ORDER` | kansasii, persicum, pseudokansasii, attenuatum, innocens, ostraviense, gastri | Display order; other species follow alphabetically. |
| `MIN_IDENTITY` | 0.98 | A **fraction**, unlike the other identity constants. A best hit below it is `divergent`. |
| `MIN_MARGIN` | 2 | A next-best species with fewer than this many additional differences makes the call `ambiguous`. |
| `BLOCK` | 80 | Alignment columns per block. |
| `PAGE_W` × `PAGE_H`, `MARGIN` | 297 × 210, 10 | Page size and margin. |
| `FONT_PT` | 6.5 pt | Alignment font size. |
| `CHAR_W` | `FONT_PT × 0.6 × 0.352778` | Width of one Courier character. |
| `LINE_H` | 3.0 | Line height. |
| `LABEL_CHARS` | 36 | Width of the row-label column in characters. |

`MIN_IDENTITY` and `MIN_MARGIN` mirror `refalign.py::ReadResult` in sanger-microsynth.

## 11. Lazily parsed statics

`LazyLock` values built once, on first use, from the data above.

| Static | Content | Module |
|---|---|---|
| `SPECIES_GROUPS` | species → complex label | `mod.rs` |
| `HSP65_REFS`, `RRL_REFS`, `RRS_REFS` | reference pools (`RRS_REFS` exists separately in `rrs.rs` and `rrs3end.rs`) | gene modules |
| `RPOB_REFS_NTM`, `_RRDR`, `_5PRIME`, `_XPERT` | one rpoB pool per region | `rpob.rs` |
| `RPOB_H37RV`, `RPOB_RIF_SITES` | H37Rv CDS and rifampicin sites | `rpob.rs` |
| `ERM41_LOF_SNPS` | erm(41) loss-of-function variants | `erm41.rs` |
| `RRL_RESISTANCE_SNPS`, `RRS_RESISTANCE_SNPS` | ntm-db resistance variants | `rrl.rs`, `rrs.rs`, `rrs3end.rs` |
| `PNCA_RESISTANCE_SNPS` | pncA catalogue maps | `pnca.rs` |
| `TB_ECOLI_MAPPING` | TB → *E. coli* numbering | `tb_data.rs` |

`batch.rs` also holds run-time state in statics (`AB1_SEQ_CACHE`, `SIXTEEN_S_HITS_CACHE`,
`PREVIEW_DISK_CACHE`); these are caches rather than constants.
