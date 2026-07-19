# M. kansasii complex reference genomes

Hand-curated reference genomes + annotation for the seven species of the *Mycobacterium
kansasii* complex (MKC), added to support species-level differentiation beyond the
kansasii/gastri binary that `src/sequencing/hsp65.rs` currently supports:

- *M. kansasii*, *M. gastri*, *M. persicum*, *M. pseudokansasii*, *M. ostraviense*,
  *M. innocens*, *M. attenuatum*

Species boundaries and type-strain designations follow Tagini et al. 2019
(doi:10.1099/ijsem.0.003378) and Jagielski et al. 2020
(doi:10.3389/fmicb.2019.02918, *"Genomic Insights Into the Mycobacterium kansasii Complex: An
Update"*).

## Layout

This directory mirrors the per-species layout used by the vendored
[`pathogen-profiler/ntm-db`](https://github.com/pathogen-profiler/ntm-db) submodule at
`res/sequences/ntm-db/db/` (`<Genus>_<species>/{genome.fasta,genome.gff}`), so that
`build.rs`'s `extract_species_gff_sequences()` can walk both directories with the same code,
and so these species directories can eventually be copied wholesale into a fork of ntm-db for
an upstream pull request. Unlike `ntm-db/`, this directory is **not** a git submodule — it's
committed directly, the same way `res/sequences/pnca/` and `res/sequences/erm41/` are.

Only `genome.fasta` (RefSeq/GenBank `_genomic.fna`) and `genome.gff` (RefSeq/GenBank
`_genomic.gff`) are included per species — no `variants.csv`/`barcode.bed`/etc., since there is
no resistance catalogue for this complex (the source literature is about taxonomy, not drug
resistance).

## Type strains used

All seven are RefSeq-annotated (PGAP), type-material assemblies from NCBI:

| Species | Type strain | RefSeq accession | WGS/assembly name |
|---|---|---|---|
| *M. kansasii* | ATCC 12478ᵀ | GCF_000157895.3 | ASM15789v2 |
| *M. gastri* | DSM 43505ᵀ | GCF_002102175.1 | ASM210217v1 |
| *M. persicum* | AFPC-000227ᵀ | GCF_002086675.1 | ASM208667v1 |
| *M. pseudokansasii* | MK142ᵀ | GCF_900566075.1 | MK142 |
| *M. ostraviense* | 241/15ᵀ (DSM 110538) | GCF_002705925.1 | ASM270592v1 |
| *M. innocens* | MK13ᵀ | GCF_900566055.1 | LAUMK13 |
| *M. attenuatum* | MK41ᵀ | GCF_900566085.1 | LAUMK41 |

Downloaded from `https://ftp.ncbi.nlm.nih.gov/genomes/all/GCF/.../<accession>_<name>_genomic.{fna,gff}.gz`.

## hsp65/groEL2 note

Every species here carries two GroEL paralogs annotated identically by PGAP as `gene=groL` /
`product=chaperonin GroEL`: groEL1 (co-transcribed in an operon immediately next to groES) and
groEL2 (a.k.a. "hsp65", standalone elsewhere in the genome — the one used diagnostically for
mycobacterial species ID). `build.rs`'s `is_hsp65_paralog2()` disambiguates them by proximity to
a `groES` gene on the same contig; it isn't a locus_tag or gene-name distinction PGAP makes
explicitly.
