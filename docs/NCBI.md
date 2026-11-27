# NCBI databases, type material and the references of this program

This page explains what the NCBI reference sequences of cosmic-files are, where they come from and
how far they can be trusted. For the module as a whole see [SEQUENCING.md](SEQUENCING.md); for the
preview panes see [PREVIEWS.md](PREVIEWS.md).

## 1. What this program does

cosmic-files is a fork of the COSMIC file manager that analyses the lab's mycobacterial Sanger
reads (`.ab1` files):

1. It reads the **file name** to get the lab number and the sequenced target.
2. It takes the basecalls from the file and trims low-quality ends (Q20).
3. It aligns the read against the **reference sequences** of that target.
4. It reports the closest species and, for some targets, predicted drug resistance, in a preview
   pane and in CSV and PDF reports.

The references are compiled into the program, so analysis needs no network. NCBI is contacted only
while the program is **built**.

A species call means "the reference most similar to this read". It can only be as good as the
references and their labels.

## 2. The NCBI databases

NCBI hosts many linked databases. The ones relevant to sequences:

| Database | Content | Used here |
|---|---|---|
| **Nucleotide** (`nuccore`) | DNA and RNA sequences: single genes, complete genomes, draft-genome contigs | yes |
| **SRA** (Sequence Read Archive) | Raw reads from high-throughput sequencing | no |
| **Trace Archive** | Older raw Sanger traces | no |
| **Assembly** / Datasets | Whole genome assemblies as units | no (cosmic-seq uses GTDB genomes) |
| **BioProject**, **BioSample** | Description of a study and of a biological sample | no |
| **Taxonomy** | Names, ranks and the tree used to label records | indirectly, through `[Organism]` and `type_material` |
| **Gene**, **Protein** | Gene summaries and protein sequences | no |

`build.rs` uses the E-utilities web interface: `esearch` finds records and `efetch` downloads them.
It addresses the Nucleotide database as `db=nucleotide` or `db=nuccore`; both mean the same
database.

### Record types in Nucleotide

| Type | Typical accession | Who is responsible | Notes |
|---|---|---|---|
| GenBank record | `MZ249501`, `KP676142` | The submitter | Often one gene from a PCR product. Mirrored with ENA and DDBJ (INSDC). |
| Complete genome | `CP000325`, `CU458896` | The submitter | Finished chromosome. |
| WGS contig or scaffold | `JASPGN010000025` | The submitter | A piece of a draft genome. |
| RefSeq targeted | `NR_102995` (rRNA), `NG_041982` | NCBI | Selected records, derived from INSDC data. |
| RefSeq genome | `NC_000962`, `NZ_JRMF01000040` | NCBI | Reference copy of a genome or contig, reannotated. |

### What "sequence quality" means here

- Nucleotide holds **consensus or assembled sequences**, not reads. A short GenBank rpoB or 16S
  entry may still rest on only one or two Sanger reads.
- No chromatogram comes with a record, so its base calls usually cannot be checked.
- Records can contain ambiguous bases, primer remnants or errors, mostly near the ends.
- GenBank content is changed by its submitter, not corrected by NCBI. Some deflines start with
  `UNVERIFIED:`; the program strips that prefix, so such records are used like any other.
- Species names are the ones on the record. Both *Mycobacterium* and the 2018 split genera
  (*Mycobacteroides*, *Mycolicibacterium*, …) occur.

## 3. Type material

### The concept

A bacterial species name is tied to a **type strain**: one deposited culture that defines the name.
If two organisms are to be called *M. kansasii*, the question is whether they belong with the *M.
kansasii* type strain. Type strains are kept in culture collections under several numbers (ATCC,
DSM, CIP, CCUG, JCM, NCTC); a superscript T marks them, for example CIP 108541<sup>T</sup>.

**Type material** is the broader term for any material that anchors a name: type strains and other
kinds of types, including those of subspecies.

### In NCBI

NCBI Taxonomy keeps lists of type material for names. Sequence records from such material are
marked, and `type_material[Filter]` restricts a search to them.

### What the filter gives and does not give

| It helps with | It does not guarantee |
|---|---|
| The species label: the sequence should come from the strain that defines the name | Good sequence quality |
| Avoiding misidentified clinical or environmental isolates | That every species is present: the type strain may have no record for this gene, or the record may not be marked |
| A smaller, less redundant reference set | Within-species diversity: a clinical isolate may differ from the type strain |
| | Stability: names are reclassified and sets change |

A GTDB species representative (used by the [GTDB references](SEQUENCING.md#2-reference-sources)) is
a different thing: a genome chosen to represent a genome-based species cluster. It is not
necessarily from the type strain, and GTDB has species without a validly published name
(`Mycobacterium sp022600695`).

## 4. How the NCBI references are fetched

### Step 1: bulk queries

[build.rs](../build.rs), `fetch_myco_sequences`:

| File | Gene term | Length (bp) | Type material only |
|---|---|---|---|
| `myco_erm41.fasta` | `erm(41)[Gene Name]` | 400–3000 | **no** |
| `myco_rpob.fasta` | `rpoB[Gene Name]` | 400–4500 | yes |
| `myco_rrs.fasta` | `16S[Title] OR rrs[Gene Name]` | 1200–3500 | yes |
| `myco_rrl.fasta` | `23S ribosomal RNA[Title] OR rrl[Gene Name]` | 1200–3500 | yes |

All four are limited to `Mycobacteriales[Organism]`. That order also contains *Corynebacterium*,
*Nocardia*, *Rhodococcus* and others, so many references are not mycobacteria.

`[Gene Name]` and `[Title]` search what the record's annotation says. A record with a missing or
differently written annotation is not found.

`SLEN` limits the length of the whole record. Complete genomes are excluded, but **short WGS
contigs pass**, and are downloaded whole, including the sequence around the gene.

`myco_erm41.fasta` is generated but **not used** by the program. erm(41) reads are compared with
three fixed references (step 2).

### Step 2: single entries

`res/sequences/sequences.toml` names records to fetch by accession, locus tag or coordinates: the
erm(41) references of *M. abscessus* subsp. *abscessus* and *bolletii*, the pncA references, the
H37Rv rpoB reference, and two 16S entries appended to `myco_rrs.fasta`. The *massiliense* erm(41)
reference was made by hand.

### Step 3: ntm-db

Genes are cut out of the genomes of the [ntm-db](https://github.com/pathogen-profiler/ntm-db)
submodule and appended to the pooled files. Their accessions contain `:`. Resistance positions for
rrs and rrl are called only on these entries.

### Contents on one machine (2026-11-27)

Classified by accession and header, so approximate for the GenBank group.

| File | Records | Length (bp) | WGS contigs or scaffolds |
|---|---|---|---|
| `myco_erm41.fasta` | 40 | 443–2948 | 17 |
| `myco_rpob.fasta` | 400 | 400–4405 | 9 |
| `myco_rrs.fasta` | 2204 | 1220–3104 | 2 |
| `myco_rrl.fasta` | 45 | 1484–3401 | 1 |

## 5. Pitfalls

- **Files are downloaded only when missing or empty.** Reference sets differ between machines
  depending on the download date, and a changed query has no effect until the file is deleted.
- **A failed bulk download can go unnoticed.** It only prints a build warning. Steps 2 and 3 then
  append to the file, so it is no longer empty and the bulk query is **not retried** at the next
  build. The rrs and rrl integrity checks look for ntm-db entries only, so they still pass. If a
  response stops early, the partial result is saved the same way. Check the record counts after a
  fresh build.
- **No download date or query is stored** with the files.
- `NCBI_API_KEY` must be set. It raises the request limit from 3 to 10 per second.
- The contact e-mail sent to NCBI is fixed in `build.rs`.

## 6. Checking or refreshing the references

1. Delete the `res/sequences/myco_*.fasta` file to refresh.
2. Rebuild and read the `fetch_myco` warnings.
3. Compare the number of `>` lines with the previous file.
4. Run `cargo test -- sequencing`.

To try a query first, paste it into the search field of
<https://www.ncbi.nlm.nih.gov/nuccore>. Adding `NOT wgs[Filter]` is a candidate for excluding
draft-genome contigs. It has not been tested here, and it could remove species whose only
type-strain sequence is in a draft genome.
