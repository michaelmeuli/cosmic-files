# Review of the previews: file names, primers and amplicons

Do the preview panes make sense for the reads the lab produces? This page compares the file-name
parser and the reference pools with the cosmic-seq
[PRIMERS.md](https://github.com/michaelmeuli/cosmic-seq/blob/master/docs/PRIMERS.md) (generated
2026-11-24).

How the previews work is described in [SEQUENCING.md](SEQUENCING.md#3-previews).

**Basis (2026-11-27):** reading the source code and matching sequences in the local reference
files. The program was not run, and no real reads were analysed. "Seen in code" and "checked on
references" below say which applies.

## 1. Summary

The file-name dispatch fits the primer names well, and the species lists, rpoB regions, erm(41),
rrl positions and pncA are plausible. Findings 1 to 8 are fixed; finding 9 was
closed without a code change.

| # | Finding | Pane | Weight |
|---|---|---|---|
| 1 | "Position 1248 = A: *M. marinum*" appears for many other species | 16S 3′ end | **fixed** |
| 2 | Mtb rrs reads get no resistance call | 16S 3′ end | **fixed** |
| 3 | Mtb 23S reads get an NTM heading and a macrolide verdict only | rrl | **fixed** |
| 4 | 16S 5′ pane lists resistance positions its reads do not cover | 16S | **fixed** |
| 5 | A 3′-end amplicon is in the 5′ reference pool | 16S | **fixed** |
| 6 | Chromatogram text and *massiliense* exception look copied from erm(41) | 16S 3′ end | **fixed** |
| 7 | Protocol numbers in headings differ from PRIMERS.md | several | **fixed** |
| 8 | Routine hsp65 amplicon file is not used | hsp65 | **fixed** |
| 9 | Odd-length GTDB references in the 3′-end pool | 16S 3′ end | closed, no change |

## 2. Primers, file names and references

| PRIMERS.md assay | File name recognised as | GTDB references used | Assessment |
|---|---|---|---|
| Mbak283f / 264r / 259r / Mbak14 | 16S | Mbak283f_Mbak259r, Mbak283f_Mbak264r, IMMF_IMMR2 | Fits (finding 5 fixed) |
| IMM F / IMM R2 | **not recognised** from the primer name | IMMF_IMMR2 | No preview unless the name also has another keyword. These are amplification primers, so this may never matter. |
| Bact-1098s / 1525a | 16S 3′ end | Bact1098s_Bact1525a | Fits (finding 1 fixed; see finding 9) |
| #289 / #261 (Mtb rrs) | rrs Mtb (`#289`, `#261`, or `rrs…` with 289 / 261) | rrs_289_261 | Fixed (finding 2). A name with `289` but no `#` or `rrs` is not recognised. |
| rpoB-2573f / 3337r | rpoB, NTM | 2573f_3337r | Fits |
| TR1 / TR2b | rpoB RRDR | TR1_TR2b | Fits |
| Tb176-f / -r | rpoB 5′ | Tb176f_Tb176r | Fits |
| rpoB-F1 / F2 / R / R2 (Xpert) | rpoB Xpert; a bare `rpoB-R` counts as NTM | three Xpert files | Known limit, noted in the parser |
| TB-11 / TB-12w / TB-12 | hsp65 | TB11_TB12 and TB11_TB12w | Fits (finding 8 fixed) |
| MCLR 19F / 21R | rrl | MCLR19F_MCLR21R | Fits |
| SP1 F / SP2 R mod (Mtb) | rrl Mtb | SP1F_SP2Rmod | Fixed (finding 3) |
| erm41f2 / r2, erm41f / r | erm(41) | none; three NCBI references | Fits |
| erm(41) promoter | erm(41) | none | Only about 115 of the 400 bp are coding sequence. It includes position 28, but the promoter itself is not analysed. |
| CME-1Y / CME-2 (erm39) | none | none | Correctly excluded |
| pncA-Ber | pncA | none; three NCBI references | Fits |
| ITS, embB, ethA, ethR, inhA, katG, gyrA, thyA, rpsL, rplC, atpE, Rv0678, tlyA, ddn, eis, panD, gidB, rpsA, folC | none | not used | No analysis; the standard file preview appears. cosmic-seq already provides amplicon files for them. |

## 3. Findings

### 1. Position 1248 names a species without checking the species

**Fixed (2026-11-27):** the position heading and the call text in reports now give the base only.
The description below is of the earlier behaviour.

*Seen in code and checked on references.*

The 16S 3′-end pane prints "16S 3′-End position 1248 = A: M. marinum" (or "G: M. ulcerans")
whenever that base is found between the two flanking sequences. It does not look at the species.
The stored call text also reads `A1248 (M. marinum)`.

An exact match of both flanks with **A** at that position occurs in references of 29 species in
`myco_rrs.fasta` and 40 in the Bact amplicon file (counting species names of all genera in those
files), among them *M. kansasii*, *M. gastri*, *M. gordonae*, *M. asiaticum*, *M. africanum* and
*M. caprae*. A read of any of these can be labelled *M. marinum*.

The separate line "16S and 16S 3′-End: Mycobacterium marinum" is correct in this respect: it also
requires the sample's 16S read to point to *marinum* or *ulcerans*.

**Suggestion:** name *marinum* / *ulcerans* only when the 16S result supports it; otherwise show
the base alone.

### 2. No resistance call for Mtb rrs reads

**Fixed (2026-11-27):** #289 / #261 reads are their own assay with a preview (protocol 32.43613)
and calls at H37Rv 1401, 1402, 1403, 1483 and 1484. A WHO-associated mutation reports resistance;
wild type gives **no verdict**, by decision. Bact-1098s reads are unchanged, so their pane still
has no verdict sentence. Not yet checked with real reads. The description below is of the earlier
behaviour.

*Seen in code.*

rrs resistance positions come from ntm-db for *M. abscessus*, *M. avium* and *M. intracellulare*
only. A #289 / #261 read from the *M. tuberculosis* complex (amikacin, capreomycin; for example
a1401g) is shown with species hits but no resistance position and no statement that none was
assessed. An empty result could be read as susceptible.

The 3′-end pane also has no verdict sentence for any species, although a combined verdict is
computed from its SNP calls.

**Suggestion:** call the WHO-catalogue rrs positions for the *M. tuberculosis* complex, as done for
pncA and rpoB, or state in the pane that resistance is not assessed.

### 3. Mtb 23S reads are treated as NTM

**Fixed (2026-11-27):** SP1 / SP2 reads are their own assay with a preview (protocol 32.43604).
Linezolid resistance is reported for WHO-associated mutations and for those named in the protocol,
each with its source; wild type gives no verdict, and no macrolide call is made. rplC (protocol
32.43617) is not assessed. An NTM read sequenced with SP primers now gets this pane, with a species
warning. Not yet checked with real reads. The description below is of the earlier behaviour.

*Seen in code.*

SP1 F / SP2 R mod belongs to protocol 32.43604 (clarithromycin and linezolid, *M. tuberculosis*
complex). The pane shows the heading of the NTM protocol 32.43605 and a macrolide verdict from
positions 2058/2059. **Linezolid positions are not called**, and the pane does not say so.

**Suggestion:** distinguish the two assays in the file-name parser, as for the rpoB regions.

### 4. 16S 5′ pane lists uncovered resistance positions

**Fixed (2026-11-27):** uncovered positions are left out of the pane and the reports. With none
covered, the pane says that resistance is not assessed. The description below is of the earlier
behaviour.

*Seen in code.*

If the best NCBI species is one of the three with a catalogue, the pane shows "16S rRNA amikacin
resistance SNPs (rrs)". The positions lie near the 3′ end (about 1373–1400 in the ntm-db
numbering), while Mbak reads cover the 5′ part. The lines then end in `?`.

**Suggestion:** drop the section from this pane, or show it only when a position is covered.

### 5. `rrs_289_261` is in the 5′ pool

**Fixed (2026-11-27):** the file is now the amplicon pool of the Mtb rrs assay. The description
below is of the earlier behaviour.

*Seen in code.*

PRIMERS.md describes #289 / #261 as the 16S **3′ end** (212 bp on H37Rv). `REF_AMPLICON_RRS` in
[mod.rs](../src/sequencing/mod.rs), the 5′ pool, includes it. A 5′ read should not match it, so
the likely effect is only extra alignment work. The 3′-end pool, where #289 reads go, does not
include it.

**Suggestion:** move it to `REF_AMPLICON_RRS3END` and compare results on real #289 reads.

### 6. Chromatogram of the 3′-end pane

**Fixed (2026-11-27):** the caption describes the window that is shown, and the chromatogram no
longer depends on the top hit. The description below is of the earlier behaviour.

*Seen in code.*

- The caption says "Shown are bases 19-39", the erm(41) range. The window is 10 bases on each side
  of position 1248.
- The chromatogram is hidden when the top hit is *massiliense*, an erm(41) rule. The pane then says
  "16S 3-End chromatogram view is not available."

### 7. Headings and protocol numbers

**Fixed (2026-11-27):** headings give the protocol number without revision, and the 16S 5′ pane
names 32.43522 (32.43501 is not in the current handbook folder). The research protocol keeps its
name (NZM 21). The description below is of the earlier behaviour.

*Seen in code.*

| Pane | Heading in the program | PRIMERS.md |
|---|---|---|
| hsp65 | 32.43505-**2** | 32.43505-**4** |
| rpoB NTM | 32.43504-**3** | 32.43504-**5** |
| 16S 3′ end | 32.43506-**1** | 32.43506-**2**; Mtb reads belong to 32.43613-2 |
| rrl | 32.43605-**1** | 32.43605-**2**; Mtb reads belong to 32.43604-2 |
| pncA | 32.43616-2 | 32.43616-**4** |
| 16S 5′ | 32.43501-1 | primers are in 32.43304; 32.43501 is not listed |

Revision numbers may change often; showing the protocol number without revision would avoid this.
Which protocol the 16S heading should name is a lab decision.

### 8. hsp65: only the TB-12 amplicons

**Fixed (2026-11-27):** the pool is built from both files, with duplicates removed. The
description below is of the earlier behaviour.

*Checked on references.*

PRIMERS.md lists TB-11 + **TB-12w** as routine and TB-12 as fallback. The program uses only
`hsp65_TB11_TB12.fasta`. Six GTDB *Mycobacterium* species (all unnamed, `sp…`) are in the TB-12w
file only, so the practical effect is small.

**Suggestion:** include both files.

### 9. Odd-length references in the 3′-end pool

**Closed without a code change (2026-11-27).** This finding first assumed that short entries are
16S fragments that could reach a high identity from little evidence. The measurements below do not
support that.

*Checked on references.* *Mycobacterium* entries of `16S_Bact1098s_Bact1525a.fasta`; the expected
product is about 448 bp. The last column is the share of an entry's 16-base stretches that occur
anywhere in the NCBI 16S references (`myco_rrs.fasta`, either strand).

| Length (bp) | Entries | 16-base stretches found in NCBI 16S |
|---|---|---|
| under 400 | 17 (shortest 51) | none, in all 17 |
| 400–500 | 674 | median 100 %; 9 entries below 10 % |
| over 500 (up to 3000) | 90 | 89 entries below 10 % |

The 17 short entries have 2 or 3 mismatches per primer, and none is 98 % or more identical
(compared without gaps) to part of another species' product of 400 bp or more. The odd-length
entries therefore look like **off-target products of the in-silico PCR**, not pieces of 16S. A 16S
read is not expected to match them well.

**Not tested:** the program did not align any read against these entries for this check, and no
real read was used. The comparison used shared 16-base stretches and ungapped matching.

**If wanted later:** the entries come from cosmic-seq, where a limit on the product length of the
in-silico PCR would remove most of them. Do not edit the exported file by hand.

## 4. What is left

1. Findings 1 to 8 are fixed. None of the fixes has been checked with real reads yet.
2. Finding 9 is closed; the odd-length entries can be removed in cosmic-seq if wanted.

Changes to calls require a higher `ANALYSIS_VERSION`, so that cached results are recomputed.
