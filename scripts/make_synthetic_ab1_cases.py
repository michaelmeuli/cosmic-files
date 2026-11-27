#!/usr/bin/env python3
"""Write a set of synthetic AB1 reads that exercises every sequencing preview.

For each gene preview there is at least one read, plus one read per distinct mutation outcome
(one representative species, not every species). Species previews get a 16S read of the same lab
number, so the "same sample" 16S lines are filled. Reads are slices of the repository's own
reference sequences with a defined edit; basecall quality is 50 everywhere, with one Gaussian peak
per base (same ABIF layout as make_synthetic_ab1.ps1).

MANIFEST.tsv, written next to the reads, lists what each file is meant to show.

    uv run --no-project python scripts/make_synthetic_ab1_cases.py [--out DIR]

All reads go into one flat folder (default target/synthetic_ab1). The .ab1 files already in that
folder are removed first. Needs the build-time references (res/sequences/myco_*.fasta).
The data are artificial: never mix them into a folder of patient reads.
"""

import argparse
import math
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEQ = ROOT / "res" / "sequences"

# --- sequences ---------------------------------------------------------------------------------

BASES = "TCAG"
AMINO = "FFLLSSSSYY**CC*WLLLLPPPPHHQQRRRRIIIMTTTTNNKKSSRRVVVVAAAADDEEGGGG"
CODONS = {a + b + c: AMINO[16 * i + 4 * j + k]
          for i, a in enumerate(BASES)
          for j, b in enumerate(BASES)
          for k, c in enumerate(BASES)}
THREE = dict(zip("ACDEFGHIKLMNPQRSTVWY*",
                 "Ala Cys Asp Glu Phe Gly His Ile Lys Leu Met Asn Pro Gln Arg Ser Thr Val Trp "
                 "Tyr *".split()))
ONE = {v: k for k, v in THREE.items()}


def fasta(relative):
    """(header, sequence) entries of a FASTA file below res/sequences."""
    path = SEQ / relative
    if not path.is_file():
        sys.exit(f"missing reference {path} (run a cargo build first)")
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(">"):
            entries.append([line[1:], []])
        elif entries:
            entries[-1][1].append(line.strip().upper())
    return [(header, "".join(parts)) for header, parts in entries]


def single(relative):
    return fasta(relative)[0]


def ntm_db(gene, accession):
    """A full-gene ntm-db entry; its coordinates are those of variants.csv."""
    for header, seq in fasta(f"myco_{gene}.fasta"):
        if header.startswith(accession) and ":" in header.split()[0]:
            return header, seq
    sys.exit(f"no ntm-db entry {accession} in myco_{gene}.fasta")


def amplicon(name, species):
    """First GTDB amplicon of `species` (exact binomial) in references/<name>.fasta."""
    for header, seq in fasta(f"references/{name}.fasta"):
        words = header.split(" [")[0].split()[1:]
        if " ".join(words) == species:
            return header, seq
    sys.exit(f"no {species} in references/{name}.fasta")


def sub(seq, pos, wt, alt):
    """Substitute the base at 1-based `pos`, checking the wild type."""
    assert seq[pos - 1] == wt, f"position {pos}: expected {wt}, found {seq[pos - 1]}"
    return seq[:pos - 1] + alt + seq[pos:]


def codon_change(seq, start, wt_aa, alt_aa):
    """Change the codon at 0-based `start` to `alt_aa` with as few substitutions as possible."""
    wt = seq[start:start + 3]
    assert THREE[CODONS[wt]] == wt_aa, f"offset {start}: expected {wt_aa}, found {wt}"
    options = [c for c, aa in CODONS.items() if THREE[aa] == alt_aa and c != wt]
    best = min(options, key=lambda c: (sum(x != y for x, y in zip(c, wt)), c))
    return seq[:start] + best + seq[start + 3:]


def revcomp(seq):
    return seq[::-1].translate(str.maketrans("ACGT", "TGCA"))


def scatter(seq, every):
    """Replace every `every`-th base by another one (lowers the identity evenly)."""
    out = list(seq)
    for i in range(every // 2, len(out), every):
        out[i] = {"A": "C", "C": "G", "G": "T", "T": "A"}[out[i]]
    return "".join(out)


# --- ABIF ----------------------------------------------------------------------------------------


def ab1_bytes(seq):
    """A minimal ABIF file: traces, basecalls, qualities and peak positions of `seq`."""
    spacing, lead, sigma, height = 12, 20, 2.5, 1500
    n = len(seq)
    scans = lead * 2 + n * spacing
    order = "GATC"  # FWO_: channel order of DATA 9..12
    traces = {c: [0] * scans for c in order}
    peaks = []
    for i, base in enumerate(seq):
        center = lead + i * spacing
        peaks.append(center)
        for s in range(max(0, center - 10), min(scans, center + 11)):
            v = height * math.exp(-((s - center) ** 2) / (2 * sigma ** 2))
            for c in order:
                # An N has all four channels at the same medium height.
                weight = 0.35 if base == "N" else (1.0 if c == base else 0.04)
                traces[c][s] = min(32767, traces[c][s] + round(v * weight))

    tags = []  # (name, number, element type, element size, element count, payload)
    for k, c in enumerate(order):
        tags.append((b"DATA", 9 + k, 4, 2, scans, struct.pack(f">{scans}h", *traces[c])))
    for number in (1, 2):
        tags.append((b"PBAS", number, 2, 1, n, seq.encode("ascii")))
        tags.append((b"PCON", number, 2, 1, n, bytes([50]) * n))
        tags.append((b"PLOC", number, 4, 2, n, struct.pack(f">{n}H", *peaks)))
    tags.append((b"FWO_", 1, 2, 1, 4, order.encode("ascii")))
    sample = b"synthetic"
    tags.append((b"SMPL", 1, 18, 1, len(sample) + 1, bytes([len(sample)]) + sample))

    body = bytearray(128)
    offsets = []
    for tag in tags:
        payload = tag[5]
        offsets.append(len(body))
        if len(payload) > 4:
            body += payload
    directory = len(body)
    for (name, number, kind, size, count, payload), offset in zip(tags, offsets):
        body += struct.pack(">4sihhii", name, number, kind, size, count, len(payload))
        body += struct.pack(">i", offset) if len(payload) > 4 else payload.ljust(4, b"\0")
        body += bytes(4)  # data handle
    header = struct.pack(">4sh4sihhiiii", b"ABIF", 101, b"tdir", 1, 1023, 28, len(tags),
                         len(tags) * 28, directory, 0)
    body[:len(header)] = header
    return bytes(body)


# --- cases ---------------------------------------------------------------------------------------

COLUMNS = ("file", "gene", "case", "reference", "top_hit", "verdict", "calls", "pane")


class Cases:
    def __init__(self):
        self.rows = []
        self.reads = {}
        self.number = 2026990000

    def add(self, primer, case, read, *, gene, ref, top="", verdict="-", calls="", pane="",
            sibling=None):
        """One read, plus a 16S read of the same lab number when `sibling` (a species) is set.

        `top`, `verdict` (S, R or -) and `calls` (`;`-separated substrings of the call tags) are
        the expected analysis result; `pane` says what to look at.
        """
        self.number += 1
        self._write(f"{self.number}_{primer}_{case}.ab1", gene, case, ref, read, top, verdict,
                    calls, pane)
        if sibling:
            header, seq = amplicon("16S_Mbak283f_Mbak264r", sibling)
            species = sibling.split()[-1]
            self._write(f"{self.number}_Mbak14_{species}.ab1", "16S", "same-sample 16S", header,
                        seq, "", "-", "", f"16S companion of {self.number}")

    def _write(self, name, gene, case, ref, read, top, verdict, calls, pane):
        assert name not in self.reads, name
        self.reads[name] = ab1_bytes(read)
        self.rows.append((name, gene, case, ref.split()[0], top, verdict, calls, pane))


def erm41_cases(cases):
    abscessus = single("erm41/erm41_abscessus_ATCC_19977.fasta")
    bolletii = single("erm41/erm41_bolletii_CIP_108541.fasta")
    massiliense = single("erm41/erm41_massiliense_CCUG_48898.fasta")

    def add(case, entry, read=None, **expect):
        cases.add("erm41_f", case, read or entry[1], gene="erm(41)", ref=entry[0], **expect)

    seq = abscessus[1]
    add("abscessus_T28", abscessus, top="subsp. abscessus", verdict="R", calls="T28",
        pane="inducible resistance; chromatogram around position 28")
    for alt in "CGA":
        add(f"abscessus_{alt}28", abscessus, sub(seq, 28, "T", alt), top="abscessus",
            verdict="S", calls=f"{alt}28",
            pane="susceptible" + ("; p.Trp10Arg loss of function too" if alt == "C" else ""))
    add("bolletii_T28", bolletii, top="subsp. bolletii", verdict="R", calls="T28",
        pane="inducible resistance, bolletii reference")
    add("massiliense", massiliense, top="subsp. massiliense", verdict="S",
        pane="susceptible with massiliense reason; no chromatogram")
    # p.Arg7*: the one substitution in codon 7 (nt 19-21) that gives a stop.
    stop = codon_change(seq, 18, "Arg", "*")
    add("abscessus_Arg7stop", abscessus, stop, top="abscessus", verdict="S",
        calls="p.Arg7*: loss of function",
        pane="position 28 anchor lost; susceptible because of loss of function")
    add("abscessus_N28", abscessus, sub(seq, 28, "T", "N"), top="abscessus", verdict="-",
        calls="T28N", pane="'erm(41) Position 28 not found', no verdict")
    add("abscessus_T28_revcomp", abscessus, revcomp(seq), top="subsp. abscessus", verdict="R",
        calls="T28", pane="chromatogram marked reverse complement")


def rrl_cases(cases):
    header, full = ntm_db("rrl", "CU458896")
    # The MCLR19F / MCLR21R window of the M. abscessus gene; E. coli 2058 is nt 2270.
    start, end = 2141, 2977
    window = full[start:end]
    abscessus = "Mycobacterium abscessus"

    def add(case, read, ref=header, species=abscessus, **expect):
        cases.add("MCLR19F", case, read, gene="rrl", ref=ref, sibling=species, **expect)

    def edit(pos, wt, alt):
        return sub(full, pos, wt, alt)[start:end]

    # M. abscessus ties with M. massiliense in this window; massiliense is listed first, and the
    # abscessus catalogue applies to it.
    add("abscessus_wildtype", window, top="massiliense", verdict="S", calls="wildtype",
        pane="A2058/A2059 wt, susceptible, catalogue SNPs all wt")
    for pos, wt, alt, ecoli, pane in [
        (2269, "A", "G", "A2057G", "position undetermined (anchor); catalogued mutation found"),
        (2270, "A", "G", "A2058G", "mutation in A2058/A2059"),
        (2271, "A", "G", "A2059G", "mutation in A2058/A2059"),
        (2281, "G", "A", "G2069A", "position undetermined (anchor); catalogued mutation found"),
        (2293, "A", "G", "A2082G", "A2058/A2059 wt but catalogued mutation"),
    ]:
        add(f"abscessus_{ecoli}", edit(pos, wt, alt), top="massiliense", verdict="R",
            calls=f"E.coli: {ecoli}", pane=pane)
    add("abscessus_A2058G_revcomp", revcomp(edit(2270, "A", "G")), top="massiliense",
        verdict="R", calls="E.coli: A2058G", pane="chromatogram marked reverse complement")

    # The M. avium window starts 9 nt later; E. coli 2058 is nt 2279.
    h, s = ntm_db("rrl", "CP000479")

    def avium_add(case, read, **expect):
        add(case, read[start + 9:end + 9], ref=h, species="Mycobacterium avium", top="avium",
            **expect)

    avium_add("avium_wildtype", s, verdict="S", calls="wildtype",
              pane="susceptible, catalogue SNPs all wt")
    for pos, wt, alt, ecoli, pane in [
        (2278, "A", "G", "A2057G", "position undetermined (anchor); catalogued mutation found"),
        (2279, "A", "G", "A2058G", "mutation in A2058/A2059"),
        (2280, "A", "G", "A2059G", "mutation in A2058/A2059"),
        (2290, "G", "A", "G2069A", "position undetermined (anchor); catalogued mutation found"),
        (2303, "A", "G", "A2082G", "A2058/A2059 wt but catalogued mutation"),
    ]:
        avium_add(f"avium_{ecoli}", sub(s, pos, wt, alt), verdict="R",
                  calls=f"E.coli: {ecoli}", pane=pane)
    avium_add("avium_N2058", sub(s, 2279, "A", "N"), verdict="-", calls="E.coli: A2058N",
              pane="position undetermined, no verdict")

    h, s = ntm_db("rrl", "CP015278")
    add("intracellulare_A2058G", sub(s, 2266, "A", "G")[start - 4:end - 4], ref=h,
        species="Mycobacterium intracellulare", top="intracellulare", verdict="R",
        calls="E.coli: A2058G", pane="resistant, species-specific catalogue")
    h, s = amplicon("23S_MCLR19F_MCLR21R", "Mycobacterium kansasii")
    # The app names the kansasii 23S reference "Mycobacterium kansas".
    add("kansasii_wildtype", s, ref=h, species="Mycobacterium kansasii", top="kansas",
        verdict="S", calls="wildtype",
        pane="species without a catalogue: position call only, no SNP list")


def rrs3end_cases(cases):
    header, full = ntm_db("rrs", "CU458896")
    start = 1062  # Bact-1098s window of the M. abscessus gene
    abscessus = "Mycobacterium abscessus"

    def add(case, read, ref, species, **expect):
        cases.add("Bact-1098s", case, read, gene="16S 3'-End", ref=ref, sibling=species,
                  **expect)

    # M. abscessus: the top NCBI hit is named "Mycobacteroides abscessus"; the catalogue of the
    # "Mycobacterium abscessus" reference applies to it.
    add("abscessus_wildtype", full[start:], header, abscessus, top="abscessus",
        pane="amikacin SNPs all wt; no verdict")
    add("abscessus_A1408G", sub(full, 1375, "A", "G")[start:], header, abscessus,
        top="abscessus", verdict="R", calls="E.coli: A1408G", pane="amikacin resistance SNP")

    # M. avium: E. coli 1406 is nt 1386, 13 nt after the abscessus numbering.
    h, s = ntm_db("rrs", "CP000479")
    avium = "Mycobacterium avium"
    add("avium_wildtype", s[start + 13:], h, avium, top="avium", pane="amikacin SNPs all wt")
    for pos, wt, alt, ecoli in [(1386, "T", "A", "T1406A"), (1388, "A", "G", "A1408G"),
                                (1389, "C", "T", "C1409T")]:
        add(f"avium_{ecoli}", sub(s, pos, wt, alt)[start + 13:], h, avium, top="avium",
            verdict="R", calls=f"E.coli: {ecoli}", pane="amikacin resistance SNP")

    anchor = "ACATGCTACAATGGCCGGT"
    h, s = amplicon("16S_Bact1098s_Bact1525a", "Mycobacterium marinum")
    at = s.index(anchor) + len(anchor)  # 0-based index of position 1248
    assert s[at] == "A"
    heading = "'16S 3\'-End position 1248 = {}'"
    both = "; '16S and 16S 3\'-End: Mycobacterium {}'"

    def marinum(case, read, **expect):
        add(case, read, h, "Mycobacterium marinum", **expect)

    marinum("marinum_pos1248A", s, calls="A1248",
            pane=heading.format("A") + both.format("marinum"))
    marinum("ulcerans_pos1248G", sub(s, at + 1, "A", "G"), calls="G1248",
            pane=heading.format("G") + both.format("ulcerans"))
    for alt in "CT":
        marinum(f"marinum_pos1248{alt}", sub(s, at + 1, "A", alt), calls=f"{alt}1248",
                pane=heading.format(alt))
    marinum("marinum_pos1248N", sub(s, at + 1, "A", "N"), pane=heading.format("undetermined"))
    marinum("marinum_pos1248A_revcomp", revcomp(s), calls="A1248",
            pane="chromatogram marked reverse complement")


def rrs16s_cases(cases):
    for species, pane in [
        ("Mycobacterium kansasii", "complex label"),
        ("Mycobacterium abscessus", "chelonae/abscessus complex label"),
        ("Mycobacterium avium", "species or complex call"),
        ("Mycobacterium tuberculosis", "species or complex call"),
        ("Mycobacterium szulgai", "tie or single-species call"),
    ]:
        header, seq = amplicon("16S_Mbak283f_Mbak264r", species)
        cases.add("Mbak14", f"{species.split()[-1]}_5prime", seq, gene="16S", ref=header,
                  top=species.split()[-1], pane=pane)
    header, full = ntm_db("rrs", "CP000479")
    cases.add("Mbak14", "avium_fulllength_A1408G", sub(full, 1388, "A", "G"), gene="16S",
              ref=header, top="avium", verdict="R", calls="E.coli: A1408G",
              pane="amikacin SNP block in the 16S pane")


def hsp65_cases(cases):
    header, seq = amplicon("hsp65_TB11_TB12", "Mycobacterium kansasii")
    cases.add("hsp65_TB-11", "kansasii", seq, gene="hsp65", ref=header, top="kansasii",
              sibling="Mycobacterium kansasii", pane="16S lines filled from the same sample")
    header, seq = amplicon("hsp65_TB11_TB12", "Mycobacterium gastri")
    cases.add("hsp65_TB-11", "gastri_no16S", seq, gene="hsp65", ref=header, top="gastri",
              pane="'No species identified from 16S hits'")


def rpob_cases(cases):
    for species, pane in [("Mycobacterium kansasii", "species ID, no rifampicin block"),
                          ("Mycobacterium chelonae", "'16S and rpoB: M. chelonae' note")]:
        header, seq = amplicon("rpoB_2573f_3337r", species)
        cases.add("rpoB_2573f", species.split()[-1], seq, gene="rpoB", ref=header,
                  top=species.split()[-1], sibling=species, pane=pane)

    header, h37rv = single("rpob/rpob_h37rv.fasta")
    tb = "Mycobacterium tuberculosis"

    def window(seq, first_nt, last_nt):
        return seq[first_nt - 1:last_nt]

    def offset(codon):
        return (codon - 1) * 3

    def change(codon, wt, alt):
        return codon_change(h37rv, offset(codon), wt, alt)

    def add(primer, gene, case, read, **expect):
        expect.setdefault("sibling", tb)
        cases.add(primer, case, read, gene=gene, ref=header, **expect)

    def rrdr(case, seq, **expect):
        # rpoB-TR1 / TR2b product on H37Rv: nt 1119-1529 (codons 373-509).
        read = window(seq, 1119, 1529 + len(seq) - len(h37rv))
        add("rpoB_TR1", "rpoB RRDR", case, read, **expect)

    rrdr("wildtype", h37rv, top="tuberculosis", verdict="S", pane="RRDR wild type")
    for codon, wt, alt in [(450, "Ser", "Leu"), (435, "Asp", "Val"), (445, "His", "Tyr")]:
        rrdr(f"{wt}{codon}{alt}", change(codon, wt, alt), verdict="R",
             calls=f"p.{wt}{codon}{alt} (rifampicin, Assoc w R", pane="catalogued mutation")
    rrdr("Leu440Ala_rule", change(440, "Leu", "Ala"), verdict="R",
         calls="p.Leu440Ala;RRDR rule", pane="uncatalogued missense, resistant by RRDR rule")
    synonymous = change(450, "Ser", "Ser")
    rrdr("Ser450Ser_synonymous", synonymous, verdict="S", pane="synonymous: susceptible")
    i = offset(437)
    rrdr("inframe_deletion", h37rv[:i] + h37rv[i + 3:], verdict="R",
         calls="del (rifampicin;in-frame RRDR indel", pane="in-frame RRDR deletion")
    i = offset(434)
    rrdr("inframe_insertion", h37rv[:i] + "TTC" + h37rv[i:], verdict="R",
         calls="ins;in-frame RRDR indel", pane="in-frame RRDR insertion")
    i = offset(440) + 1
    rrdr("frameshift", h37rv[:i] + h37rv[i + 1:], verdict="-", calls="frameshift (check read)",
         pane="no verdict")
    i = offset(440)
    assert h37rv[i:i + 3] == "CTG"
    rrdr("Leu440stop", h37rv[:i] + "TAG" + h37rv[i + 3:], verdict="-",
         calls="stop codon (check read)", pane="no verdict")
    rrdr("Ile491Phe_outside_RRDR", change(491, "Ile", "Phe"), verdict="R", calls="p.Ile491Phe",
         pane="catalogued mutation outside the RRDR")
    add("rpoB_TR1", "rpoB RRDR", "partial_RRDR", window(h37rv, 1119, offset(441)), verdict="-",
        pane="'RRDR not fully covered'")
    add("rpoB_TR1", "rpoB RRDR", "Ser450Leu_revcomp",
        revcomp(window(change(450, "Ser", "Leu"), 1119, 1529)), verdict="R",
        calls="p.Ser450Leu", pane="reverse strand")
    h, s = amplicon("rpoB_TR1_TR2b", "Mycobacterium avium")
    cases.add("rpoB_TR1", "avium_not_tuberculosis", s, gene="rpoB RRDR", ref=h, top="avium",
              sibling="Mycobacterium avium", verdict="*",
              calls="catalogue not validated for this species",
              pane="species warning under the rifampicin calls")

    # Tb176-f / Tb176-r product: nt 276-640 (codons 92-213).
    add("rpoB_Tb176-f", "rpoB 5'", "wildtype_5prime", window(h37rv, 276, 640), verdict="-",
        pane="no catalogued mutation, no verdict (RRDR not covered)")
    add("rpoB_Tb176-f", "rpoB 5'", "Val170Phe", window(change(170, "Val", "Phe"), 276, 640),
        verdict="R", calls="p.Val170Phe", pane="catalogued mutation in the 5' region")
    # rpoB-F1 / R product (GeneXpert): nt 1206-1397.
    add("rpoB-F1", "rpoB Xpert", "wildtype_Xpert", window(h37rv, 1206, 1397), verdict="S",
        pane="Xpert region covers the whole RRDR")
    add("rpoB-F1", "rpoB Xpert", "Ser450Leu_Xpert",
        window(change(450, "Ser", "Leu"), 1206, 1397), verdict="R", calls="p.Ser450Leu",
        pane="resistant")


def pnca_cases(cases):
    h37rv = single("pnca/pnca_h37rv.fasta")
    header, seq = h37rv
    flank = 50  # c.1 is at 0-based index 50

    def add(case, read, ref=header, **expect):
        cases.add("pncA-Ber-fw", case, read, gene="pncA", ref=ref, **expect)

    def nt(c_pos, wt, alt):
        index = flank + (c_pos - 1 if c_pos > 0 else c_pos)
        return sub(seq, index + 1, wt, alt)

    def aa(codon, wt, alt):
        return codon_change(seq, flank + (codon - 1) * 3, wt, alt)

    add("H37Rv_wildtype", seq, verdict="S", pane="predicted susceptible")
    add("promoter_c.-11A_G", nt(-11, "A", "G"), verdict="R", calls="c.-11A>G (pyrazinamide",
        pane="promoter mutation")
    add("Asp12Ala_AssocR", aa(12, "Asp", "Ala"), verdict="R",
        calls="p.Asp12Ala (pyrazinamide, Assoc w R)", pane="catalogued missense")
    add("Gln10stop_AssocR", aa(10, "Gln", "*"), verdict="R", calls="p.Gln10*",
        pane="catalogued nonsense")

    interim = catalogue_example(seq, flank, "Assoc w R - Interim")
    add(f"{interim[0]}_interim", interim[1], verdict="R",
        calls=f"p.{interim[0]};Assoc w R - Interim", pane="interim confidence")
    unsure = catalogue_example(seq, flank, "Uncertain significance")
    add(f"{unsure[0]}_uncertain", unsure[1], verdict="-",
        calls=f"p.{unsure[0]};Uncertain significance", pane="no verdict")
    untested = untested_example(seq, flank)
    add(f"{untested[0]}_untested", untested[1], verdict="-", calls="(mutation, untested)",
        pane="uncatalogued variant, no verdict")
    i = flank + 150
    add("frameshift_c.151del", seq[:i] + seq[i + 1:], verdict="S",
        pane="APP GAP: frameshifts are not called, read reported susceptible")
    add("partial_read", seq[:330], verdict="-", pane="sites uncovered, no verdict")
    add("Asp12Ala_revcomp", revcomp(aa(12, "Asp", "Ala")), verdict="R", calls="p.Asp12Ala",
        pane="reverse strand")
    for name, file in [("bovis_His57Asp", "pnca_bovis_AF2122_97"),
                       ("canettii", "pnca_canettii_CIPT_140010059")]:
        h, s = single(f"pnca/{file}.fasta")
        add(name, s, ref=h, verdict="*", top="bovis" if "bovis" in name else "canetti",
            calls="p.His57Asp" if "bovis" in name else "",
            pane="intrinsic M. bovis resistance mutation" if "bovis" in name
            else "canettii reference")


def pnca_catalogue():
    """(mutation, confidence) rows of the pncA codon substitutions in the WHO catalogue."""
    import csv

    with open(ROOT / "tbprofiler" / "mutations.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["Gene"] == "pncA":
                yield row["Mutation"], row["confidence"]


def pnca_codons(seq, flank):
    """(codon number, wild-type amino acid) of the pncA coding sequence."""
    for codon in range(2, 187):
        i = flank + (codon - 1) * 3
        yield codon, THREE[CODONS[seq[i:i + 3]]]


def catalogue_example(seq, flank, confidence):
    """First pncA missense (by codon) whose only catalogue confidence is `confidence`."""
    import re

    seen = {}
    for mutation, conf in pnca_catalogue():
        if conf:
            seen.setdefault(mutation, set()).add(conf)
    found = []
    for mutation, confs in seen.items():
        m = re.fullmatch(r"p\.([A-Z][a-z]{2})(\d+)([A-Z][a-z]{2})", mutation)
        if m and confs == {confidence} and m[1] in ONE and m[3] in ONE:
            found.append((int(m[2]), m[1], m[3]))
    codon, wt, alt = min(found)
    return f"{wt}{codon}{alt}", codon_change(seq, flank + (codon - 1) * 3, wt, alt)


def untested_example(seq, flank):
    """First single-base missense at a catalogued codon whose alt the catalogue doesn't list."""
    listed = {m for m, conf in pnca_catalogue() if conf}
    codons = {int("".join(c for c in m[5:] if c.isdigit()))
              for m in listed if m.startswith("p.")}
    for codon, wt in pnca_codons(seq, flank):
        if codon not in codons:
            continue
        i = flank + (codon - 1) * 3
        old = seq[i:i + 3]
        for position in range(3):
            for base in "ACGT":
                new = old[:position] + base + old[position + 1:]
                alt = THREE[CODONS[new]]
                # A changed base must not hit a catalogued nucleotide row either.
                c_pos = (codon - 1) * 3 + position + 1
                nt_row = f"c.{c_pos}{old[position]}>{base}"
                if alt not in (wt, "*") and f"p.{wt}{codon}{alt}" not in listed \
                        and nt_row not in listed:
                    return f"{wt}{codon}{alt}", seq[:i] + new + seq[i + 3:]
    sys.exit("no uncatalogued pncA variant found")


def fallback_cases(cases):
    # A homopolymer: random bases give short 100 % matches that count as a hit.
    cases.add("hsp65_TB-11", "unalignable", "A" * 400, gene="hsp65", ref="poly-A",
              pane="'Could not align'")
    header, full = ntm_db("rrl", "CU458896")
    window = full[2141:2977]
    cases.add("MCLR19F", "short_read", window[90:170], gene="rrl", ref=header, verdict="*",
              pane="under 100 bases: no result in the preview (the folder scan still calls it S)")
    cases.add("MCLR19F", "low_identity", scatter(window, 25), gene="rrl", ref=header,
              verdict="*", pane="below 98%: 'Show alignments below 98% identity' button")
    cases.add("inhA-rev", "no_analysis", window, gene="", ref=header,
              pane="unrecognised name: standard file preview")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "target" / "synthetic_ab1")
    out = parser.parse_args().out

    cases = Cases()
    for build in (erm41_cases, rrl_cases, rrs3end_cases, rrs16s_cases, hsp65_cases,
                  rpob_cases, pnca_cases, fallback_cases):
        build(cases)

    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.ab1"):
        old.unlink()
    for name, data in cases.reads.items():
        (out / name).write_bytes(data)
    lines = ["\t".join(COLUMNS)] + ["\t".join(row) for row in cases.rows]
    (out / "MANIFEST.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    companions = sum(row[2] == "same-sample 16S" for row in cases.rows)
    print(f"Wrote {len(cases.reads) - companions} case reads and {companions} 16S companions "
          f"to {out}")


if __name__ == "__main__":
    main()
