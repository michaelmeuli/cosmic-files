//! Parsing of routine Sanger (AB1) file names into a sample ID and the gene/amplicon sequenced.
//!
//! Naming conventions are documented in kansasii-docs
//! [`SANGER_LABNUMBERS.md`](https://github.com/michaelmeuli/kansasii-docs/blob/master/docs/SANGER_LABNUMBERS.md)
//! (lab numbers) and
//! [`SANGER_RPOB.md`](https://github.com/michaelmeuli/kansasii-docs/blob/master/docs/SANGER_RPOB.md)
//! (rpoB regions); primer names come from cosmic-seq
//! [`PRIMERS.md`](https://github.com/michaelmeuli/cosmic-seq/blob/master/docs/PRIMERS.md).
//!
//! A name looks like `<lab number><sep><marker/primer part>[_<run date>_<time>_<well>].ab1`, e.g.
//! `2014500121_clr_mclr_21r_2014-08-04_12-04-17_H05.ab1` or `2025500747 rpoB_rpoB-2573f.ab1`.
//! Gene keywords are matched only in the marker part, so digits of the lab number or run date
//! never trigger a rule.

use std::ops::Range;
use std::path::Path;

pub use super::rpob::RpoBRegion;

/// Gene/amplicon an AB1 read was sequenced for, i.e. which `identify_sequence_*` analysis it gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ab1Gene {
    /// erm(41), *M. abscessus* macrolide resistance (erm41f/r, erm41f2/r2, ermprom).
    Erm41,
    /// hsp65 / groEL2 (TB-11 / TB-12(w), "65kDa").
    Hsp65,
    /// rpoB, with the region the read covers (NTM 2573f/3337r or one of the Mtb regions).
    RpoB(RpoBRegion),
    /// 16S rRNA 5' part (Mbak283f/264r/259r, sequenced with Mbak14).
    Rrs16S,
    /// 16S rRNA 3' end (Bact-1098s / 1525a), species ID.
    Rrs3End,
    /// *M. tuberculosis* complex rrs, aminoglycoside / capreomycin resistance (#289 / #261).
    RrsMtb,
    /// 23S rRNA (MCLR 19F / 21R, SP1 F / SP2 R mod).
    Rrl,
    /// pncA (pncA-Ber-fw / rv).
    PncA,
}

impl Ab1Gene {
    /// The gene label stored in [`SampleSusceptibilityRecord::gene`](super::batch::SampleSusceptibilityRecord)
    /// (and therefore in the disk cache and CSV exports).
    pub fn label(self) -> &'static str {
        match self {
            Self::Erm41 => "erm(41)",
            Self::Hsp65 => "hsp65",
            Self::RpoB(region) => region.label(),
            Self::Rrs16S => "16S",
            Self::Rrs3End => "16S 3'-End",
            Self::RrsMtb => "rrs Mtb",
            Self::Rrl => "rrl",
            Self::PncA => "pncA",
        }
    }
}

/// Extract `(sample_id, gene)` from an AB1 filename.
///
/// `sample_id` is the normalised 10-digit lab number (`YYYY` + 6-digit counter, see
/// [`find_lab_number`]), or the whole file stem when the name carries none.
/// `gene` is inferred from keywords in the marker part of the name (see [`gene_from_marker`]);
/// `None` means no analysis applies (unknown marker, or an rpoB read of a region without
/// references, e.g. the *M. abscessus* MAB amplicon).
pub fn parse_ab1_filename(name: &str) -> (String, Option<Ab1Gene>) {
    let stem = Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    let lab = find_lab_number(stem);
    let marker = marker_part(stem, lab.as_ref().map(|(_, span)| span.clone()));
    let sample_id = lab.map_or_else(|| stem.to_string(), |(id, _)| id);
    (sample_id, gene_from_marker(&marker))
}

/// `true` if `b[start..start + len]` is a run of ASCII digits not embedded in a longer digit run.
fn is_isolated_digits(b: &[u8], start: usize, len: usize) -> bool {
    start + len <= b.len()
        && b[start..start + len].iter().all(u8::is_ascii_digit)
        && (start == 0 || !b[start - 1].is_ascii_digit())
        && b.get(start + len).is_none_or(|c| !c.is_ascii_digit())
}

/// Find the lab number (TNR) in a file stem and return it normalised to 10 digits, together
/// with the byte range it occupies in `stem`. Forms, tried in this order over the whole stem:
///
/// 1. `YYYYNNNNNN` — 10 digits starting with `20` (2011 onwards);
/// 2. `YYYY_NNNNNN` / `YYYY NNNNNN` (e.g. `2010_500249`);
/// 3. `NNNNNN-YY` (e.g. `176104-08` → `2008176104`).
///
/// Six-digit numbers without a year (common before 2011) are not unique across years and are
/// not returned.
fn find_lab_number(stem: &str) -> Option<(String, Range<usize>)> {
    let b = stem.as_bytes();
    let starts_20 = |i: usize| b[i..].starts_with(b"20");

    if let Some(i) = (0..b.len()).find(|&i| starts_20(i) && is_isolated_digits(b, i, 10)) {
        return Some((stem[i..i + 10].to_string(), i..i + 10));
    }
    if let Some(i) = (0..b.len()).find(|&i| {
        starts_20(i)
            && is_isolated_digits(b, i, 4)
            && matches!(b.get(i + 4), Some(b'_' | b' '))
            && is_isolated_digits(b, i + 5, 6)
    }) {
        return Some((
            format!("{}{}", &stem[i..i + 4], &stem[i + 5..i + 11]),
            i..i + 11,
        ));
    }
    if let Some(i) = (0..b.len()).find(|&i| {
        is_isolated_digits(b, i, 6)
            && b.get(i + 6) == Some(&b'-')
            && is_isolated_digits(b, i + 7, 2)
    }) {
        return Some((
            format!("20{}{}", &stem[i + 7..i + 9], &stem[i..i + 6]),
            i..i + 9,
        ));
    }
    None
}

/// The lowercase marker/primer part of a file stem (SANGER_RPOB.md, parser rule 1): the lab
/// number is blanked out, and `_Peaktraced` plus the run suffix (`_YYYY-MM-DD_hh-mm-ss_A01`,
/// before 2009 `_YYYY-MM-DD_NN_A01`) are removed.
fn marker_part(stem: &str, lab_span: Option<Range<usize>>) -> String {
    // ASCII lowercasing keeps byte offsets, so `lab_span` stays valid.
    let mut s = stem.to_ascii_lowercase();
    if let Some(span) = lab_span {
        s.replace_range(span, " ");
    }
    let b = s.as_bytes();
    let is_date = |i: usize| {
        let d = |j: usize| b.get(i + j).is_some_and(u8::is_ascii_digit);
        (0..4).all(d)
            && b.get(i + 4) == Some(&b'-')
            && (5..7).all(d)
            && b.get(i + 7) == Some(&b'-')
            && (8..10).all(d)
    };
    if let Some(cut) = (0..b.len()).find(|&i| matches!(b[i], b'_' | b' ') && is_date(i + 1)) {
        s.truncate(cut);
    }
    s.replace("_peaktraced", " ")
}

/// Split the marker part into tokens on `_`, space and `.`, dropping punctuation that primer
/// names carry inside a token (`rpoB-2573f` → `rpob2573f`, `erm(41)` → `erm41`, `TB-12w` → `tb12w`).
fn tokens(marker: &str) -> Vec<String> {
    marker
        .split(['_', ' ', '.'])
        .map(|t| {
            t.chars()
                .filter(|c| !matches!(c, '-' | '(' | ')' | '#' | '`' | '\''))
                .collect::<String>()
        })
        .filter(|t| !t.is_empty())
        .collect()
}

/// `true` if `num` occurs in `s` with no digit directly before or after it.
fn has_standalone_num(s: &str, num: &str) -> bool {
    let b = s.as_bytes();
    s.match_indices(num).any(|(i, _)| {
        (i == 0 || !b[i - 1].is_ascii_digit())
            && b.get(i + num.len()).is_none_or(|c| !c.is_ascii_digit())
    })
}

/// `true` if `s` contains `pat` not directly followed by a digit.
fn contains_not_before_digit(s: &str, pat: &str) -> bool {
    let b = s.as_bytes();
    s.match_indices(pat)
        .any(|(i, _)| b.get(i + pat.len()).is_none_or(|c| !c.is_ascii_digit()))
}

/// `tr\s?\d` — the Mtb RRDR primers TR1 / TR2b (and typos such as `TR26`, `TR 2`).
fn has_tr_primer(s: &str) -> bool {
    let b = s.as_bytes();
    s.match_indices("tr").any(|(i, _)| {
        let mut j = i + 2;
        if b.get(j) == Some(&b' ') {
            j += 1;
        }
        b.get(j).is_some_and(u8::is_ascii_digit)
    })
}

/// `rpoB-?[FR]\d(?!\d)` — the Xpert-region primers rpoB-F1, -F2, -R2.
fn has_xpert_primer(s: &str) -> bool {
    let b = s.as_bytes();
    s.match_indices("rpob").any(|(i, _)| {
        let mut j = i + 4;
        if b.get(j) == Some(&b'-') {
            j += 1;
        }
        matches!(b.get(j), Some(b'f' | b'r'))
            && b.get(j + 1).is_some_and(u8::is_ascii_digit)
            && b.get(j + 2).is_none_or(|c| !c.is_ascii_digit())
    })
}

/// Classify an rpoB-selected marker part (SANGER_RPOB.md, parser rules 4–5, first match
/// wins). The NTM species-ID region and the three Mtb rifampicin regions each map to their
/// [`RpoBRegion`]; the *M. abscessus* (MAB) and *M. marinum* (RPO F/R) amplicons and other
/// genera have no references and return `None`.
///
/// Not covered (needs folder context): bare `rpoB-R` in the August 2018 GeneXpert runs, which
/// is the Xpert reverse primer but is classified here as NTM.
fn rpob_region(m: &str) -> Option<Ab1Gene> {
    let region = if m.contains("strep") || m.contains("univ") || m.contains("grpob") {
        return None; // other genus
    } else if m.contains("mab") || m.contains("marinum") {
        return None; // M. abscessus / M. marinum amplicons, 2015 only
    } else if contains_not_before_digit(m, "tb176") {
        RpoBRegion::Mtb5Prime
    } else if m.contains("genexpert") || has_xpert_primer(m) {
        RpoBRegion::MtbXpert
    } else if has_standalone_num(m, "81")
        || has_tr_primer(m)
        || m.contains("core")
        || m.contains("mut")
        || m.contains("rpobc")
    {
        RpoBRegion::MtbRrdr
    } else {
        // NTM 2573f/3337r (`25[67][2-5]`, `573f`, `258f`, `3?337r`, `myco`) or no primer token,
        // which the corpus shows is the NTM species-ID assay as well (rule 5).
        RpoBRegion::Ntm
    };
    Some(Ab1Gene::RpoB(region))
}

/// Infer the gene from the marker part. Rules are checked in this order; the first match wins.
fn gene_from_marker(m: &str) -> Option<Ab1Gene> {
    let toks = tokens(m);
    let compact: String = m.chars().filter(char::is_ascii_alphanumeric).collect();
    let any_tok = |f: &dyn Fn(&str) -> bool| toks.iter().any(|t| f(t.as_str()));
    let no_digit_at = |t: &str, i: usize| t.as_bytes().get(i).is_none_or(|c| !c.is_ascii_digit());

    // erm(41): `erm`, `erm41…`, `ermprom…`, `ermf`/`ermr2`; not erm(38/39/40) (`erm39`, CME-1Y).
    if any_tok(&|t| {
        t.strip_prefix("erm").is_some_and(|rest| {
            rest.is_empty()
                || rest.starts_with("41")
                || rest.starts_with("prom")
                || (rest.len() <= 3 && rest.starts_with(['f', 'r']))
        })
    }) {
        return Some(Ab1Gene::Erm41);
    }

    // hsp65: `hsp65`, `65kDa`, primers TB-11 / TB-12 / TB-12w.
    if compact.contains("hsp65")
        || compact.contains("65kda")
        || any_tok(&|t| t.starts_with("tb11") || t.starts_with("tb12"))
    {
        return Some(Ab1Gene::Hsp65);
    }

    // rpoB: selected by `rpo|TR\s?\d|81\s?bp|Tb176(?!\d)` (TR1/TR2b reads often lack "rpoB");
    // a selected file is decided by `rpob_region` and never falls through to other genes.
    if m.contains("rpo")
        || has_tr_primer(m)
        || m.contains("81bp")
        || m.contains("81 bp")
        || contains_not_before_digit(m, "tb176")
    {
        return rpob_region(m);
    }

    // 16S 5' part: Mbak283f / Mbak264r / Mbak259r / Mbak14.
    if any_tok(&|t| t.starts_with("mbak")) {
        return Some(Ab1Gene::Rrs16S);
    }

    // 16S 3' end: Bact-1098s / Bact-1525a.
    if compact.contains("1098s") || compact.contains("1525a") {
        return Some(Ab1Gene::Rrs3End);
    }

    // Mtb rrs amplicon: `#289` / `#261`, or `rrs` with a standalone 289 / 261. Any other `rrs`
    // name is a 16S 3' end read.
    let rrs_token = any_tok(&|t| t.starts_with("rrs"));
    if m.contains("#289")
        || m.contains("#261")
        || (rrs_token && (has_standalone_num(m, "289") || has_standalone_num(m, "261")))
    {
        return Some(Ab1Gene::RrsMtb);
    }
    if rrs_token {
        return Some(Ab1Gene::Rrs3End);
    }

    // 23S: `rrl`, MCLR 19F / 21R (also typed `MCRL`), `clr`, SP1 F / SP2 R mod. A bare `23S`
    // is not enough: in the routine corpus it only occurs on non-mycobacterial 23S reads
    // (*H. pylori* `Hpy_23S_fw`, `23S ExoSAP_MN23SVDFn`), while every mycobacterial rrl read
    // also names one of the primers above.
    if any_tok(&|t| {
        t.starts_with("rrl")
            || t.starts_with("mclr")
            || t.starts_with("mcrl")
            || t == "clr"
            || ((t.starts_with("sp1") || t.starts_with("sp2")) && no_digit_at(t, 3))
    }) {
        return Some(Ab1Gene::Rrl);
    }

    if any_tok(&|t| t.starts_with("pnca")) {
        return Some(Ab1Gene::PncA);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::Ab1Gene::*;
    use super::*;

    const NTM: Option<Ab1Gene> = Some(RpoB(RpoBRegion::Ntm));

    #[track_caller]
    fn check(name: &str, id: &str, gene: Option<Ab1Gene>) {
        let (got_id, got_gene) = parse_ab1_filename(name);
        assert_eq!(got_id, id, "sample id of {name:?}");
        assert_eq!(got_gene, gene, "gene of {name:?}");
    }

    #[test]
    fn lab_numbers() {
        check(
            "2014500121_clr_mclr_21r_2014-08-04_12-04-17_H05.ab1",
            "2014500121",
            Some(Rrl),
        );
        check("2010_500249_rpoB.ab1", "2010500249", NTM);
        check("176104-08_rpoB.ab1", "2008176104", NTM);
        check("12345.ab1", "12345", None);
        // Not inside a longer digit run.
        check("120250012345 x.ab1", "120250012345 x", None);
    }

    #[test]
    fn genes_from_docs() {
        check("2025500258 LC1_Mbak14.ab1", "2025500258", Some(Rrs16S));
        check(
            "2026311072 rrl R 2.4.26_MCLR 21R.ab1",
            "2026311072",
            Some(Rrl),
        );
        check(
            "2016339219_rpoB_2573f_2016-09-22_14-50-52_D07.ab1",
            "2016339219",
            NTM,
        );
        check("2025500747 rpoB_rpoB-2573f.ab1", "2025500747", NTM);
    }

    #[test]
    fn rpob_regions() {
        // `81` inside the lab number must not be read as the RRDR marker.
        check("2026338109 rpoB_rpoB-2573f.ab1", "2026338109", NTM);
        check("2025500100 rpoBs.ab1", "2025500100", NTM);
        check("2025500100 rpoB_F.ab1", "2025500100", NTM);
        check("2025500100 rpoB_R.ab1", "2025500100", NTM);
        check("2025500100 rpoB_MycoR2.ab1", "2025500100", NTM);
        for (name, gene) in [
            (
                "2025342747 rpoB 81 r_TR2b.ab1",
                Some(RpoB(RpoBRegion::MtbRrdr)),
            ),
            ("2023186001_TR1_x.ab1", Some(RpoB(RpoBRegion::MtbRrdr))),
            (
                "2025500100 rpoB_R_TR2b.ab1",
                Some(RpoB(RpoBRegion::MtbRrdr)),
            ),
            ("2025500100 rpoBc.ab1", Some(RpoB(RpoBRegion::MtbRrdr))),
            ("2025500100 Tb176-r.ab1", Some(RpoB(RpoBRegion::Mtb5Prime))),
            ("2025500100 rpoB-F2.ab1", Some(RpoB(RpoBRegion::MtbXpert))),
            (
                "2025500100 rpoB_GeneXpert.ab1",
                Some(RpoB(RpoBRegion::MtbXpert)),
            ),
            ("2025500100 rpoB_MAB_F.ab1", None),
            ("2025500100 M.marinum_RPO_F.ab1", None),
            ("2025500100 rpoB-univ-FW.ab1", None),
        ] {
            assert_eq!(parse_ab1_filename(name).1, gene, "gene of {name:?}");
        }
        assert_eq!(RpoB(RpoBRegion::Ntm).label(), "rpoB");
        assert_eq!(RpoB(RpoBRegion::MtbRrdr).label(), "rpoB RRDR");
    }

    #[test]
    fn other_genes() {
        let id = "2025500100";
        for (marker, gene) in [
            ("erm41f2", Some(Erm41)),
            ("erm(41)", Some(Erm41)),
            ("erm 41", Some(Erm41)),
            ("ermpromfor", Some(Erm41)),
            ("erm39_CME-1Y", None),
            ("TB-12w", Some(Hsp65)),
            ("TB-11", Some(Hsp65)),
            ("65kDa", Some(Hsp65)),
            ("hsp65", Some(Hsp65)),
            ("Mbak259r", Some(Rrs16S)),
            ("Mbak-14", Some(Rrs16S)),
            ("Bact-1098s", Some(Rrs3End)),
            ("rrs_#289", Some(RrsMtb)),
            ("#261", Some(RrsMtb)),
            ("rrs_261", Some(RrsMtb)),
            ("rrs289", Some(RrsMtb)),
            ("rrs", Some(Rrs3End)),
            ("289", None),
            ("SP2 R mod", Some(Rrl)),
            ("SP1 F", Some(Rrl)),
            ("23S", None),
            ("MCRL 21R", Some(Rrl)),
            ("16-23S-ITS-1f", None),
            ("pncA-Ber-fw", Some(PncA)),
            ("LC3", None),
        ] {
            check(&format!("{id} {marker}.ab1"), id, gene);
        }
    }

    /// Real file names from the routine Sanger archive ("Sequenzen MOL Routine", 2006–2026).
    #[test]
    fn routine_corpus() {
        const RRDR: Option<Ab1Gene> = Some(RpoB(RpoBRegion::MtbRrdr));
        for (name, id, gene) in [
            // Non-mycobacterial 23S reads must not get the rrl analysis.
            ("2026125196 Hp Mak_Hpy_23S_fw.ab1", "2026125196", None),
            ("2024128865 HP 23S 10ul_Hpy_23S_rev.ab1", "2024128865", None),
            ("2026126327 Hp Mak_Hpy-23S-rev.ab1", "2026126327", None),
            ("2023124106 23S ExoSAP_MN23SVDFn.ab1", "2023124106", None),
            // Mycobacterial rrl.
            ("rrl_mcrl21f.ab1", "rrl_mcrl21f", Some(Rrl)),
            ("2014500121 clr f_mclr19f.ab1", "2014500121", Some(Rrl)),
            ("2024500100 rrl-r_SP2 R mod.ab1", "2024500100", Some(Rrl)),
            // rpoB regions.
            ("2023341228rpoB_rpoB-2573f.ab1", "2023341228", NTM),
            ("2023333227_rpoBS_3337r.ab1", "2023333227", NTM),
            ("2022340459_rpoB_10uL_r.ab1", "2022340459", NTM),
            (
                "2024340653 rpoB-81 coreregion f_TR1.ab1",
                "2024340653",
                RRDR,
            ),
            ("2024340653 rpoB 81bp 10ul_TR2b r.ab1", "2024340653", RRDR),
            (
                "2024500100 rpoB-5 f_Tb176-f.ab1",
                "2024500100",
                Some(RpoB(RpoBRegion::Mtb5Prime)),
            ),
            ("2019430890 Strep rpoB_rpoB-univ-FW.ab1", "2019430890", None),
            // Other mycobacterial genes.
            (
                "2023334476_16S_Bact_1098s_2023-02-23_14-57-15_H10.ab1",
                "2023334476",
                Some(Rrs3End),
            ),
            (
                "2024336969 16S rRNA 3'End_Bact-1098s.ab1",
                "2024336969",
                Some(Rrs3End),
            ),
            ("2023 335278 MTB A9_Mbak14.ab1", "2023335278", Some(Rrs16S)),
            (
                "176797_12w_hsp65_2010-03-19_16-38-37_E06.ab1",
                "176797_12w_hsp65_2010-03-19_16-38-37_E06",
                Some(Hsp65),
            ),
            (
                "202300268 65kDa_Tb11.ab1",
                "202300268 65kDa_Tb11",
                Some(Hsp65),
            ),
            (
                "ATCC_19977_erm41_f2_2023-01-27_11-50-48_E04.ab1",
                "ATCC_19977_erm41_f2_2023-01-27_11-50-48_E04",
                Some(Erm41),
            ),
            (
                "QCCH_2023_1_500010_PZA100_pncA_F_2023-01-26_16-40-03_F03.ab1",
                "QCCH_2023_1_500010_PZA100_pncA_F_2023-01-26_16-40-03_F03",
                Some(PncA),
            ),
            // Assays without an analysis.
            ("2026500201 inhA_inhA-rev.ab1", "2026500201", None),
            ("2024500589 katG r_katG_core_rev.ab1", "2024500589", None),
            ("2015179546 embB_embB-1r.ab1", "2015179546", None),
            ("2026316065 K_Bak11w.ab1", "2026316065", None),
            ("2023 121980 Eub_DPO-F.ab1", "2023121980", None),
            ("2026120645 Hp -gyrA_gyrA-fw.ab1", "2026120645", None),
        ] {
            check(name, id, gene);
        }
    }
}
