//! PDF alignment of *M. kansasii*-complex reads against the complex's reference strains.
//!
//! Rust counterpart of `sanger-microsynth/sanger_ms/refalign.py::write_pdf`. That script aligns
//! the read to one full GTDB genome per species; cosmic-files has no genomes, so the rows come
//! from the GTDB amplicon hits already stored in each record (`SeqIdHit::aligned_query` /
//! `aligned_ref`), projected onto the read's coordinates. One section per read: closest species
//! and call, a pairwise difference matrix (upper triangle = differences, lower = % identity) and
//! the read-anchored alignment in blocks of 80 bases with differences from the closest
//! reference shaded.

use printpdf::path::{PaintMode, WindingOrder};
use printpdf::{
    BuiltinFont, Color, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference,
    Point, Polygon, Rgb,
};

use super::batch::SampleSusceptibilityRecord;
use super::{species_group, RefSource, SeqIdHit};

/// Species group label whose reads get an alignment.
const COMPLEX: &str = "M. kansasii complex";
/// Display order of the complex's species; others follow alphabetically.
const SPECIES_ORDER: [&str; 7] = [
    "kansasii",
    "persicum",
    "pseudokansasii",
    "attenuatum",
    "innocens",
    "ostraviense",
    "gastri",
];
/// Same thresholds as `refalign.py::ReadResult` (`min_identity`, `min_margin`).
const MIN_IDENTITY: f64 = 0.98;
const MIN_MARGIN: usize = 2;
const BLOCK: usize = 80;

const PAGE_W: f32 = 297.0;
const PAGE_H: f32 = 210.0;
const MARGIN: f32 = 10.0;
const FONT_PT: f32 = 6.5;
/// Advance width of one Courier character in mm (0.6 em).
const CHAR_W: f32 = FONT_PT * 0.6 * 0.352_778;
const LINE_H: f32 = 3.0;
const LABEL_CHARS: usize = 36;

/// One row of the alignment: a reference strain laid over the read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RefRow {
    label: String,
    species: String,
    /// Reference base per read position (`-` = gap/not covered, `N` = ambiguous).
    cols: Vec<u8>,
    diffs: usize,
    compared: usize,
}

impl RefRow {
    fn identity(&self) -> f64 {
        if self.compared == 0 {
            0.0
        } else {
            1.0 - self.diffs as f64 / self.compared as f64
        }
    }
}

/// A read with its per-species reference rows, best first.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadAlignment {
    read: Vec<u8>,
    /// Best row per species, sorted best (fewest differences per compared base) first.
    by_quality: Vec<RefRow>,
}

impl ReadAlignment {
    fn status(&self) -> &'static str {
        let Some(best) = self.by_quality.first() else {
            return "no_hit";
        };
        if best.identity() < MIN_IDENTITY {
            return "divergent";
        }
        match self.runner_up() {
            Some(r) if r.diffs.saturating_sub(best.diffs) < MIN_MARGIN => "ambiguous",
            _ => "ok",
        }
    }

    /// Best row of a species other than the closest.
    fn runner_up(&self) -> Option<&RefRow> {
        let best = self.by_quality.first()?;
        self.by_quality.iter().skip(1).find(|r| r.species != best.species)
    }

    /// Rows in display order (species order), the closest one's index, for the figure.
    fn display_rows(&self) -> (Vec<&RefRow>, usize) {
        let mut rows: Vec<&RefRow> = self.by_quality.iter().collect();
        rows.sort_by_key(|r| {
            (
                SPECIES_ORDER
                    .iter()
                    .position(|s| *s == r.species)
                    .unwrap_or(SPECIES_ORDER.len()),
                r.species.clone(),
            )
        });
        let best_species = &self.by_quality[0].species;
        let best = rows.iter().position(|r| &r.species == best_species).unwrap_or(0);
        (rows, best)
    }
}

fn complement(b: u8) -> u8 {
    match b {
        b'A' => b'T',
        b'T' => b'A',
        b'C' => b'G',
        b'G' => b'C',
        other => other,
    }
}

fn revcomp(s: &[u8]) -> Vec<u8> {
    s.iter().rev().map(|&b| complement(b)).collect()
}

fn is_base(b: u8) -> bool {
    matches!(b, b'A' | b'C' | b'G' | b'T')
}

/// `(differences, compared columns)` over columns where both have an ACGT base.
fn diff(a: &[u8], b: &[u8]) -> (usize, usize) {
    let mut d = 0;
    let mut m = 0;
    for (&x, &y) in a.iter().zip(b) {
        if is_base(x) && is_base(y) {
            m += 1;
            d += usize::from(x != y);
        }
    }
    (d, m)
}

fn epithet(description: &str) -> String {
    description
        .split_whitespace()
        .nth(1)
        .unwrap_or("unknown")
        .to_string()
}

/// Projects the GTDB complex hits of a record onto the read's coordinates, or `None` if the
/// record has none.
fn align_record(rec: &SampleSusceptibilityRecord) -> Option<ReadAlignment> {
    let hits: Vec<&SeqIdHit> = rec
        .seq_id_hits
        .iter()
        .filter(|h| {
            h.source == RefSource::Gtdb && species_group(&h.description) == Some(COMPLEX)
        })
        .collect();
    let top = hits.iter().max_by(|a, b| a.identity.total_cmp(&b.identity))?;
    let strand = top.is_reverse;

    // All hits in the orientation of the best one (the gapped rows reverse-complement as a pair).
    let oriented: Vec<(&SeqIdHit, Vec<u8>, Vec<u8>)> = hits
        .iter()
        .map(|&h| {
            let q = h.aligned_query.to_ascii_uppercase();
            let r = h.aligned_ref.to_ascii_uppercase();
            if h.is_reverse == strand {
                (h, q, r)
            } else {
                (h, revcomp(&q), revcomp(&r))
            }
        })
        .collect();
    let ungap = |q: &[u8]| q.iter().copied().filter(|&b| b != b'-').collect::<Vec<u8>>();
    // The longest aligned span is the read; the others are placed inside it.
    let read = oriented.iter().map(|(_, q, _)| ungap(q)).max_by_key(Vec::len)?;
    if read.is_empty() {
        return None;
    }

    let mut best_per_species: Vec<RefRow> = Vec::new();
    for (hit, q, r) in &oriented {
        let uq = ungap(q);
        if uq.is_empty() {
            continue;
        }
        let Some(offset) = read.windows(uq.len()).position(|w| w == uq.as_slice()) else {
            continue;
        };
        let mut cols = vec![b'-'; read.len()];
        let mut qi = 0;
        for (&qb, &rb) in q.iter().zip(r) {
            if qb == b'-' {
                continue;
            }
            cols[offset + qi] = if is_base(rb) || rb == b'-' { rb } else { b'N' };
            qi += 1;
        }
        let (diffs, compared) = diff(&read, &cols);
        let species = epithet(&hit.description);
        let accession = hit.accession.split('|').next().unwrap_or(&hit.accession);
        let row = RefRow {
            label: format!("M. {species} {accession}"),
            species,
            cols,
            diffs,
            compared,
        };
        match best_per_species.iter_mut().find(|x| x.species == row.species) {
            Some(existing) => {
                if quality_key(&row) < quality_key(existing) {
                    *existing = row;
                }
            }
            None => best_per_species.push(row),
        }
    }
    if best_per_species.is_empty() {
        return None;
    }
    best_per_species.sort_by(|a, b| quality_key(a).total_cmp_pair(&quality_key(b)));
    Some(ReadAlignment {
        read,
        by_quality: best_per_species,
    })
}

/// Sort key: differences per compared base, then more compared columns first.
fn quality_key(r: &RefRow) -> Quality {
    Quality(
        if r.compared == 0 {
            f64::INFINITY
        } else {
            r.diffs as f64 / r.compared as f64
        },
        -(i64::try_from(r.compared).unwrap_or(0)),
    )
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Quality(f64, i64);

impl PartialOrd for Quality {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.total_cmp_pair(other))
    }
}

impl Quality {
    fn total_cmp_pair(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0).then(self.1.cmp(&other.1))
    }
}

/// Builds the alignment PDF for every kansasii-complex record, or `None` if there is none.
pub fn build_kansasii_alignment_pdf(records: &[&SampleSusceptibilityRecord]) -> Option<Vec<u8>> {
    let sections: Vec<(&SampleSusceptibilityRecord, ReadAlignment)> = records
        .iter()
        .filter_map(|&r| align_record(r).map(|a| (r, a)))
        .collect();
    if sections.is_empty() {
        return None;
    }

    let (doc, page, layer) = PdfDocument::new(
        "Kansasii complex alignment",
        Mm(PAGE_W),
        Mm(PAGE_H),
        "Layer 1",
    );
    let mut pdf = Pdf {
        font: doc.add_builtin_font(BuiltinFont::Courier).ok()?,
        bold: doc.add_builtin_font(BuiltinFont::CourierBold).ok()?,
        sans: doc.add_builtin_font(BuiltinFont::Helvetica).ok()?,
        sans_bold: doc.add_builtin_font(BuiltinFont::HelveticaBold).ok()?,
        layer: doc.get_page(page).get_layer(layer),
        doc,
        y: MARGIN,
        pages: 1,
    };
    for (i, (rec, aln)) in sections.iter().enumerate() {
        if i > 0 {
            pdf.new_page();
        }
        draw_section(&mut pdf, rec, aln);
    }
    pdf.doc.save_to_bytes().ok()
}

struct Pdf {
    doc: PdfDocumentReference,
    layer: PdfLayerReference,
    font: IndirectFontRef,
    bold: IndirectFontRef,
    sans: IndirectFontRef,
    sans_bold: IndirectFontRef,
    /// Current y from the top of the page, mm.
    y: f32,
    pages: usize,
}

impl Pdf {
    fn new_page(&mut self) {
        self.pages += 1;
        let (page, layer) = self
            .doc
            .add_page(Mm(PAGE_W), Mm(PAGE_H), format!("Layer {}", self.pages));
        self.layer = self.doc.get_page(page).get_layer(layer);
        self.y = MARGIN;
    }

    fn set_fill(&self, rgb: (f32, f32, f32)) {
        self.layer
            .set_fill_color(Color::Rgb(Rgb::new(rgb.0, rgb.1, rgb.2, None)));
    }

    /// Text with its top at `y_top` mm from the page top.
    fn text(&self, s: &str, size: f32, x: f32, y_top: f32, font: &IndirectFontRef) {
        self.set_fill((0.0, 0.0, 0.0));
        self.layer
            .use_text(s, size, Mm(x), Mm(PAGE_H - y_top - size * 0.352_778), font);
    }

    fn rect(&self, x: f32, y_top: f32, w: f32, h: f32, rgb: (f32, f32, f32)) {
        self.set_fill(rgb);
        let y0 = PAGE_H - y_top - h;
        let pts = vec![
            (Point::new(Mm(x), Mm(y0)), false),
            (Point::new(Mm(x + w), Mm(y0)), false),
            (Point::new(Mm(x + w), Mm(y0 + h)), false),
            (Point::new(Mm(x), Mm(y0 + h)), false),
        ];
        self.layer.add_polygon(Polygon {
            rings: vec![pts],
            mode: PaintMode::Fill,
            winding_order: WindingOrder::NonZero,
        });
    }
}

fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((cut, _)) => format!("{}..", &s[..cut]),
        None => s.to_string(),
    }
}

fn ascii(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}

fn draw_section(pdf: &mut Pdf, rec: &SampleSusceptibilityRecord, aln: &ReadAlignment) {
    let (rows, best) = aln.display_rows();
    let closest = &aln.by_quality[0];
    pdf.text(
        &format!(
            "{} ({}): alignment to the kansasii-complex reference strains",
            rec.sample_id,
            truncate(&rec.file_name, 60)
        ),
        11.0,
        MARGIN,
        pdf.y,
        &pdf.sans_bold,
    );
    pdf.y += 7.0;
    let mut verdict = format!(
        "Closest of {} species: M. {} ({}), {:.2}% identity ({} of {} positions differ)",
        aln.by_quality.len(),
        closest.species,
        closest.label.rsplit(' ').next().unwrap_or(""),
        closest.identity() * 100.0,
        closest.diffs,
        closest.compared
    );
    if let Some(r) = aln.runner_up() {
        verdict += &format!(
            "; next species: M. {} {:.2}% ({})",
            r.species,
            r.identity() * 100.0,
            r.diffs
        );
    }
    verdict += &format!(
        ". Call: {} (needs >= {:.0}% and >= {MIN_MARGIN} fewer differences than the next species).",
        aln.status(),
        MIN_IDENTITY * 100.0
    );
    pdf.text(&verdict, 7.5, MARGIN, pdf.y, &pdf.sans);
    pdf.y += 8.0;

    // Difference matrix: upper triangle = differences, lower = % identity.
    let read_name = rec.sample_id.as_str();
    let mut names: Vec<String> = rows.iter().map(|r| r.label.clone()).collect();
    names.push(read_name.to_string());
    let mut seqs: Vec<&[u8]> = rows.iter().map(|r| r.cols.as_slice()).collect();
    seqs.push(aln.read.as_slice());
    let n = seqs.len();
    let label_w = 62.0;
    let cell_w = 13.0;
    let cell_h = 3.6;
    let mx = MARGIN + label_w + 6.0;
    let mut dmat = vec![vec![(0usize, 0usize); n]; n];
    let mut vmax = 1usize;
    let mut lo_id = 100.0_f64;
    for i in 0..n {
        for j in 0..n {
            if i != j {
                dmat[i][j] = diff(seqs[i], seqs[j]);
                vmax = vmax.max(dmat[i][j].0);
                if dmat[i][j].1 > 0 {
                    lo_id = lo_id.min(100.0 * (1.0 - dmat[i][j].0 as f64 / dmat[i][j].1 as f64));
                }
            }
        }
    }
    for j in 0..n {
        pdf.rect(mx + j as f32 * cell_w, pdf.y, cell_w - 0.6, cell_h, (0.82, 0.84, 0.87));
        pdf.text(&(j + 1).to_string(), 6.5, mx + j as f32 * cell_w + 4.5, pdf.y + 0.5, &pdf.sans);
    }
    pdf.y += cell_h + 0.4;
    for i in 0..n {
        let bold = i == best || i == n - 1;
        pdf.text(
            &format!("{} {}", i + 1, truncate(&names[i], 50)),
            6.5,
            MARGIN,
            pdf.y + 0.5,
            if bold { &pdf.sans_bold } else { &pdf.sans },
        );
        for (j, &(d, m)) in dmat[i].iter().enumerate() {
            if i == j {
                continue;
            }
            let (rgb, txt) = if j > i {
                let a = d as f32 / vmax as f32;
                ((1.0, 1.0 - 0.55 * a, 1.0 - 0.55 * a), d.to_string())
            } else if m > 0 {
                let id = 100.0 * (1.0 - d as f64 / m as f64);
                let a = ((100.0 - id) / (100.0 - lo_id).max(1e-9)) as f32;
                ((1.0 - 0.5 * a, 1.0 - 0.5 * a, 1.0), format!("{id:.2}"))
            } else {
                ((1.0, 1.0, 1.0), String::new())
            };
            pdf.rect(mx + j as f32 * cell_w, pdf.y, cell_w - 0.6, cell_h - 0.4, rgb);
            pdf.text(&txt, 6.0, mx + j as f32 * cell_w + 2.0, pdf.y + 0.5, &pdf.sans);
        }
        pdf.y += cell_h;
    }
    pdf.text(
        &format!(
            "upper: differences, lower: % identity; shaded bases below differ from {}",
            names[best]
        ),
        6.0,
        MARGIN,
        pdf.y + 1.0,
        &pdf.sans,
    );
    pdf.y += 8.0;

    // Alignment blocks anchored on the read.
    let x0 = MARGIN + LABEL_CHARS as f32 * CHAR_W + 3.0;
    let len = aln.read.len();
    for b0 in (0..len).step_by(BLOCK) {
        let need = LINE_H * (n as f32 + 2.5);
        if pdf.y + need > PAGE_H - MARGIN {
            pdf.new_page();
        }
        let b1 = (b0 + BLOCK).min(len);
        for p in b0..b1 {
            if (p + 1) % 20 == 0 {
                let x = x0 + ((p - b0) + (p - b0) / 10) as f32 * CHAR_W;
                pdf.text(&(p + 1).to_string(), 5.0, x, pdf.y, &pdf.sans);
            }
        }
        pdf.y += 2.5;
        for (r, s) in seqs.iter().enumerate() {
            let yy = pdf.y + r as f32 * LINE_H;
            let bold = r == best || r == n - 1;
            pdf.text(
                &truncate(&names[r], LABEL_CHARS),
                FONT_PT,
                MARGIN,
                yy,
                if bold { &pdf.bold } else { &pdf.font },
            );
            let seg = &s[b0..b1];
            for (k, &ch) in seg.iter().enumerate() {
                let reference = seqs[best][b0 + k];
                if r != best && is_base(ch) && is_base(reference) && ch != reference {
                    pdf.rect(
                        x0 + (k + k / 10) as f32 * CHAR_W,
                        yy,
                        CHAR_W,
                        LINE_H - 0.4,
                        (0.96, 0.65, 0.65),
                    );
                }
            }
            let grouped = seg
                .chunks(10)
                .map(ascii)
                .collect::<Vec<_>>()
                .join(" ");
            pdf.text(&grouped, FONT_PT, x0, yy, &pdf.font);
            pdf.text(
                &b1.to_string(),
                FONT_PT,
                x0 + (seg.len() + seg.len() / 10) as f32 * CHAR_W + 2.0,
                yy,
                &pdf.font,
            );
        }
        pdf.y += LINE_H * (n as f32 + 1.4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sequencing::batch::{SampleSusceptibilityRecord, ANALYSIS_VERSION};
    use crate::sequencing::SusceptibilityCalls;

    fn hit(desc: &str, source: RefSource, ident: f32, q: &[u8], r: &[u8]) -> SeqIdHit {
        SeqIdHit {
            accession: "GCF_1.1|amplicon|1".to_string(),
            description: desc.to_string(),
            source,
            identity: ident,
            is_reverse: false,
            rrl_snp_calls: Vec::new(),
            rrs_snp_calls: Vec::new(),
            rrs_snp_calls_3end: Vec::new(),
            rrs_mtb_snp_calls: Vec::new(),
            rrl_mtb_snp_calls: Vec::new(),
            erm41_snp_calls: Vec::new(),
            pnca_snp_calls: Vec::new(),
            rpob_snp_calls: Vec::new(),
            aligned_query: q.to_vec(),
            aligned_ref: r.to_vec(),
            ref_start: 0,
            erm41_position_28_opt: None,
            rrs3end_position_1248_opt: None,
            rrl_position_2058_2059_opt: None,
        }
    }

    fn record(hits: Vec<SeqIdHit>) -> SampleSusceptibilityRecord {
        SampleSusceptibilityRecord {
            sample_id: "24-000001".to_string(),
            gene: Some("16S".to_string()),
            file_name: "24-000001-16S.ab1".to_string(),
            file_path: "24-000001-16S.ab1".into(),
            file_created: None,
            susceptibility_calls: SusceptibilityCalls::default(),
            species: None,
            identity: None,
            species_gtdb: None,
            identity_gtdb: None,
            is_susceptible: None,
            seq_id_hits: hits,
            analysis_version: ANALYSIS_VERSION,
        }
    }

    #[test]
    fn projects_hits_onto_read_with_gaps_and_offsets() {
        let rec = record(vec![
            // Full read ACGTACGTAC; kansasii differs at read position 3 (T vs A).
            hit("Mycobacterium kansasii", RefSource::Gtdb, 99.0, b"ACGTACGTAC", b"ACGAACGTAC"),
            // Shorter span (read positions 2..8) with a deletion in the reference.
            hit("Mycobacterium persicum", RefSource::Gtdb, 97.0, b"GTACGT", b"GT-CGT"),
        ]);
        let aln = align_record(&rec).unwrap();
        assert_eq!(aln.read, b"ACGTACGTAC");
        let persicum = aln.by_quality.iter().find(|r| r.species == "persicum").unwrap();
        assert_eq!(persicum.cols, b"--GT-CGT--");
        let kansasii = aln.by_quality.iter().find(|r| r.species == "kansasii").unwrap();
        assert_eq!((kansasii.diffs, kansasii.compared), (1, 10));
        assert_eq!(aln.by_quality[0].species, "persicum");
    }

    #[test]
    fn ignores_ncbi_and_non_complex_hits() {
        let rec = record(vec![
            hit("Mycobacterium kansasii", RefSource::Ncbi, 99.0, b"ACGT", b"ACGT"),
            hit("Mycobacterium tuberculosis", RefSource::Gtdb, 99.0, b"ACGT", b"ACGT"),
        ]);
        assert!(align_record(&rec).is_none());
        assert!(build_kansasii_alignment_pdf(&[&rec]).is_none());
    }

    #[test]
    fn builds_a_pdf_for_a_kansasii_complex_read() {
        let rec = record(vec![
            hit("Mycobacterium kansasii", RefSource::Gtdb, 99.0, b"ACGTACGTAC", b"ACGAACGTAC"),
            hit("Mycobacterium persicum", RefSource::Gtdb, 97.0, b"ACGTACGTAC", b"ACGTACGAAC"),
        ]);
        let pdf = build_kansasii_alignment_pdf(&[&rec]).unwrap();
        assert!(pdf.starts_with(b"%PDF"));
    }

    #[test]
    fn reverse_hits_are_oriented_like_the_best_hit() {
        let mut rev = hit("Mycobacterium persicum", RefSource::Gtdb, 90.0, b"GTACGT", b"GTACGT");
        rev.is_reverse = true; // revcomp(GTACGT) = ACGTAC
        let rec = record(vec![
            hit("Mycobacterium kansasii", RefSource::Gtdb, 99.0, b"ACGTACGTAC", b"ACGTACGTAC"),
            rev,
        ]);
        let aln = align_record(&rec).unwrap();
        let persicum = aln.by_quality.iter().find(|r| r.species == "persicum").unwrap();
        assert_eq!(persicum.cols, b"ACGTAC----");
    }

    #[test]
    fn status_follows_identity_and_margin() {
        let row = |sp: &str, diffs| RefRow {
            label: sp.into(),
            species: sp.into(),
            cols: Vec::new(),
            diffs,
            compared: 100,
        };
        let aln = |a, b| ReadAlignment {
            read: Vec::new(),
            by_quality: vec![row("kansasii", a), row("persicum", b)],
        };
        assert_eq!(aln(0, 5).status(), "ok");
        assert_eq!(aln(1, 2).status(), "ambiguous");
        assert_eq!(aln(5, 9).status(), "divergent");
    }
}
