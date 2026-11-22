//! TB Profiler / AB1 sequencing extensions to [`Item`]: species & resistance calls,
//! per-gene preview panes and the chromatogram canvas.

use cosmic::iced::{Color, Length, Point, Rectangle};
use cosmic::{Element, cosmic_theme, theme, widget};
use std::borrow::Cow;
use std::path::Path;

use super::{Item, ItemMetadata};
use crate::fl;
use crate::location::Location;
use crate::sequencing::batch::{Ab1Gene, RpoBRegion, parse_ab1_filename};
use crate::sequencing::rrs3end::Rrs3EndPosition1248;
use crate::sequencing::{
    Ab1Channels, Ab1Read, RefSource, SeqData, SeqIdHit, SusceptibilityCalls, best_snp_hit,
    hits_from, parse_ab1_quality, parse_ab1_sequence,
    tb_data::{DrVariant, TB_ECOLI_MAPPING},
    trim_to_min_quality,
};
use crate::tab::Message;

/// [`SeqData`] for a listed AB1 file without reading it: only the alignment hits already in
/// [`AB1_SEQ_CACHE`](crate::sequencing::batch::AB1_SEQ_CACHE) for the file as `metadata`
/// describes it (a memory lookup). The file itself is read by [`read_ab1`] when the preview
/// needs it.
pub(super) fn cached_seq_data(path: &Path, metadata: &std::fs::Metadata) -> SeqData {
    let seq_id_hits = crate::sequencing::batch::cached_hits(path, metadata).unwrap_or_default();
    SeqData {
        read_opt: None,
        seq_id_hits,
    }
}

/// Parses an AB1 file's bytes for the preview: chromatogram, basecall length and
/// quality-trimmed length/quality. Blocking work: call from a worker thread.
pub fn read_ab1(path: &Path, bytes: &[u8]) -> Ab1Read {
    let ab1_seq = parse_ab1_sequence(bytes);
    let ab1_qual = parse_ab1_quality(bytes);
    let (length, trimmed_length, trimmed_avg_quality_opt) = if let Some(seq) = ab1_seq.as_ref() {
        let length = seq.len();
        let trimmed: &[u8] = match &ab1_qual {
            Some(qual) => match trim_to_min_quality(seq, qual, 20) {
                Some(trimmed) => {
                    let removed = seq.len() - trimmed.len();
                    if removed > 0 {
                        log::info!(
                            "{}: quality trimming removed {} of {} bases",
                            path.display(),
                            removed,
                            seq.len()
                        );
                    } else {
                        log::info!(
                            "{}: quality trimming removed no bases, using full sequence",
                            path.display()
                        );
                    }
                    trimmed
                }
                None => {
                    log::warn!(
                        "{}: quality trimming found no bases above threshold, using full sequence",
                        path.display()
                    );
                    seq.as_slice()
                }
            },
            None => seq.as_slice(),
        };
        let trimmed_length = trimmed.len();
        let trimmed_avg_quality_opt =
            ab1_qual
                .as_ref()
                .filter(|_| trimmed_length > 0)
                .map(|qual| {
                    let start = trimmed.as_ptr() as usize - seq.as_ptr() as usize;
                    let sum: u32 = qual[start..start + trimmed_length]
                        .iter()
                        .map(|&q| q as u32)
                        .sum();
                    sum as f32 / trimmed_length as f32
                });
        (length, trimmed_length, trimmed_avg_quality_opt)
    } else {
        (0, 0, None)
    };
    let chromatogram_opt = Ab1Channels::from_bytes(bytes);
    Ab1Read {
        chromatogram_opt,
        length,
        trimmed_length,
        trimmed_avg_quality_opt,
    }
}

type Details<'a> = widget::Column<'a, Message, cosmic::Theme>;

/// Text shown where a chromatogram would be: still loading (the preview reads the file on a
/// worker thread) or not available for this read.
fn chromatogram_placeholder(metadata: &ItemMetadata, gene: &str) -> String {
    if metadata.ab1_read_loaded() {
        format!("{gene} chromatogram view is not available.")
    } else {
        "Loading chromatogram…".to_string()
    }
}

/// Pushes one species-call line per reference source in `sources`, e.g.
/// `16S (NCBI): M. kansasii complex`. `species_for` gives the call of a source (`None`: no
/// species identified).
fn push_species_calls<'a>(
    mut details: Details<'a>,
    gene: &str,
    sources: &[RefSource],
    species_for: impl Fn(RefSource) -> Option<String>,
) -> Details<'a> {
    details = details.push(widget::text::body(""));
    for &source in sources {
        let label = source.label();
        details = details.push(widget::text::heading(match species_for(source) {
            Some(species) => format!("{gene} ({label}): {species}"),
            None => format!("{gene} ({label}): No species identified from {gene} hits."),
        }));
    }
    details
}

/// Pushes the species-identification section of one reference source: heading, best-hit
/// identity, and the top `max` hits as links to their alignments. Sources without hits (no
/// references of that source for this target, e.g. NCBI for hsp65) are left out.
fn push_source_section<'a>(
    mut details: Details<'a>,
    hits: &[SeqIdHit],
    source: RefSource,
    gene: &str,
    max: usize,
) -> Details<'a> {
    let hits = hits_from(hits, source);
    let Some(best) = hits.first() else {
        return details;
    };
    details = details.push(widget::text::heading(""));
    details = details.push(widget::text::heading(format!(
        "Species identification ({gene}, {} database):",
        source.label()
    )));
    details = details.push(widget::text::body(format!(
        "Sequence identity to {}: {:.1}%",
        best.description, best.identity
    )));
    for hit in hits.iter().take(max) {
        details = details.push(
            widget::button::link(format!("{} ({:.1}%)", hit.description, hit.identity))
                .on_press(Message::OpenSeqAlignment(Box::new((*hit).clone())))
                .padding(0),
        );
    }
    details
}

/// Combined susceptibility verdict and per-gene calls for an AB1 file's alignment hits.
///
/// The same function the batch scan uses
/// ([`susceptibility_from_hits`](crate::sequencing::batch::susceptibility_from_hits)), so the
/// preview and the report always agree.
pub fn ab1_susceptibility(hits: &[SeqIdHit]) -> (Option<bool>, SusceptibilityCalls) {
    crate::sequencing::batch::susceptibility_from_hits(hits)
}

impl Item {
    /// Returns seq_id_hits for preview, falling back to `AB1_SEQ_CACHE` when the item was
    /// created before the background scan ran (empty stored hits).
    ///
    /// Called from `view`, so the common case (hits stored on the item) borrows instead of
    /// cloning every hit and its alignment strings.
    pub fn seq_id_hits_cached(&self) -> Cow<'_, [SeqIdHit]> {
        let stored = self.metadata.seq_id_hits();
        if !stored.is_empty() {
            return Cow::Borrowed(stored);
        }
        let result = self.ab1_cached_hits().unwrap_or_default();
        log::trace!(
            "seq_id_hits_cached({}): {} hits from AB1_SEQ_CACHE",
            self.name,
            result.len()
        );
        Cow::Owned(result)
    }

    /// This item's hits in `AB1_SEQ_CACHE`, if they were computed for the file as listed (same
    /// mtime and size as the item's metadata). No file I/O.
    pub fn ab1_cached_hits(&self) -> Option<Vec<SeqIdHit>> {
        let ItemMetadata::Path { metadata, .. } = &self.metadata else {
            return None;
        };
        crate::sequencing::batch::cached_hits(self.path_opt()?, metadata)
    }

    fn is_fasta(&self) -> bool {
        let lower = self.name.to_ascii_lowercase();
        lower.ends_with(".fasta") || lower.ends_with(".fa")
    }

    /// Gene inferred from the file name by the same parser the batch scan uses, so the preview
    /// shows the analysis the scan ran. FASTA files get no gene preview.
    fn ab1_gene(&self) -> Option<Ab1Gene> {
        if self.is_fasta() {
            None
        } else {
            parse_ab1_filename(&self.name).1
        }
    }

    pub fn is_erm41(&self) -> bool {
        self.ab1_gene() == Some(Ab1Gene::Erm41)
    }

    pub fn is_hsp65(&self) -> bool {
        self.ab1_gene() == Some(Ab1Gene::Hsp65)
    }

    /// rpoB region of this read (NTM species ID or one of the Mtb rifampicin regions), if any.
    pub fn rpob_region(&self) -> Option<RpoBRegion> {
        match self.ab1_gene() {
            Some(Ab1Gene::RpoB(region)) => Some(region),
            _ => None,
        }
    }

    pub fn is_16s(&self) -> bool {
        self.ab1_gene() == Some(Ab1Gene::Rrs16S)
    }

    pub fn is_16s3end(&self) -> bool {
        self.ab1_gene() == Some(Ab1Gene::Rrs3End)
    }

    /// Returns the sample's 16S seq_id_hits, first by looking for a sibling 16S AB1 in the
    /// currently listed `items`, then falling back to the project-wide
    /// [`SIXTEEN_S_HITS_CACHE`](crate::sequencing::batch::SIXTEEN_S_HITS_CACHE) populated by
    /// background `scan_ab1_directory` runs — so the sibling is found even when it lives in a
    /// different directory than the file being previewed.
    fn sibling_16s_hits<'a>(&self, items: &'a [Item]) -> Option<Cow<'a, [SeqIdHit]>> {
        let (sample_id, _) = parse_ab1_filename(&self.name);
        // One filename parse per item (`is_16s` would parse it a second time).
        if let Some(sibling) = items.iter().find(|it| {
            let (id, gene) = parse_ab1_filename(&it.name);
            gene == Some(Ab1Gene::Rrs16S) && id == sample_id && !it.is_fasta()
        }) {
            return Some(sibling.seq_id_hits_cached());
        }
        crate::sequencing::batch::sixteen_s_hits_for_sample(&sample_id).map(Cow::Owned)
    }

    pub fn is_chelonae(&self, items: &[Item]) -> bool {
        let chelonae_abscessus_complex = self
            .sibling_16s_hits(items)
            .and_then(|hits| {
                hits.first().map(|top| {
                    top.description.contains("chelonae") || top.description.contains("abscessus")
                })
            })
            .unwrap_or(false);
        chelonae_abscessus_complex
            && self
                .seq_id_hits_cached()
                .first()
                .is_some_and(|top| top.description.contains("chelonae"))
    }

    pub fn is_marinum(&self, items: &[Item]) -> bool {
        let marinum_ulcerans = self
            .sibling_16s_hits(items)
            .and_then(|hits| {
                hits.first().map(|top| {
                    top.description.contains("marinum") || top.description.contains("ulcerans")
                })
            })
            .unwrap_or(false);
        marinum_ulcerans && self.metadata.rrs3endposition_call() == Rrs3EndPosition1248::A1248
    }

    pub fn is_ulcerans(&self, items: &[Item]) -> bool {
        let marinum_ulcerans = self
            .sibling_16s_hits(items)
            .and_then(|hits| {
                hits.first().map(|top| {
                    top.description.contains("ulcerans") || top.description.contains("marinum")
                })
            })
            .unwrap_or(false);
        marinum_ulcerans && self.metadata.rrs3endposition_call() == Rrs3EndPosition1248::G1248
    }

    /// Species call of the sample's sibling 16S read from the `source` references.
    pub fn species_from_16s_sibling(&self, items: &[Item], source: RefSource) -> Option<String> {
        self.sibling_16s_hits(items).and_then(|hits| {
            crate::sequencing::batch::species_from_16s_hits(&hits_from(&hits, source))
        })
    }

    /// Species call of this rpoB read from the `source` references.
    pub fn species_from_rpob_hits(&self, source: RefSource) -> Option<String> {
        crate::sequencing::batch::species_from_rpob_hits(&hits_from(
            &self.seq_id_hits_cached(),
            source,
        ))
    }

    pub fn is_rrl_ntm(&self) -> bool {
        self.ab1_gene() == Some(Ab1Gene::Rrl)
    }

    pub fn is_pnca(&self) -> bool {
        self.ab1_gene() == Some(Ab1Gene::PncA)
    }

    pub fn preview_tbprofiler_json(&self) -> Element<'_, Message> {
        fn tb_variant_widget(v: &DrVariant) -> Element<'static, Message> {
            widget::container(
                widget::column::with_capacity(3)
                    .push({
                        let mut drug_col = widget::column::with_capacity(v.drugs.len());
                        for drug in &v.drugs {
                            drug_col = drug_col.push(widget::text::body(format!(
                                "{}: {}",
                                drug.drug, drug.confidence
                            )));
                        }
                        drug_col
                    })
                    .push(widget::text::body(format!(
                        "{} ({}): {}",
                        v.gene_name, v.gene_id, v.change
                    )))
                    .push({
                        let mut ecoli_col = widget::column::with_capacity(1);
                        if let Some(ecoli_value) =
                            TB_ECOLI_MAPPING.get(&(v.gene_name.clone(), v.change.clone()))
                        {
                            ecoli_col = ecoli_col
                                .push(widget::text::body(format!("E. coli: {}", ecoli_value)));
                        }
                        ecoli_col
                    }),
            )
            .into()
        }
        let cosmic_theme::Spacing {
            space_xxxs,
            space_m,
            ..
        } = theme::active().cosmic().spacing;
        let tbprofilerjson_opt = match &self.metadata {
            ItemMetadata::Path {
                tbprofilerjson_opt, ..
            } => tbprofilerjson_opt.as_ref(),
            #[cfg(feature = "russh")]
            ItemMetadata::RusshPath {
                tbprofilerjson_opt, ..
            } => tbprofilerjson_opt.as_ref(),
            _ => None,
        };

        let dr_variant_count = tbprofilerjson_opt.map_or(0, |json| json.dr_variants.len());
        let mut column = widget::column::with_capacity(5 + dr_variant_count).spacing(space_m);
        let mut details = widget::column::with_capacity(1).spacing(space_xxxs);
        details = details.push(widget::text::heading(self.name.clone()));

        column = column.push(details);

        #[cfg(feature = "russh")]
        if let ItemMetadata::RusshPath { .. } = &self.metadata
            && self.metadata.is_dir()
        {
            if self.state.selected {
                column = column
                    .push(widget::button::standard(fl!("open")).on_press(Message::Open(None)));
            }
            return column.into();
        }

        if let Some(json) = tbprofilerjson_opt {
            column = column.push(widget::text::heading(format!(
                "DB: {} ({})",
                json.pipeline.db_version.name, json.pipeline.db_version.commit
            )));
            let mut dr_variants = json.dr_variants.clone();
            dr_variants.sort_by_key(|v| v.highest_confidence_rank());
            for v in &dr_variants {
                column = column.push(tb_variant_widget(v));
            }
        }

        if let ItemMetadata::Path { .. } = &self.metadata
            && self.metadata.is_tbprofiler_result_as_sample()
        {
            for (label, opt_path) in [
                ("Open .results.csv", self.metadata.csv_path()),
                ("Open .results.json", self.metadata.json_path()),
                ("Open .results.docx", self.metadata.docx_path()),
            ] {
                if let Some(p) = opt_path {
                    column = column.push(
                        widget::button::standard(label)
                            .on_press(Message::Open(Some(p.to_path_buf()))),
                    );
                }
            }
        }

        #[cfg(feature = "russh")]
        if let ItemMetadata::RusshPath { .. } = &self.metadata {
            if let Some(Location::Remote(uri, _, Some(path))) = &self.location_opt {
                // Runs on every view; keep it out of info-level logs.
                log::trace!(
                    "item is remote, showing download button: {}",
                    path.display()
                );
                if !self.metadata.is_tbprofiler_result_as_sample() {
                    column = column.push(
                        widget::button::standard(fl!("download"))
                            .on_press(Message::Download(Some((path.clone(), uri.clone())))),
                    );
                }
            }
            if let Some(Location::Remote(uri, _, _)) = &self.location_opt
                && self.metadata.is_tbprofiler_result_as_sample()
            {
                for (label, opt_path) in [
                    ("Download .results.csv", self.metadata.csv_path()),
                    ("Download .results.json", self.metadata.json_path()),
                    ("Download .results.docx", self.metadata.docx_path()),
                ] {
                    if let Some(p) = opt_path {
                        column = column.push(
                            widget::button::standard(label)
                                .on_press(Message::Download(Some((p.to_path_buf(), uri.clone())))),
                        );
                    }
                }
            }
        }

        column.into()
    }

    pub fn preview_erm41(&self) -> Element<'_, Message> {
        let cosmic_theme::Spacing {
            space_xxxs,
            space_m,
            ..
        } = theme::active().cosmic().spacing;

        let hits = self.seq_id_hits_cached();
        let erm41_snp_tag_count = hits.first().map_or(0, |best| {
            best.erm41_snp_calls
                .iter()
                .filter(|s| !s.call_tag().is_empty())
                .count()
        });

        let mut column = widget::column::with_capacity(1).spacing(space_m);
        let mut details =
            widget::column::with_capacity(22 + erm41_snp_tag_count).spacing(space_xxxs);
        details = details.push(widget::text::heading("32.43622-erm(41)-Endpunkt-PCR"));

        if hits.is_empty()
            || self
                .metadata
                .sequence_length_trimmed()
                .is_some_and(|n| n < 100)
            || hits
                .first()
                .is_none_or(|h| h.identity < crate::sequencing::MIN_SEQ_ID_IDENTITY)
        {
            details = details.push(widget::text::body(
                "Could not align sequence to references.",
            ));
            if let Some(sequence_length) = self.metadata.sequence_length() {
                details = details.push(widget::text::body(format!(
                    "Sequence length: {}",
                    sequence_length
                )));
            }
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }
        } else {
            let best = &hits[0];
            details = details.push(widget::text::body(format!(
                "Sequence identity to {}: {:.1}%",
                best.description, best.identity
            )));
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }
            details = details.push(widget::text::heading(""));
            details = details.push(widget::text::heading(
                "Percent identity to erm(41) references of abscessus subspecies:",
            ));
            for hit in &hits[..hits.len().min(3)] {
                details = details.push(
                    widget::button::link(format!("{}: {:.1}%", hit.description, hit.identity,))
                        .on_press(Message::OpenSeqAlignment(Box::new(hit.clone())))
                        .padding(0),
                );
            }
            if self.metadata.is_abscessus_seq_id() || self.metadata.is_bolletii_seq_id() {
                let call = self.metadata.erm41position28_call();
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::heading(format!("erm(41) {}", call)));
            }

            details = details.push(widget::text::body(""));
            {
                let snp_tags: Vec<String> = best
                    .erm41_snp_calls
                    .iter()
                    .map(|s| s.call_tag())
                    .filter(|t| !t.is_empty())
                    .collect();
                details = details.push(widget::text::body("erm(41) loss-of-function SNPs:"));
                if snp_tags.is_empty() {
                    details = details.push(widget::text::body("No erm(41) SNPs found."));
                } else {
                    details = details.push(widget::text::body(format!(
                        "(Using commit: {} of ntm-db repository)",
                        env!("NTM_DB_COMMIT")
                    )));
                    for tag in snp_tags {
                        details = details.push(widget::text::body(tag));
                    }
                }
            }

            if let Some(chrom) = self
                .metadata
                .ab1_chromatogram()
                .filter(|c| c.erm41_view_state_opt.is_some())
                && !self.metadata.is_massiliense_seq_id()
            {
                let view_state = chrom.erm41_view_state_opt.unwrap();
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::body(
                    "Shown are bases 19-39, with position 28 in bold.",
                ));
                if view_state.is_reverse {
                    details = details.push(widget::text::body("reverse complement"));
                }
                details = details.push(widget::text::body(""));
                let canvas = widget::Canvas::new(ChromatogramProgram {
                    is_reverse: view_state.is_reverse,
                    display_window: Some(view_state.window),
                    highlighted_scans: chrom
                        .peak_locs
                        .get(view_state.pos28_base_idx as usize)
                        .copied()
                        .map(|v| vec![v])
                        .unwrap_or_default(),
                    chrom,
                })
                .width(Length::Fill)
                .height(Length::Fixed(200.0));
                details = details.push(canvas);
                details = details.push(widget::text::body(""));
            } else {
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::body(chromatogram_placeholder(
                    &self.metadata,
                    "erm(41)",
                )));
                details = details.push(widget::text::body(""));
            }
            match self
                .metadata
                .susceptibility_calls()
                .erm41
                .position_28
                .and_then(|p| p.is_susceptible())
            {
                Some(true) => {
                    details = details.push(widget::text::heading(
                        "Predicted to be susceptible to macrolides.",
                    ))
                }
                Some(false) => {
                    details = details.push(widget::text::heading(
                        "Predicted inducible macrolide resistance.",
                    ))
                }
                None => {}
            }
        }

        column = column.push(details);
        column.into()
    }

    pub fn preview_hsp65(&self, items: &[Item]) -> Element<'_, Message> {
        let cosmic_theme::Spacing {
            space_xxxs,
            space_m,
            ..
        } = theme::active().cosmic().spacing;

        let hits = self.seq_id_hits_cached();

        let mut column = widget::column::with_capacity(1).spacing(space_m);
        let mut details = widget::column::with_capacity(16).spacing(space_xxxs);
        details = details.push(widget::text::heading("32.43505-2-Mykobakterien NTM 65kDa"));

        if hits.is_empty()
            || self
                .metadata
                .sequence_length_trimmed()
                .is_some_and(|n| n < 100)
            || hits
                .first()
                .is_none_or(|h| h.identity < crate::sequencing::MIN_SEQ_ID_IDENTITY)
        {
            details = details.push(widget::text::body(
                "Could not align sequence to references.",
            ));
            if let Some(sequence_length) = self.metadata.sequence_length() {
                details = details.push(widget::text::body(format!(
                    "Sequence length: {}",
                    sequence_length
                )));
            }
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }
        } else {
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }

            details = push_species_calls(details, "16S", &RefSource::ALL, |source| {
                self.species_from_16s_sibling(items, source)
            });

            for source in RefSource::ALL {
                details = push_source_section(details, &hits, source, "hsp65", 3);
            }
        }

        column = column.push(details);
        column.into()
    }

    pub fn preview_rpob(&self, items: &[Item], region: RpoBRegion) -> Element<'_, Message> {
        let cosmic_theme::Spacing {
            space_xxxs,
            space_m,
            ..
        } = theme::active().cosmic().spacing;

        let hits = self.seq_id_hits_cached();

        let mut column = widget::column::with_capacity(1).spacing(space_m);
        let mut details = widget::column::with_capacity(15).spacing(space_xxxs);
        details = details.push(widget::text::heading(region.protocol()));
        if hits.is_empty()
            || self
                .metadata
                .sequence_length_trimmed()
                .is_some_and(|n| n < 100)
            || hits
                .first()
                .is_none_or(|h| h.identity < crate::sequencing::MIN_SEQ_ID_IDENTITY)
        {
            details = details.push(widget::text::body(
                "Could not align sequence to references.",
            ));
            if let Some(sequence_length) = self.metadata.sequence_length() {
                details = details.push(widget::text::body(format!(
                    "Sequence length: {}",
                    sequence_length
                )));
            }
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }
        } else {
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }

            details = push_species_calls(details, "16S", &RefSource::ALL, |source| {
                self.species_from_16s_sibling(items, source)
            });

            // The Mtb regions have GTDB references only; don't report a missing NCBI call.
            let rpob_sources: Vec<RefSource> = RefSource::ALL
                .into_iter()
                .filter(|&s| hits.iter().any(|h| h.source == s))
                .collect();
            details = push_species_calls(details, "rpoB", &rpob_sources, |source| {
                self.species_from_rpob_hits(source)
            });

            if self.is_chelonae(items) {
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::heading(
                    "16S and rpoB: Mycobacteroides chelonae",
                ));
            }

            for source in RefSource::ALL {
                details = push_source_section(details, &hits, source, "rpoB", 3);
            }

            if region.is_mtb() {
                details = self.push_rifampicin_calls(details);
            }
        }

        column = column.push(details);
        column.into()
    }

    /// Rifampicin-resistance block of the rpoB preview (Mtb regions): called sites, the
    /// verdict, and a warning when the species isn't *M. tuberculosis*.
    fn push_rifampicin_calls<'a>(
        &self,
        mut details: widget::Column<'a, Message, cosmic::Theme>,
    ) -> widget::Column<'a, Message, cosmic::Theme> {
        let rpob = &self.metadata.susceptibility_calls().rpob;
        details = details.push(widget::text::body(""));
        details = details.push(widget::text::heading("Rifampicin resistance calls"));
        details = details.push(widget::text::body("(rpoB, WHO mutation catalogue):"));
        if rpob.snp_calls.is_empty() {
            details = details.push(widget::text::body(
                "Read does not align to the M. tuberculosis rpoB gene.",
            ));
            return details;
        }
        let called: Vec<_> = rpob
            .snp_calls
            .iter()
            .filter(|c| !c.call_tag().is_empty())
            .collect();
        if called.is_empty() {
            details = details.push(widget::text::body("No mutation at a catalogued site."));
        }
        for call in called {
            details = details.push(widget::text::body(format!(
                "    {}: {}",
                call.site_label(),
                call.call_tag()
            )));
        }
        details = details.push(widget::text::heading(match rpob.is_susceptible {
            Some(true) => "RRDR (codons 426-452) wild type. Predicted rifampicin susceptible.",
            Some(false) => {
                "rpoB mutation meets WHO-catalogue resistance confidence. Predicted rifampicin resistance."
            }
            None => "No rifampicin verdict: RRDR (codons 426-452) not fully covered or unclear.",
        }));
        if !rpob.species_validated {
            details = details.push(widget::text::body(
                "Warning: best species hit is not M. tuberculosis; the WHO catalogue is validated \
                 only for the M. tuberculosis complex.",
            ));
        }
        details
    }

    pub fn preview_16s(&self) -> Element<'_, Message> {
        let cosmic_theme::Spacing {
            space_xxxs,
            space_m,
            ..
        } = theme::active().cosmic().spacing;

        let hits = self.seq_id_hits_cached();
        // SNP calls exist only on ntm-db full-gene hits (accession contains ':'), whose
        // coordinates the catalogue positions refer to; take them from the best such hit of
        // the winning NCBI species.
        let best_snp_hit = best_snp_hit(&hits, |h| !h.rrs_snp_calls.is_empty());
        let rrs_snp_count = best_snp_hit.map_or(0, |snp_hit| snp_hit.rrs_snp_calls.len());

        let mut column = widget::column::with_capacity(1).spacing(space_m);
        let mut details = widget::column::with_capacity(32 + rrs_snp_count).spacing(space_xxxs);
        details = details.push(widget::text::heading("32.43501-1-Mtb-NTM Kulturen-LC"));

        if hits.is_empty()
            || self
                .metadata
                .sequence_length_trimmed()
                .is_some_and(|n| n < 100)
            || hits
                .first()
                .is_none_or(|h| h.identity < crate::sequencing::MIN_SEQ_ID_IDENTITY)
        {
            details = details.push(widget::text::body(
                "Could not align sequence to references.",
            ));
            if let Some(sequence_length) = self.metadata.sequence_length() {
                details = details.push(widget::text::body(format!(
                    "Sequence length: {}",
                    sequence_length
                )));
            }
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }
        } else {
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }

            details = push_species_calls(details, "16S", &RefSource::ALL, |source| {
                crate::sequencing::batch::species_from_16s_hits(&hits_from(&hits, source))
            });

            details = push_source_section(details, &hits, RefSource::Ncbi, "16S", 8);
            if let Some(snp_hit) = best_snp_hit {
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::body(
                    "16S rRNA amikacin resistance SNPs (rrs):",
                ));
                details = details.push(widget::text::body(format!(
                    "(Using commit: {} of ntm-db repository)",
                    env!("NTM_DB_COMMIT")
                )));
                for snp in &snp_hit.rrs_snp_calls {
                    details = details.push(widget::text::body(snp.call_tag().to_string()));
                }
            }
            details = push_source_section(details, &hits, RefSource::Gtdb, "16S", 8);
        }

        column = column.push(details);
        column.into()
    }

    pub fn preview_16s3end(&self, items: &[Item]) -> Element<'_, Message> {
        let cosmic_theme::Spacing {
            space_xxxs,
            space_m,
            ..
        } = theme::active().cosmic().spacing;

        let hits = self.seq_id_hits_cached();
        // SNP calls exist only on ntm-db full-gene hits (accession contains ':'), whose
        // coordinates the catalogue positions refer to; take them from the best such hit of
        // the winning NCBI species.
        let best_snp_hit = best_snp_hit(&hits, |h| !h.rrs_snp_calls_3end.is_empty());
        let rrs_snp_count = best_snp_hit.map_or(0, |snp_hit| snp_hit.rrs_snp_calls_3end.len());

        let mut column = widget::column::with_capacity(1).spacing(space_m);
        let mut details = widget::column::with_capacity(42 + rrs_snp_count).spacing(space_xxxs);
        details = details.push(widget::text::heading("32.43506-1-16SEnd"));

        if hits.is_empty()
            || self
                .metadata
                .sequence_length_trimmed()
                .is_some_and(|n| n < 100)
            || hits
                .first()
                .is_none_or(|h| h.identity < crate::sequencing::MIN_SEQ_ID_IDENTITY)
        {
            details = details.push(widget::text::body(
                "Could not align sequence to references.",
            ));
            if let Some(sequence_length) = self.metadata.sequence_length() {
                details = details.push(widget::text::body(format!(
                    "Sequence length: {}",
                    sequence_length
                )));
            }
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }
        } else {
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }

            details = push_species_calls(details, "16S", &RefSource::ALL, |source| {
                self.species_from_16s_sibling(items, source)
            });

            if self.is_marinum(items) {
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::heading(
                    "16S and 16S 3'-End: Mycobacterium marinum",
                ));
            }
            if self.is_ulcerans(items) {
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::heading(
                    "16S and 16S 3'-End: Mycobacterium ulcerans",
                ));
            }

            if let Some(snp_hit) = best_snp_hit {
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::body(
                    "16S rRNA amikacin resistance SNPs (rrs):",
                ));
                details = details.push(widget::text::body(format!(
                    "(Using commit: {} of ntm-db repository)",
                    env!("NTM_DB_COMMIT")
                )));
                for snp in &snp_hit.rrs_snp_calls_3end {
                    details = details.push(widget::text::body(snp.call_tag().to_string()));
                }
            }
            if let Some(chrom) = self
                .metadata
                .ab1_chromatogram()
                .filter(|c| c.rrs3end_view_state_opt.is_some())
                && !self.metadata.is_massiliense_seq_id()
            {
                let view_state = chrom.rrs3end_view_state_opt.unwrap();
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::body(
                    "Shown are bases 19-39, with E. coli position 1248 in bold.",
                ));
                if view_state.is_reverse {
                    details = details.push(widget::text::body("reverse complement"));
                }
                details = details.push(widget::text::body(""));
                let canvas = widget::Canvas::new(ChromatogramProgram {
                    is_reverse: view_state.is_reverse,
                    display_window: Some(view_state.window),
                    highlighted_scans: chrom
                        .peak_locs
                        .get(view_state.pos1248_base_idx as usize)
                        .copied()
                        .map(|v| vec![v])
                        .unwrap_or_default(),
                    chrom,
                })
                .width(Length::Fill)
                .height(Length::Fixed(200.0));
                details = details.push(canvas);
                details = details.push(widget::text::body(""));
            } else {
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::body(chromatogram_placeholder(
                    &self.metadata,
                    "16S 3-End",
                )));
                details = details.push(widget::text::body(""));
            }

            match self.metadata.rrs3endposition_call() {
                Rrs3EndPosition1248::A1248 => {
                    details = details.push(widget::text::heading(
                        "16S 3'-End position 1248 = A:  M. marinum",
                    ))
                }
                Rrs3EndPosition1248::G1248 => {
                    details = details.push(widget::text::heading(
                        "16S 3'-End position 1248 = G:  M. ulcerans",
                    ))
                }
                Rrs3EndPosition1248::C1248 => {
                    details = details.push(widget::text::heading("16S 3'-End position 1248 = C"))
                }
                Rrs3EndPosition1248::T1248 => {
                    details = details.push(widget::text::heading("16S 3'-End position 1248 = T"))
                }
                Rrs3EndPosition1248::Undetermined => {
                    details = details.push(widget::text::heading(
                        "16S 3'-End position 1248 = undetermined",
                    ))
                }
            }

            for source in RefSource::ALL {
                details = push_source_section(details, &hits, source, "16S 3'-End only", 8);
            }
        }

        column = column.push(details);
        column.into()
    }

    pub fn preview_rrl_ntm(&self, items: &[Item]) -> Element<'_, Message> {
        let cosmic_theme::Spacing {
            space_xxxs,
            space_m,
            ..
        } = theme::active().cosmic().spacing;

        let hits = self.seq_id_hits_cached();
        // SNP calls exist only on ntm-db full-gene hits (accession contains ':'), whose
        // coordinates the catalogue positions refer to; take them from the best such hit of
        // the winning NCBI species.
        let best_snp_hit = best_snp_hit(&hits, |h| !h.rrl_snp_calls.is_empty());
        let rrl_snp_count = best_snp_hit.map_or(0, |snp_hit| snp_hit.rrl_snp_calls.len());

        let mut column = widget::column::with_capacity(1).spacing(space_m);
        let mut details = widget::column::with_capacity(30 + rrl_snp_count).spacing(space_xxxs);
        details = details.push(widget::text::heading(
            "32.43605-1-PCR - NTM 23S CLR-Sequenzierung",
        ));

        if hits.is_empty()
            || self
                .metadata
                .sequence_length_trimmed()
                .is_some_and(|n| n < 100)
            || hits
                .first()
                .is_none_or(|h| h.identity < crate::sequencing::MIN_SEQ_ID_IDENTITY)
        {
            details = details.push(widget::text::body(
                "Could not align sequence to references.",
            ));
            if let Some(sequence_length) = self.metadata.sequence_length() {
                details = details.push(widget::text::body(format!(
                    "Sequence length: {}",
                    sequence_length
                )));
            }
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }
        } else {
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }

            details = push_species_calls(details, "16S", &RefSource::ALL, |source| {
                self.species_from_16s_sibling(items, source)
            });

            for source in RefSource::ALL {
                details = push_source_section(details, &hits, source, "rrl", 3);
            }
            details = details.push(widget::text::body(""));
            if let Some(snp_hit) = best_snp_hit {
                details = details.push(widget::text::body(
                    "23S rRNA macrolide resistance SNPs (rrl):",
                ));
                details = details.push(widget::text::body(format!(
                    "(Using commit: {} of ntm-db repository)",
                    env!("NTM_DB_COMMIT")
                )));
                for snp in &snp_hit.rrl_snp_calls {
                    details = details.push(widget::text::body(snp.call_tag().to_string()));
                }
            }
            if let Some(chrom) = self
                .metadata
                .ab1_chromatogram()
                .filter(|c| c.rrl_ntm_view_state_opt.is_some())
            {
                let view_state = chrom.rrl_ntm_view_state_opt.unwrap();
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::body(
                    "Shown in bold are bases coresponding to E. coli positions 2058/2059",
                ));
                if view_state.is_reverse {
                    details = details.push(widget::text::body("reverse complement"));
                }
                details = details.push(widget::text::body(""));
                let canvas = widget::Canvas::new(ChromatogramProgram {
                    is_reverse: view_state.is_reverse,
                    display_window: Some(view_state.window),
                    highlighted_scans: {
                        let idx = view_state.snp_base_idx as usize;
                        [idx, idx + 1]
                            .iter()
                            .filter_map(|&i| chrom.peak_locs.get(i).copied())
                            .collect()
                    },
                    chrom,
                })
                .width(Length::Fill)
                .height(Length::Fixed(200.0));
                details = details.push(canvas);
                details = details.push(widget::text::body(""));
            } else {
                details = details.push(widget::text::body(""));
                details = details.push(widget::text::body(chromatogram_placeholder(
                    &self.metadata,
                    "rrl",
                )));
                details = details.push(widget::text::body(""));
            }
            match self
                .metadata
                .susceptibility_calls()
                .rrl
                .position_2058_2059
                .and_then(|p| p.is_susceptible())
            {
                Some(true) => {
                    details = details.push(widget::text::heading(
                        "E. coli positions A2058 and A2059 are wt (macrolide susceptible).",
                    ))
                }
                Some(false) => {
                    details = details.push(widget::text::heading(
                        "Mutation in E. coli A2058 and/or A2059. Predicted macrolide resistance.",
                    ))
                }
                None => {}
            }
        }

        column = column.push(details);
        column.into()
    }

    pub fn preview_pnca(&self) -> Element<'_, Message> {
        let cosmic_theme::Spacing {
            space_xxxs,
            space_m,
            ..
        } = theme::active().cosmic().spacing;

        let hits = self.seq_id_hits_cached();
        let pnca_called_count = self
            .metadata
            .susceptibility_calls()
            .pnca
            .snp_calls
            .iter()
            .filter(|c| !c.call_tag().is_empty())
            .count()
            .max(1);

        let mut column = widget::column::with_capacity(1).spacing(space_m);
        let mut details = widget::column::with_capacity(9 + pnca_called_count).spacing(space_xxxs);
        details = details.push(widget::text::heading("32.43616-2-MtbKomplex-pncA-Seq"));

        if hits.is_empty()
            || self
                .metadata
                .sequence_length_trimmed()
                .is_some_and(|n| n < 100)
            || hits
                .first()
                .is_none_or(|h| h.identity < crate::sequencing::MIN_SEQ_ID_IDENTITY)
        {
            details = details.push(widget::text::body(
                "Could not align sequence to the pncA reference.",
            ));
            if let Some(sequence_length) = self.metadata.sequence_length() {
                details = details.push(widget::text::body(format!(
                    "Sequence length: {}",
                    sequence_length
                )));
            }
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }
        } else {
            let best = &hits[0];
            details = details.push(widget::text::body(format!(
                "Sequence identity to {}: {:.1}%",
                best.description, best.identity
            )));
            if let Some(sequence_length_trimmed) = self.metadata.sequence_length_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Trimmed sequence length: {}",
                    sequence_length_trimmed
                )));
            }
            if let Some(avg_qual) = self.metadata.sequence_avg_quality_trimmed() {
                details = details.push(widget::text::body(format!(
                    "Average quality score: {:.1}",
                    avg_qual
                )));
            }
            details = details.push(
                widget::button::link(format!("View alignment ({:.1}%)", best.identity))
                    .on_press(Message::OpenSeqAlignment(Box::new(best.clone())))
                    .padding(0),
            );

            let pnca = &self.metadata.susceptibility_calls().pnca;
            let called: Vec<_> = pnca
                .snp_calls
                .iter()
                .filter(|c| !c.call_tag().is_empty())
                .collect();
            details = details.push(widget::text::body(""));
            details = details.push(widget::text::heading("Pyrazinamide resistance calls"));
            details = details.push(widget::text::body("(pncA, WHO mutation catalogue):"));
            if called.is_empty() {
                details = details.push(widget::text::body("No catalogued sites covered."));
            } else {
                for snp in &called {
                    details = details.push(widget::text::body(format!(
                        "    {}: {}",
                        snp.site_label(),
                        snp.call_tag()
                    )));
                }
            }
            match pnca.is_susceptible {
                Some(true) => {
                    details = details.push(widget::text::heading(
                        "No pncA mutation at or above WHO-catalogue resistance confidence. Predicted pyrazinamide susceptible.",
                    ))
                }
                Some(false) => {
                    details = details.push(widget::text::heading(
                        "pncA mutation meets WHO-catalogue resistance confidence. Predicted pyrazinamide resistance.",
                    ))
                }
                None => {}
            }
        }

        column = column.push(details);
        column.into()
    }
}

/// Canvas program that renders an AB1 Sanger chromatogram.
///
/// Draws the four channel intensity curves in standard colors:
/// A = green, C = blue, G = black, T = red.
/// Base call letters are drawn at their peak scan positions along the top.
struct ChromatogramProgram<'a> {
    chrom: &'a crate::sequencing::Ab1Channels,
    is_reverse: bool,
    display_window: Option<(u16, u16)>,
    highlighted_scans: Vec<u16>,
}

/// Everything the chromatogram geometry depends on besides the canvas size (which
/// [`widget::canvas::Cache`] tracks itself). The geometry is rebuilt only when it changes.
#[derive(Clone, PartialEq, Eq)]
struct ChromatogramKey {
    /// Identity of the trace data: address of the struct and of its first channel buffer.
    data: (usize, usize),
    lens: [usize; 4],
    is_reverse: bool,
    display_window: Option<(u16, u16)>,
    highlighted_scans: Vec<u16>,
}

#[derive(Default)]
struct ChromatogramState {
    cache: widget::canvas::Cache<cosmic::Renderer>,
    key: std::cell::RefCell<Option<ChromatogramKey>>,
}

impl ChromatogramProgram<'_> {
    fn key(&self) -> ChromatogramKey {
        let mut lens = [0; 4];
        for (len, channel) in lens.iter_mut().zip(&self.chrom.channels) {
            *len = channel.len();
        }
        ChromatogramKey {
            data: (
                std::ptr::from_ref(self.chrom) as usize,
                self.chrom
                    .channels
                    .first()
                    .map_or(0, |c| c.as_ptr() as usize),
            ),
            lens,
            is_reverse: self.is_reverse,
            display_window: self.display_window,
            highlighted_scans: self.highlighted_scans.clone(),
        }
    }
}

impl<'a> widget::canvas::Program<Message, cosmic::Theme, cosmic::Renderer>
    for ChromatogramProgram<'a>
{
    type State = ChromatogramState;

    fn draw(
        &self,
        state: &Self::State,
        renderer: &cosmic::Renderer,
        _theme: &cosmic::Theme,
        bounds: Rectangle,
        _cursor: cosmic::iced::mouse::Cursor,
    ) -> Vec<widget::canvas::Geometry<cosmic::Renderer>> {
        let key = self.key();
        if state.key.borrow().as_ref() != Some(&key) {
            state.cache.clear();
            *state.key.borrow_mut() = Some(key);
        }
        vec![
            state
                .cache
                .draw(renderer, bounds.size(), |frame| self.draw_traces(frame)),
        ]
    }
}

impl ChromatogramProgram<'_> {
    fn draw_traces(&self, frame: &mut widget::canvas::Frame<cosmic::Renderer>) {
        use cosmic::iced::alignment;
        use widget::canvas::{Path, Stroke};

        let bounds = frame.size();
        let chrom = self.chrom;
        let is_rev = self.is_reverse;

        // Standard Sanger palette: colour by the base the dye represents.
        // For a reverse read the channel physically contains the complement base,
        // so we complement the channel's base before looking up the colour â€”
        // that way the displayed colour always matches the plus-strand base.
        let dna_complement = |b: u8| -> u8 {
            match b.to_ascii_uppercase() {
                b'A' => b'T',
                b'T' => b'A',
                b'C' => b'G',
                b'G' => b'C',
                _ => b'N',
            }
        };
        let base_color = |base: u8| -> Color {
            match base.to_ascii_uppercase() {
                b'A' => Color::from_rgb(0.0, 0.7, 0.0),
                b'C' => Color::from_rgb(0.0, 0.0, 1.0),
                b'G' => Color::from_rgb(0.8, 0.55, 0.0),
                b'T' => Color::from_rgb(1.0, 0.0, 0.0),
                _ => Color::from_rgb(0.5, 0.5, 0.5),
            }
        };

        // Restrict to the display window.
        // Fall back to the full scan range if the anchor was not found.
        let total_scans: u16 = chrom
            .channels
            .iter()
            .map(|c| c.len() as u16)
            .max()
            .unwrap_or(1);
        if total_scans == 0 {
            return;
        }
        let (scan_start, scan_end) = self
            .display_window
            .unwrap_or((0, total_scans.saturating_sub(1)));
        let scan_end = scan_end.min(total_scans.saturating_sub(1));
        let window_len = (scan_end + 1).saturating_sub(scan_start).max(1);

        // Y range: only over the visible window for better contrast
        let mut y_min = i16::MAX;
        let mut y_max = i16::MIN;
        for channel in &chrom.channels {
            for &v in &channel
                [(scan_start as usize).min(channel.len())..(scan_end as usize).min(channel.len())]
            {
                if v < y_min {
                    y_min = v;
                }
                if v > y_max {
                    y_max = v;
                }
            }
        }
        if y_min == i16::MAX {
            y_min = 0;
            y_max = 1;
        }
        if y_max == y_min {
            y_max = y_min + 1;
        }
        let y_range = (y_max - y_min) as f32;

        // Leave a small margin at the top for base letters
        let top_margin = 18.0_f32;
        let plot_h = (bounds.height - top_margin).max(1.0);
        let plot_w = bounds.width;

        // Map scan index to canvas x.
        // For reverse reads we flip the x-axis so the plus-strand 5â€²â†’3â€² direction
        // always runs left to right, identical to a forward read.
        let scan_to_x = |scan: usize| -> f32 {
            let t = (scan.saturating_sub(scan_start as usize)) as f32
                / ((window_len as usize) - 1).max(1) as f32;
            if is_rev {
                (1.0 - t) * plot_w
            } else {
                t * plot_w
            }
        };
        let intensity_to_y =
            |v: i16| -> f32 { top_margin + (1.0 - (v - y_min) as f32 / y_range) * plot_h };

        // Draw each channel, restricted to [scan_start, scan_end].
        // For reverse reads the channel base is the complement of the plus-strand base,
        // so we complement it before resolving the display colour.
        for (ch_idx, channel) in chrom.channels.iter().enumerate() {
            if channel.is_empty() {
                continue;
            }
            let raw_base = chrom.base_order[ch_idx];
            let display_base = if is_rev {
                dna_complement(raw_base)
            } else {
                raw_base
            };
            let color = base_color(display_base);

            let slice_end = (scan_end + 1).min(channel.len() as u16);
            let slice_start = scan_start.min(slice_end);
            if slice_start >= slice_end {
                continue;
            }
            let window_slice = &channel[slice_start as usize..slice_end as usize];

            let path = Path::new(|builder| {
                builder.move_to(Point {
                    x: scan_to_x(slice_start as usize),
                    y: intensity_to_y(window_slice[0]),
                });
                for (i, &v) in window_slice.iter().enumerate().skip(1) {
                    builder.line_to(Point {
                        x: scan_to_x(slice_start as usize + i),
                        y: intensity_to_y(v),
                    });
                }
            });

            frame.stroke(&path, Stroke::default().with_color(color).with_width(1.2));
        }

        // Draw base call letters only for bases whose peak falls in the window.
        // For reverse reads show the complement letter so the label matches the
        // plus-strand base at each position.
        // Highlighted scan positions are drawn in bold.
        for (base, &peak) in chrom.bases.iter().zip(chrom.peak_locs.iter()) {
            let scan = peak;
            if scan < scan_start || scan > scan_end {
                continue;
            }
            let display_base = if is_rev { dna_complement(*base) } else { *base };
            let x = scan_to_x(scan as usize);
            let color = base_color(display_base);
            let is_highlighted = self.highlighted_scans.contains(&scan);
            frame.fill_text(widget::canvas::Text {
                content: String::from(display_base as char),
                position: Point { x, y: 2.0 },
                max_width: f32::INFINITY,
                color,
                size: cosmic::iced::Pixels(if is_highlighted { 20.0 } else { 11.0 }),
                line_height: cosmic::iced::advanced::text::LineHeight::default(),
                font: cosmic::iced::Font::default(),
                align_x: cosmic::iced::advanced::text::Alignment::Center,
                align_y: alignment::Vertical::Top,
                shaping: cosmic::iced::advanced::text::Shaping::Basic,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_ab1_parses_lengths_and_chromatogram() {
        // Generated locally under target/ (not committed); skip when absent.
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/synthetic_ab1/2026999001_hsp65_gastri_synthetic.ab1");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: {} not found", path.display());
            return;
        };
        let read = read_ab1(&path, &bytes);
        assert!(read.length > 0);
        assert!(read.trimmed_length <= read.length);
        assert!(read.chromatogram_opt.is_some());
    }

    #[test]
    fn read_ab1_of_unreadable_bytes_is_empty() {
        let read = read_ab1(Path::new("x.ab1"), &[]);
        assert_eq!((read.length, read.trimmed_length), (0, 0));
        assert!(read.chromatogram_opt.is_none());
    }

    #[test]
    fn cached_seq_data_reads_no_file() {
        let metadata = std::fs::metadata(".").unwrap();
        let seq = cached_seq_data(Path::new("does/not/exist.ab1"), &metadata);
        assert!(seq.read_opt.is_none());
        assert!(seq.seq_id_hits.is_empty());
    }
}
