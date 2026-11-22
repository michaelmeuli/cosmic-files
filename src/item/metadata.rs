use std::fs::Metadata;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::sequencing::erm41::Erm41Position28;
use crate::sequencing::rrl::RrlPosition2058_2059;
use crate::sequencing::rrs3end::Rrs3EndPosition1248;
use crate::sequencing::tb_data::TbProfilerJson;
use crate::sequencing::{Ab1Channels, SeqData, SeqIdHit, SusceptibilityCalls};
use crate::trash::{TrashItem, TrashItemSize};

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ItemMetadata {
    Path {
        metadata: Metadata,
        children_opt: Option<usize>,
        tbprofilerjson_opt: Option<TbProfilerJson>,
        is_ab1: bool,
        sequence_opt: Option<SeqData>,
        is_tbprofiler_result_as_sample: bool,
        is_tbprofiler_groupable_raw_result_file: bool,
        sample_json_path_opt: Option<PathBuf>,
        sample_csv_path_opt: Option<PathBuf>,
        sample_docx_path_opt: Option<PathBuf>,
        is_susceptible: Option<bool>,
        susceptibility_calls: SusceptibilityCalls,
    },
    Trash {
        size: TrashItemSize,
        entry: TrashItem,
    },
    SimpleDir {
        entries: u64,
    },
    SimpleFile {
        size: u64,
    },
    #[cfg(feature = "gvfs")]
    GvfsPath {
        mtime: u64,
        size_opt: Option<u64>,
        children_opt: Option<usize>,
        is_dir: bool,
    },
    #[cfg(feature = "russh")]
    RusshPath {
        mtime: u64,
        size_opt: Option<u64>,
        children_opt: Option<usize>,
        is_tbprofiler_json: bool,
        tbprofilerjson_opt: Option<TbProfilerJson>,
        is_tbprofiler_result_as_sample: bool,
        is_tbprofiler_groupable_raw_result_file: bool,
        sample_json_path_opt: Option<PathBuf>,
        sample_csv_path_opt: Option<PathBuf>,
        sample_docx_path_opt: Option<PathBuf>,
        is_susceptible: Option<bool>,
    },
}

impl ItemMetadata {
    pub fn is_dir(&self) -> bool {
        match self {
            Self::Path { metadata, .. } => metadata.is_dir(),
            Self::Trash { size, .. } => match size {
                TrashItemSize::Entries(_) => true,
                TrashItemSize::Bytes(_) => false,
            },
            Self::SimpleDir { .. } => true,
            Self::SimpleFile { .. } => false,
            #[cfg(feature = "gvfs")]
            Self::GvfsPath { is_dir, .. } => *is_dir,
            #[cfg(feature = "russh")]
            Self::RusshPath { children_opt, .. } => children_opt.is_some(),
        }
    }

    pub fn modified(&self) -> Option<SystemTime> {
        match self {
            Self::Path { metadata, .. } => metadata.modified().ok(),
            #[cfg(feature = "gvfs")]
            Self::GvfsPath { mtime, .. } => {
                SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(*mtime))
            }
            #[cfg(feature = "russh")]
            Self::RusshPath { mtime, .. } => {
                SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(*mtime))
            }
            _ => None,
        }
    }

    pub fn file_size(&self) -> Option<u64> {
        match self {
            Self::Path { metadata, .. } => (!metadata.is_dir()).then_some(metadata.len()),
            Self::Trash { size, .. } => match size {
                TrashItemSize::Bytes(size) => Some(*size),
                TrashItemSize::Entries(_) => None,
            },
            #[cfg(feature = "gvfs")]
            Self::GvfsPath { size_opt, .. } => *size_opt,
            #[cfg(feature = "russh")]
            Self::RusshPath { size_opt, .. } => *size_opt,
            _ => None,
        }
    }

    pub fn children_count(&self) -> Option<&usize> {
        match &self {
            ItemMetadata::Path { children_opt, .. } => children_opt.as_ref(),
            #[cfg(feature = "gvfs")]
            ItemMetadata::GvfsPath { children_opt, .. } => children_opt.as_ref(),
            #[cfg(feature = "russh")]
            ItemMetadata::RusshPath { children_opt, .. } => children_opt.as_ref(),
            _ => None,
        }
    }

    pub fn is_tbprofiler_json(&self) -> bool {
        match self {
            Self::Path {
                tbprofilerjson_opt, ..
            } => tbprofilerjson_opt.is_some(),
            #[cfg(feature = "russh")]
            Self::RusshPath {
                is_tbprofiler_json, ..
            } => *is_tbprofiler_json,
            _ => false,
        }
    }

    pub fn is_ab1(&self) -> bool {
        match self {
            Self::Path { is_ab1, .. } => *is_ab1,
            _ => false,
        }
    }

    pub fn erm41position28_call(&self) -> Erm41Position28 {
        match self {
            Self::Path { sequence_opt, .. } => sequence_opt
                .as_ref()
                .and_then(|s| s.seq_id_hits.first()?.erm41_position_28_opt)
                .unwrap_or(Erm41Position28::Undetermined),
            _ => Erm41Position28::Undetermined,
        }
    }

    pub fn is_erm41position28(&self) -> bool {
        !matches!(self.erm41position28_call(), Erm41Position28::Undetermined)
    }

    pub fn ab1_chromatogram(&self) -> Option<&Ab1Channels> {
        match self {
            Self::Path { sequence_opt, .. } => sequence_opt
                .as_ref()?
                .read_opt
                .as_ref()?
                .chromatogram_opt
                .as_ref(),
            _ => None,
        }
    }

    /// `true` once the preview has read the AB1 file itself (chromatogram, lengths, quality).
    pub fn ab1_read_loaded(&self) -> bool {
        matches!(
            self,
            Self::Path {
                sequence_opt: Some(SeqData {
                    read_opt: Some(_),
                    ..
                }),
                ..
            }
        )
    }

    pub fn rrl_position_2058_2059_call(&self) -> RrlPosition2058_2059 {
        match self {
            Self::Path { sequence_opt, .. } => sequence_opt
                .as_ref()
                .and_then(|s| s.seq_id_hits.first()?.rrl_position_2058_2059_opt)
                .unwrap_or(RrlPosition2058_2059::Undetermined),
            _ => RrlPosition2058_2059::Undetermined,
        }
    }

    pub fn is_rrl_position_2058_2059(&self) -> bool {
        !matches!(
            self.rrl_position_2058_2059_call(),
            RrlPosition2058_2059::Undetermined
        )
    }

    pub fn rrs3endposition_call(&self) -> Rrs3EndPosition1248 {
        match self {
            Self::Path { sequence_opt, .. } => sequence_opt
                .as_ref()
                .and_then(|s| s.seq_id_hits.first()?.rrs3end_position_1248_opt)
                .unwrap_or(Rrs3EndPosition1248::Undetermined),
            _ => Rrs3EndPosition1248::Undetermined,
        }
    }

    pub fn is_rrs3endposition(&self) -> bool {
        !matches!(
            self.rrs3endposition_call(),
            Rrs3EndPosition1248::Undetermined
        )
    }

    pub fn seq_id_hits(&self) -> &[SeqIdHit] {
        match self {
            Self::Path { sequence_opt, .. } => sequence_opt
                .as_ref()
                .map(|s| s.seq_id_hits.as_slice())
                .unwrap_or(&[]),
            _ => &[],
        }
    }

    pub fn is_seq_id(&self) -> bool {
        self.seq_id_hits()
            .first()
            .is_some_and(|h| h.identity >= crate::sequencing::MIN_SEQ_ID_IDENTITY)
    }

    pub fn sequence_length(&self) -> Option<usize> {
        match self {
            Self::Path { sequence_opt, .. } => {
                Some(sequence_opt.as_ref()?.read_opt.as_ref()?.length)
            }
            _ => None,
        }
    }

    pub fn sequence_length_trimmed(&self) -> Option<usize> {
        match self {
            Self::Path { sequence_opt, .. } => {
                Some(sequence_opt.as_ref()?.read_opt.as_ref()?.trimmed_length)
            }
            _ => None,
        }
    }

    pub fn sequence_avg_quality_trimmed(&self) -> Option<f32> {
        match self {
            Self::Path { sequence_opt, .. } => {
                sequence_opt
                    .as_ref()?
                    .read_opt
                    .as_ref()?
                    .trimmed_avg_quality_opt
            }
            _ => None,
        }
    }

    pub fn is_abscessus_seq_id(&self) -> bool {
        match self {
            Self::Path { sequence_opt, .. } => sequence_opt
                .as_ref()
                .and_then(|s| s.seq_id_hits.first())
                .map(|h| h.description == "Mycobacteroides abscessus subsp. abscessus")
                .unwrap_or(false),
            _ => false,
        }
    }

    pub fn is_bolletii_seq_id(&self) -> bool {
        match self {
            Self::Path { sequence_opt, .. } => sequence_opt
                .as_ref()
                .and_then(|s| s.seq_id_hits.first())
                .map(|h| h.description == "Mycobacteroides abscessus subsp. bolletii")
                .unwrap_or(false),
            _ => false,
        }
    }

    pub fn is_massiliense_seq_id(&self) -> bool {
        match self {
            Self::Path { sequence_opt, .. } => sequence_opt
                .as_ref()
                .and_then(|s| s.seq_id_hits.first())
                .map(|h| h.description == "Mycobacteroides abscessus subsp. massiliense")
                .unwrap_or(false),
            _ => false,
        }
    }

    pub fn set_json(&mut self, json: Option<TbProfilerJson>) {
        match self {
            Self::Path {
                tbprofilerjson_opt, ..
            } => *tbprofilerjson_opt = json,
            #[cfg(feature = "russh")]
            Self::RusshPath {
                tbprofilerjson_opt, ..
            } => *tbprofilerjson_opt = json,
            _ => {}
        }
    }

    pub fn is_tbprofilerjson_opt(&self) -> bool {
        match self {
            Self::Path {
                tbprofilerjson_opt, ..
            } => tbprofilerjson_opt.is_some(),
            #[cfg(feature = "russh")]
            Self::RusshPath {
                tbprofilerjson_opt, ..
            } => tbprofilerjson_opt.is_some(),
            _ => false,
        }
    }

    pub fn is_tbprofiler_result_as_sample(&self) -> bool {
        match self {
            Self::Path {
                is_tbprofiler_result_as_sample,
                ..
            } => *is_tbprofiler_result_as_sample,
            #[cfg(feature = "russh")]
            Self::RusshPath {
                is_tbprofiler_result_as_sample,
                ..
            } => *is_tbprofiler_result_as_sample,
            _ => false,
        }
    }

    pub fn is_groupable_as_sample_tbprofiler_result_item(&self) -> bool {
        match self {
            Self::Path {
                is_tbprofiler_groupable_raw_result_file,
                ..
            } => *is_tbprofiler_groupable_raw_result_file,
            #[cfg(feature = "russh")]
            Self::RusshPath {
                is_tbprofiler_groupable_raw_result_file,
                ..
            } => *is_tbprofiler_groupable_raw_result_file,
            _ => false,
        }
    }

    pub fn json_path(&self) -> Option<&PathBuf> {
        match self {
            Self::Path {
                sample_json_path_opt,
                ..
            } => sample_json_path_opt.as_ref(),
            #[cfg(feature = "russh")]
            Self::RusshPath {
                sample_json_path_opt,
                ..
            } => sample_json_path_opt.as_ref(),
            _ => None,
        }
    }

    pub fn csv_path(&self) -> Option<&PathBuf> {
        match self {
            Self::Path {
                sample_csv_path_opt,
                ..
            } => sample_csv_path_opt.as_ref(),
            #[cfg(feature = "russh")]
            Self::RusshPath {
                sample_csv_path_opt,
                ..
            } => sample_csv_path_opt.as_ref(),
            _ => None,
        }
    }

    pub fn docx_path(&self) -> Option<&PathBuf> {
        match self {
            Self::Path {
                sample_docx_path_opt,
                ..
            } => sample_docx_path_opt.as_ref(),
            #[cfg(feature = "russh")]
            Self::RusshPath {
                sample_docx_path_opt,
                ..
            } => sample_docx_path_opt.as_ref(),
            _ => None,
        }
    }

    pub fn is_susceptible(&self) -> Option<bool> {
        match self {
            Self::Path { is_susceptible, .. } => *is_susceptible,
            #[cfg(feature = "russh")]
            Self::RusshPath { is_susceptible, .. } => *is_susceptible,
            _ => None,
        }
    }

    pub fn susceptibility_calls(&self) -> SusceptibilityCalls {
        match self {
            Self::Path {
                susceptibility_calls,
                ..
            } => susceptibility_calls.clone(),
            _ => SusceptibilityCalls::default(),
        }
    }
}
