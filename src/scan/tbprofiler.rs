use mime_guess::mime;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::config::IconSizes;
use crate::item::{DirSize, Item, ItemMetadata, ItemState, ItemThumbnail};
use crate::location::Location;
use crate::mime_icon::mime_icon;
use crate::sequencing::SusceptibilityCalls;
use crate::sequencing::tb_data::TbProfilerJson;

/// Two-pass grouping: collect `.results.*` files into virtual sample items,
/// mirroring the remote scan behaviour so `ToggleShowAsSamples` works locally.
pub fn group_tbprofiler_samples(tab_path: &PathBuf, items: &mut Vec<Item>, sizes: IconSizes) {
    struct LocalSampleFiles {
        json: Option<PathBuf>,
        csv: Option<PathBuf>,
        docx: Option<PathBuf>,
    }

    let mut samples: HashMap<String, LocalSampleFiles> = HashMap::new();
    for item in items.iter_mut() {
        let name = item.name.clone();
        let path = item.path_opt().cloned();
        if let ItemMetadata::Path {
            is_tbprofiler_groupable_raw_result_file,
            ..
        } = &mut item.metadata
            && let Some((sample_id, suffix)) = name.split_once(".results.")
        {
            let entry = samples
                .entry(sample_id.to_string())
                .or_insert(LocalSampleFiles {
                    json: None,
                    csv: None,
                    docx: None,
                });
            match suffix {
                "json" => entry.json = path,
                "csv" => entry.csv = path,
                "docx" => entry.docx = path,
                _ => {}
            }
            *is_tbprofiler_groupable_raw_result_file = true;
        }
    }
    for item in items.iter_mut() {
        let name = item.name.clone();
        if let ItemMetadata::Path {
            is_tbprofiler_groupable_raw_result_file,
            ..
        } = &mut item.metadata
            && *is_tbprofiler_groupable_raw_result_file
        {
            let sample_id = name.find('.').map(|i| &name[..i]);
            if sample_id.is_none_or(|id| samples.get(id).is_none_or(|f| f.json.is_none())) {
                *is_tbprofiler_groupable_raw_result_file = false;
            }
        }
    }
    // Propagate susceptibility to raw sample files so filtering works in file view too
    let sample_susceptibility: HashMap<String, bool> = samples
        .iter()
        .filter_map(|(id, files)| {
            let p = files.json.as_ref()?;
            let json: TbProfilerJson = fs::read_to_string(p)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())?;
            Some((
                id.clone(),
                json.dr_variants.iter().all(|v| v.is_susceptible()),
            ))
        })
        .collect();
    for item in items.iter_mut() {
        let name = item.name.clone();
        if let ItemMetadata::Path {
            is_tbprofiler_groupable_raw_result_file,
            is_susceptible,
            ..
        } = &mut item.metadata
            && *is_tbprofiler_groupable_raw_result_file
            && let Some(id) = name.find('.').map(|i| &name[..i])
            && let Some(&sus) = sample_susceptibility.get(id)
        {
            *is_susceptible = Some(sus);
        }
    }

    for (sample_id, files) in samples {
        if files.json.is_none() {
            continue;
        }
        let representative = files.json.as_deref().unwrap_or(tab_path);
        let Ok(fs_meta) = fs::metadata(representative) else {
            continue;
        };
        let tbprofilerjson_opt: Option<TbProfilerJson> = files.json.as_ref().and_then(|p| {
            fs::read_to_string(p)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
        });
        let is_susceptible = tbprofilerjson_opt
            .as_ref()
            .map(|j| j.dr_variants.iter().all(|v| v.is_susceptible()));
        let location = Location::Path(tab_path.join(&sample_id));
        let metadata = ItemMetadata::Path {
            metadata: fs_meta,
            children_opt: None,
            tbprofilerjson_opt,
            is_ab1: false,
            sequence_opt: None,
            is_tbprofiler_result_as_sample: true,
            is_tbprofiler_groupable_raw_result_file: false,
            sample_json_path_opt: files.json,
            sample_csv_path_opt: files.csv,
            sample_docx_path_opt: files.docx,
            is_susceptible,
            susceptibility_calls: SusceptibilityCalls::default(),
        };
        items.push(Item {
            name: sample_id.clone(),
            display_name: sample_id,
            metadata,
            hidden: false,
            location_opt: Some(location),
            image_dimensions: None,
            mime: mime::APPLICATION_JSON,
            icon_handle_grid: mime_icon(mime::APPLICATION_JSON, sizes.grid()),
            icon_handle_list: mime_icon(mime::APPLICATION_JSON, sizes.list()),
            icon_handle_list_condensed: mime_icon(mime::APPLICATION_JSON, sizes.list_condensed()),
            thumbnail_opt: Some(ItemThumbnail::NotImage),
            dir_size: DirSize::NotDirectory,
            is_mount_point: false,
            is_client_point: false,
            state: ItemState::default(),
        });
    }
}
