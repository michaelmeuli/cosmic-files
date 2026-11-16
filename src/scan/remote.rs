use crate::config::IconSizes;
use crate::item::Item;
use crate::russh::CLIENTS;

pub fn scan_remote(uri: &str, sizes: IconSizes) -> Vec<Item> {
    for client in CLIENTS.values() {
        match client.remote_scan(uri, sizes) {
            Some(Ok(items)) => return items,
            Some(Err(err)) => {
                log::warn!("failed to scan remote {uri:?}: {err}");
            }
            None => {}
        }
    }
    Vec::new()
}

pub fn item_from_remote(uri: &str, sizes: IconSizes) -> Result<Item, String> {
    for client in CLIENTS.values() {
        match client.remote_parent_item(uri, sizes) {
            Some(Ok(item)) => return Ok(item),
            Some(Err(err)) => {
                log::warn!("failed to scan remote {uri:?}: {err}");
            }
            None => {}
        }
    }
    Err(format!("no client found for remote uri: {uri}"))
}
