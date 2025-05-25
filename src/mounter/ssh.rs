use async_ssh2_tokio::client::{Client, AuthMethod, ServerCheckMethod};
use cosmic::{iced::Subscription, widget, Task};
use std::{any::TypeId, collections::BTreeMap, path::PathBuf, sync::Arc};
use tokio::sync::{mpsc, Mutex};

use super::{Mounter, MounterAuth, MounterItem, MounterItems, MounterMessage};
use crate::{
    config::IconSizes,
    err_str,
    tab::{self, DirSize, ItemMetadata, ItemThumbnail, Location},
};
