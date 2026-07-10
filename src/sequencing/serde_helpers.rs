//! `#[serde(with = "...")]` helpers for types serde can't (de)serialize directly, used to make
//! resistance-SNP-call structs (e.g. [`erm41::Erm41LofCall`](super::erm41::Erm41LofCall),
//! [`rrl::RrlSnpCall`](super::rrl::RrlSnpCall)) and batch-scan records round-trip through JSON.

/// (De)serializes a `BTreeMap<u8, V>` as a JSON array of `[key, value]` pairs.
///
/// serde_json (and JSON generally) only supports string map keys, so a `BTreeMap<u8, _>` can't
/// be serialized as a JSON object directly; encoding it as an array of pairs sidesteps that.
pub mod u8_btree_map {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S, V: Serialize>(map: &BTreeMap<u8, V>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let pairs: Vec<(u8, &V)> = map.iter().map(|(k, v)| (*k, v)).collect();
        pairs.serialize(s)
    }

    pub fn deserialize<'de, D, V: Deserialize<'de>>(d: D) -> Result<BTreeMap<u8, V>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let pairs: Vec<(u8, V)> = Vec::deserialize(d)?;
        Ok(pairs.into_iter().collect())
    }
}

/// (De)serializes `Option<SystemTime>` as an optional Unix timestamp in whole seconds.
///
/// `SystemTime` has no stable serde representation of its own; this truncates to second
/// precision, which is enough for cache-freshness comparisons.
pub mod option_systemtime_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn serialize<S: Serializer>(t: &Option<SystemTime>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            None => s.serialize_none(),
            Some(st) => {
                let secs = st.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                s.serialize_some(&secs)
            }
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SystemTime>, D::Error> {
        let opt: Option<u64> = Option::deserialize(d)?;
        Ok(opt.map(|secs| UNIX_EPOCH + Duration::from_secs(secs)))
    }
}
