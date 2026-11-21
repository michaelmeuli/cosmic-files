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

/// (De)serializes a `Vec<u8>` of ASCII (e.g. a gapped alignment row) as a JSON string.
///
/// serde_json writes a plain `Vec<u8>` as an array of numbers (`[65,67,...]`, ~3.5 bytes per
/// base). Deserialization also accepts that old array form, so existing caches still load.
pub mod ascii_bytes {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        match std::str::from_utf8(bytes) {
            Ok(text) => s.serialize_str(text),
            // Not valid UTF-8: keep it lossless as a byte array (still readable below).
            Err(_) => s.collect_seq(bytes),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct BytesVisitor;

        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string or an array of bytes")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
                Ok(v.as_bytes().to_vec())
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }

        d.deserialize_any(BytesVisitor)
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
