//! Conversion between plain JSON (what serde produces) and Firestore's typed
//! `Value` JSON representation used by the REST API.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::time::{format_rfc3339, now_millis, parse_rfc3339};

const TS_MARKER: &str = "__yyds_timestamp__";
const GEO_MARKER: &str = "__yyds_geopoint__";
const REF_MARKER: &str = "__yyds_reference__";
const BYTES_MARKER: &str = "__yyds_bytes__";

// ------------------------------------------------------------------ types

/// Firestore `timestamp` value. Stored as a native timestamp (sortable,
/// usable in rules); read back from any RFC 3339 string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}

impl Timestamp {
    pub fn now() -> Self {
        Self::from_millis(now_millis())
    }
    pub fn from_millis(ms: i64) -> Self {
        Self {
            seconds: ms.div_euclid(1000),
            nanos: (ms.rem_euclid(1000) as u32) * 1_000_000,
        }
    }
    pub fn to_millis(&self) -> i64 {
        self.seconds * 1000 + (self.nanos / 1_000_000) as i64
    }
    pub fn to_rfc3339(&self) -> String {
        format_rfc3339(self.seconds, self.nanos)
    }
    pub fn parse(s: &str) -> Option<Self> {
        parse_rfc3339(s).map(|(seconds, nanos)| Self { seconds, nanos })
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry(TS_MARKER, &self.to_rfc3339())?;
        m.end()
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Str(String),
            Marker {
                #[serde(rename = "__yyds_timestamp__")]
                v: String,
            },
        }
        let s = match Repr::deserialize(d)? {
            Repr::Str(s) | Repr::Marker { v: s } => s,
        };
        Timestamp::parse(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid timestamp {s:?}")))
    }
}

/// Firestore `geoPoint` value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GeoPoint {
    pub latitude: f64,
    pub longitude: f64,
}

impl Serialize for GeoPoint {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        json!({ GEO_MARKER: { "latitude": self.latitude, "longitude": self.longitude } })
            .serialize(s)
    }
}

impl<'de> Deserialize<'de> for GeoPoint {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct LatLng {
            #[serde(default)]
            latitude: f64,
            #[serde(default)]
            longitude: f64,
        }
        let v = LatLng::deserialize(d)?;
        Ok(GeoPoint {
            latitude: v.latitude,
            longitude: v.longitude,
        })
    }
}

/// Firestore `reference` value: full document name
/// (`projects/{p}/databases/{db}/documents/{path}`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reference(pub String);

impl Serialize for Reference {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        json!({ REF_MARKER: self.0 }).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Reference {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d).map(Reference)
    }
}

/// Firestore `bytes` value. Read back as a base64 string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Bytes(pub Vec<u8>);

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use base64::Engine;
        json!({ BYTES_MARKER: base64::engine::general_purpose::STANDARD.encode(&self.0) })
            .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use base64::Engine;
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map(Bytes)
            .map_err(serde::de::Error::custom)
    }
}

// -------------------------------------------------------------- encoding

/// Serialise any `T: Serialize` into Firestore `fields` (the value must be a map / struct).
pub(crate) fn to_fields<T: Serialize + ?Sized>(data: &T) -> Result<Map<String, Value>> {
    match serde_json::to_value(data)? {
        Value::Object(m) => Ok(encode_map(m)),
        other => Err(Error::InvalidArgument(format!(
            "document data must serialise to a map/struct, got {}",
            type_name(&other)
        ))),
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "map",
    }
}

fn encode_map(m: Map<String, Value>) -> Map<String, Value> {
    m.into_iter().map(|(k, v)| (k, encode_value(v))).collect()
}

/// Plain JSON → Firestore `Value`.
pub(crate) fn encode_value(v: Value) -> Value {
    match v {
        Value::Null => json!({ "nullValue": null }),
        Value::Bool(b) => json!({ "booleanValue": b }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                json!({ "integerValue": i.to_string() })
            } else {
                json!({ "doubleValue": n.as_f64().unwrap_or(0.0) })
            }
        }
        Value::String(s) => json!({ "stringValue": s }),
        Value::Array(a) => {
            json!({ "arrayValue": { "values": a.into_iter().map(encode_value).collect::<Vec<_>>() } })
        }
        Value::Object(mut m) => {
            if m.len() == 1 {
                if let Some(Value::String(s)) = m.get(TS_MARKER) {
                    return json!({ "timestampValue": s });
                }
                if let Some(Value::String(s)) = m.get(REF_MARKER) {
                    return json!({ "referenceValue": s });
                }
                if let Some(Value::String(s)) = m.get(BYTES_MARKER) {
                    return json!({ "bytesValue": s });
                }
                if let Some(g) = m.remove(GEO_MARKER) {
                    return json!({ "geoPointValue": g });
                }
            }
            json!({ "mapValue": { "fields": encode_map(m) } })
        }
    }
}

// -------------------------------------------------------------- decoding

/// Firestore `fields` → plain JSON object.
pub(crate) fn from_fields(fields: Map<String, Value>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k, decode_value(v)))
            .collect(),
    )
}

/// Firestore `Value` → plain JSON.
pub(crate) fn decode_value(v: Value) -> Value {
    let Value::Object(mut m) = v else {
        return Value::Null;
    };
    let Some((kind, inner)) = m.iter_mut().next().map(|(k, v)| (k.clone(), v.take())) else {
        return Value::Null;
    };
    match kind.as_str() {
        "nullValue" => Value::Null,
        "booleanValue" => inner,
        "integerValue" => match &inner {
            Value::String(s) => s.parse::<i64>().map(Value::from).unwrap_or(Value::Null),
            _ => inner,
        },
        "doubleValue" => match &inner {
            Value::Number(_) => inner,
            // "NaN" / "Infinity" have no JSON representation.
            _ => Value::Null,
        },
        "timestampValue" | "stringValue" | "bytesValue" | "referenceValue" => inner,
        "geoPointValue" => inner,
        "arrayValue" => {
            let values = match inner {
                Value::Object(mut a) => a.remove("values"),
                _ => None,
            };
            match values {
                Some(Value::Array(vs)) => Value::Array(vs.into_iter().map(decode_value).collect()),
                _ => Value::Array(vec![]),
            }
        }
        "mapValue" => {
            let fields = match inner {
                Value::Object(mut a) => a.remove("fields"),
                _ => None,
            };
            match fields {
                Some(Value::Object(f)) => from_fields(f),
                _ => Value::Object(Map::new()),
            }
        }
        _ => Value::Null,
    }
}

// ----------------------------------------------------------- field paths

/// Quote a single field-path segment if necessary.
pub(crate) fn quote_segment(seg: &str) -> String {
    let simple = !seg.is_empty()
        && seg
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if simple {
        seg.to_string()
    } else {
        format!("`{}`", seg.replace('\\', "\\\\").replace('`', "\\`"))
    }
}

/// Field path from segments, e.g. `["a", "b c"]` → ``a.`b c` ``.
pub(crate) fn field_path(segments: &[&str]) -> String {
    segments
        .iter()
        .map(|s| quote_segment(s))
        .collect::<Vec<_>>()
        .join(".")
}

/// Leaf field paths of an *encoded* fields map (used for merge).
pub(crate) fn leaf_paths(fields: &Map<String, Value>) -> Vec<String> {
    fn walk(prefix: &mut Vec<String>, fields: &Map<String, Value>, out: &mut Vec<String>) {
        for (k, v) in fields {
            prefix.push(k.clone());
            match v
                .get("mapValue")
                .and_then(|m| m.get("fields"))
                .and_then(Value::as_object)
            {
                Some(inner) if !inner.is_empty() => walk(prefix, inner, out),
                _ => out.push(field_path(
                    &prefix.iter().map(String::as_str).collect::<Vec<_>>(),
                )),
            }
            prefix.pop();
        }
    }
    let mut out = Vec::new();
    walk(&mut Vec::new(), fields, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Sample {
        name: String,
        age: i64,
        ratio: f64,
        tags: Vec<String>,
        nested: Inner,
        missing: Option<String>,
        at: Timestamp,
        place: GeoPoint,
        raw: Bytes,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Inner {
        ok: bool,
    }

    #[test]
    fn roundtrip_struct() {
        let s = Sample {
            name: "太郎".into(),
            age: 42,
            ratio: 0.5,
            tags: vec!["a".into(), "b".into()],
            nested: Inner { ok: true },
            missing: None,
            at: Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_000_000,
            },
            place: GeoPoint {
                latitude: 35.68,
                longitude: 139.76,
            },
            raw: Bytes(vec![0, 1, 2, 255]),
        };
        let fields = to_fields(&s).unwrap();
        assert_eq!(fields["age"], json!({"integerValue": "42"}));
        assert_eq!(fields["ratio"], json!({"doubleValue": 0.5}));
        assert_eq!(fields["missing"], json!({"nullValue": null}));
        assert_eq!(
            fields["at"],
            json!({"timestampValue": "2023-11-14T22:13:20.123000000Z"})
        );
        assert_eq!(
            fields["place"],
            json!({"geoPointValue": {"latitude": 35.68, "longitude": 139.76}})
        );
        assert_eq!(fields["raw"], json!({"bytesValue": "AAEC/w=="}));
        assert_eq!(
            fields["nested"],
            json!({"mapValue": {"fields": {"ok": {"booleanValue": true}}}})
        );
        let back: Sample = serde_json::from_value(from_fields(fields)).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn decodes_server_shapes() {
        let v = decode_value(json!({"timestampValue": "2024-01-01T00:00:00Z"}));
        let t: Timestamp = serde_json::from_value(v).unwrap();
        assert_eq!(t.seconds, 1_704_067_200);
        assert_eq!(decode_value(json!({"arrayValue": {}})), json!([]));
        assert_eq!(decode_value(json!({"mapValue": {}})), json!({}));
        assert_eq!(decode_value(json!({"doubleValue": "NaN"})), Value::Null);
        assert_eq!(
            decode_value(json!({"integerValue": "-9007199254740993"})),
            json!(-9007199254740993i64)
        );
    }

    #[test]
    fn rejects_non_map() {
        assert!(to_fields(&5).is_err());
    }

    #[test]
    fn paths() {
        assert_eq!(quote_segment("abc_1"), "abc_1");
        assert_eq!(quote_segment("1abc"), "`1abc`");
        assert_eq!(quote_segment("a`b"), "`a\\`b`");
        let f = to_fields(&json!({"a": {"b": 1, "c d": {"e": 2}}, "z": {}, "y": 3})).unwrap();
        let mut p = leaf_paths(&f);
        p.sort();
        assert_eq!(p, vec!["a.`c d`.e", "a.b", "y", "z"]);
    }
}
