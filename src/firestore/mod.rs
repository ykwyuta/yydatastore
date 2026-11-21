//! Cloud Firestore (REST API v1).

mod value;

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use value::{
    decode_value, encode_value, field_path, from_fields, leaf_paths, quote_segment, to_fields,
};
pub use value::{Bytes, GeoPoint, Reference, Timestamp};

use crate::auth::Auth;
use crate::error::{Error, Result};
use crate::http::send_json;
use crate::AppInner;

/// Firestore handle. Cheap to clone.
#[derive(Clone)]
pub struct Firestore {
    inner: Arc<FsInner>,
}

struct FsInner {
    app: Arc<AppInner>,
    auth: Auth,
}

/// A document read from Firestore.
#[derive(Debug, Clone)]
pub struct Document<T> {
    /// Document ID (last path segment).
    pub id: String,
    /// Path relative to the database root, e.g. `users/alice`.
    pub path: String,
    pub data: T,
    pub create_time: Option<Timestamp>,
    pub update_time: Option<Timestamp>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDocument {
    name: String,
    #[serde(default)]
    fields: Map<String, Value>,
    #[serde(default)]
    create_time: Option<String>,
    #[serde(default)]
    update_time: Option<String>,
}

/// One page of [`CollectionRef::list`].
#[derive(Debug, Clone)]
pub struct ListPage<T> {
    pub documents: Vec<Document<T>>,
    /// Pass to the next `list` call; `None` on the last page.
    pub next_page_token: Option<String>,
}

impl Firestore {
    pub(crate) fn new(app: Arc<AppInner>, auth: Auth) -> Self {
        Self {
            inner: Arc::new(FsInner { app, auth }),
        }
    }

    /// Reference to a top-level (or slash-separated nested) collection, e.g.
    /// `"users"` or `"users/alice/posts"`.
    pub fn collection(&self, path: &str) -> CollectionRef {
        CollectionRef {
            db: self.clone(),
            path: normalize(path),
        }
    }

    /// Reference to a document by slash-separated path, e.g. `"users/alice"`.
    pub fn doc(&self, path: &str) -> DocumentRef {
        DocumentRef {
            db: self.clone(),
            path: normalize(path),
        }
    }

    /// `projects/{p}/databases/{db}/documents`
    pub fn documents_root(&self) -> String {
        let c = &self.inner.app.config;
        format!(
            "projects/{}/databases/{}/documents",
            c.project_id, c.database_id
        )
    }

    fn base_url(&self) -> String {
        match &self.inner.app.config.firestore_emulator_host {
            Some(h) => format!("http://{h}/v1"),
            None => "https://firestore.googleapis.com/v1".to_string(),
        }
    }

    /// Full URL for a relative path (each segment percent-encoded).
    fn url_for(&self, rel_path: &str) -> String {
        let mut url = format!("{}/{}", self.base_url(), self.documents_root());
        for seg in rel_path.split('/').filter(|s| !s.is_empty()) {
            url.push('/');
            url.push_str(&encode_segment(seg));
        }
        url
    }

    async fn request(
        &self,
        method: reqwest::Method,
        url: String,
    ) -> Result<reqwest::RequestBuilder> {
        let mut req = self.inner.app.http.request(method, url);
        match self.inner.auth.id_token().await {
            Ok(tok) => req = req.bearer_auth(tok),
            Err(Error::NotSignedIn) => {
                // Unauthenticated access (only allowed if the rules permit it).
                req = req.query(&[("key", self.inner.app.config.api_key.as_str())]);
            }
            Err(e) => return Err(e),
        }
        Ok(req)
    }

    fn convert<T: DeserializeOwned>(&self, raw: RawDocument) -> Result<Document<T>> {
        let root = self.documents_root();
        let path = raw
            .name
            .strip_prefix(&root)
            .map(|p| p.trim_start_matches('/').to_string())
            .unwrap_or_else(|| raw.name.clone());
        Ok(Document {
            id: path.rsplit('/').next().unwrap_or_default().to_string(),
            data: serde_json::from_value(from_fields(raw.fields))?,
            create_time: raw.create_time.as_deref().and_then(Timestamp::parse),
            update_time: raw.update_time.as_deref().and_then(Timestamp::parse),
            path,
        })
    }
}

fn normalize(path: &str) -> String {
    path.split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn encode_segment(seg: &str) -> String {
    url::form_urlencoded::byte_serialize(seg.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

fn segment_count(path: &str) -> usize {
    path.split('/').filter(|s| !s.is_empty()).count()
}

// =====================================================================
// DocumentRef
// =====================================================================

/// Reference to a single document.
#[derive(Clone)]
pub struct DocumentRef {
    db: Firestore,
    path: String,
}

impl std::fmt::Debug for DocumentRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DocumentRef").field(&self.path).finish()
    }
}

impl DocumentRef {
    pub fn id(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or_default()
    }

    /// Path relative to the database root, e.g. `users/alice`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Value to store in another document's field to reference this one.
    pub fn as_reference(&self) -> Reference {
        Reference(format!("{}/{}", self.db.documents_root(), self.path))
    }

    /// Sub-collection of this document.
    pub fn collection(&self, id: &str) -> CollectionRef {
        CollectionRef {
            db: self.db.clone(),
            path: format!("{}/{}", self.path, normalize(id)),
        }
    }

    fn check(&self) -> Result<()> {
        let n = segment_count(&self.path);
        if n == 0 || n % 2 != 0 {
            return Err(Error::InvalidArgument(format!(
                "document path must have an even number of segments: {:?}",
                self.path
            )));
        }
        Ok(())
    }

    /// Read the document. Returns `Ok(None)` if it does not exist.
    pub async fn get<T: DeserializeOwned>(&self) -> Result<Option<Document<T>>> {
        self.check()?;
        let req = self
            .db
            .request(reqwest::Method::GET, self.db.url_for(&self.path))
            .await?;
        match send_json::<RawDocument>(req).await {
            Ok(raw) => Ok(Some(self.db.convert(raw)?)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Create or **overwrite** the whole document.
    pub async fn set<T: Serialize + ?Sized>(&self, data: &T) -> Result<()> {
        self.check()?;
        let fields = to_fields(data)?;
        self.patch(fields, None, None).await
    }

    /// Create the document, failing with `ALREADY_EXISTS` if it exists.
    pub async fn create<T: Serialize + ?Sized>(&self, data: &T) -> Result<()> {
        self.check()?;
        let fields = to_fields(data)?;
        self.patch(fields, None, Some(false)).await
    }

    /// Create or deep-merge into the document (like `set(..., { merge: true })`
    /// in the JS SDK): only the given leaf fields are written.
    pub async fn merge<T: Serialize + ?Sized>(&self, data: &T) -> Result<()> {
        self.check()?;
        let fields = to_fields(data)?;
        let mask = leaf_paths(&fields);
        self.patch(fields, Some(mask), None).await
    }

    /// Update fields of an **existing** document (fails with `NOT_FOUND`
    /// otherwise). Top-level keys are field paths; use dots for nested fields,
    /// e.g. `json!({"profile.age": 31, "score": 10})`. A given field replaces
    /// the whole existing value at that path.
    pub async fn update<T: Serialize + ?Sized>(&self, data: &T) -> Result<()> {
        self.check()?;
        let Value::Object(m) = serde_json::to_value(data)? else {
            return Err(Error::InvalidArgument(
                "update data must be a map/struct".into(),
            ));
        };
        let mut fields = Map::new();
        let mut mask = Vec::new();
        for (key, v) in m {
            let segs: Vec<&str> = key.split('.').collect();
            if segs.iter().any(|s| s.is_empty()) {
                return Err(Error::InvalidArgument(format!(
                    "invalid field path {key:?}"
                )));
            }
            mask.push(field_path(&segs));
            insert_path(&mut fields, &segs, encode_value(v));
        }
        self.patch(fields, Some(mask), Some(true)).await
    }

    /// Delete specific fields (dot-separated paths) of an existing document.
    pub async fn delete_fields(&self, paths: &[&str]) -> Result<()> {
        self.check()?;
        let mask = paths
            .iter()
            .map(|p| field_path(&p.split('.').collect::<Vec<_>>()))
            .collect();
        self.patch(Map::new(), Some(mask), Some(true)).await
    }

    async fn patch(
        &self,
        fields: Map<String, Value>,
        mask: Option<Vec<String>>,
        exists: Option<bool>,
    ) -> Result<()> {
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(mask) = mask {
            for p in mask {
                query.push(("updateMask.fieldPaths", p));
            }
        }
        if let Some(e) = exists {
            query.push(("currentDocument.exists", e.to_string()));
        }
        // Don't echo the document back.
        query.push(("mask.fieldPaths", "__name__".into()));
        let req = self
            .db
            .request(reqwest::Method::PATCH, self.db.url_for(&self.path))
            .await?
            .query(&query)
            .json(&json!({ "fields": fields }));
        send_json::<Value>(req).await.map(|_| ())
    }

    /// Delete the document (succeeds if it does not exist).
    pub async fn delete(&self) -> Result<()> {
        self.check()?;
        let req = self
            .db
            .request(reqwest::Method::DELETE, self.db.url_for(&self.path))
            .await?;
        send_json::<Value>(req).await.map(|_| ())
    }
}

fn insert_path(fields: &mut Map<String, Value>, segs: &[&str], v: Value) {
    if segs.len() == 1 {
        fields.insert(segs[0].to_string(), v);
        return;
    }
    let entry = fields
        .entry(segs[0].to_string())
        .or_insert_with(|| json!({ "mapValue": { "fields": {} } }));
    if entry.get("mapValue").is_none() {
        *entry = json!({ "mapValue": { "fields": {} } });
    }
    let inner = entry["mapValue"]["fields"]
        .as_object_mut()
        .expect("map fields");
    insert_path(inner, &segs[1..], v);
}

// =====================================================================
// CollectionRef
// =====================================================================

/// Reference to a collection.
#[derive(Clone)]
pub struct CollectionRef {
    db: Firestore,
    path: String,
}

impl std::fmt::Debug for CollectionRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CollectionRef").field(&self.path).finish()
    }
}

impl CollectionRef {
    pub fn id(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or_default()
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn doc(&self, id: &str) -> DocumentRef {
        DocumentRef {
            db: self.db.clone(),
            path: format!("{}/{}", self.path, normalize(id)),
        }
    }

    fn check(&self) -> Result<()> {
        if segment_count(&self.path) % 2 != 1 {
            return Err(Error::InvalidArgument(format!(
                "collection path must have an odd number of segments: {:?}",
                self.path
            )));
        }
        Ok(())
    }

    /// Parent document path ("" for top-level collections).
    fn parent_path(&self) -> &str {
        self.path.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
    }

    /// Add a document with an auto-generated ID.
    pub async fn add<T: Serialize + ?Sized>(&self, data: &T) -> Result<DocumentRef> {
        self.check()?;
        let fields = to_fields(data)?;
        let req = self
            .db
            .request(reqwest::Method::POST, self.db.url_for(&self.path))
            .await?
            .query(&[("mask.fieldPaths", "__name__")])
            .json(&json!({ "fields": fields }));
        let raw: RawDocument = send_json(req).await?;
        let id = raw.name.rsplit('/').next().unwrap_or_default().to_string();
        Ok(self.doc(&id))
    }

    /// List documents, one page at a time.
    pub async fn list<T: DeserializeOwned>(
        &self,
        page_size: u32,
        page_token: Option<&str>,
    ) -> Result<ListPage<T>> {
        self.check()?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            #[serde(default)]
            documents: Vec<RawDocument>,
            #[serde(default)]
            next_page_token: Option<String>,
        }
        let mut q = vec![("pageSize", page_size.to_string())];
        if let Some(t) = page_token {
            q.push(("pageToken", t.to_string()));
        }
        let req = self
            .db
            .request(reqwest::Method::GET, self.db.url_for(&self.path))
            .await?
            .query(&q);
        let r: Resp = send_json(req).await?;
        Ok(ListPage {
            documents: r
                .documents
                .into_iter()
                .map(|d| self.db.convert(d))
                .collect::<Result<_>>()?,
            next_page_token: r.next_page_token.filter(|t| !t.is_empty()),
        })
    }

    /// Start building a query on this collection.
    pub fn query(&self) -> Query {
        Query {
            collection: self.clone(),
            filters: Vec::new(),
            order_by: Vec::new(),
            limit: None,
            offset: None,
        }
    }
}

// =====================================================================
// Query
// =====================================================================

/// Comparison operators for [`Query::filter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    ArrayContains,
    In,
    ArrayContainsAny,
    NotIn,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Lt => "LESS_THAN",
            Op::Le => "LESS_THAN_OR_EQUAL",
            Op::Gt => "GREATER_THAN",
            Op::Ge => "GREATER_THAN_OR_EQUAL",
            Op::Eq => "EQUAL",
            Op::Ne => "NOT_EQUAL",
            Op::ArrayContains => "ARRAY_CONTAINS",
            Op::In => "IN",
            Op::ArrayContainsAny => "ARRAY_CONTAINS_ANY",
            Op::NotIn => "NOT_IN",
        }
    }
}

/// Sort direction for [`Query::order_by`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Asc,
    Desc,
}

/// A structured query over one collection (filters are AND-ed).
#[derive(Clone, Debug)]
pub struct Query {
    collection: CollectionRef,
    filters: Vec<Value>,
    order_by: Vec<Value>,
    limit: Option<u32>,
    offset: Option<u32>,
}

fn query_field_path(path: &str) -> String {
    path.split('.')
        .map(quote_segment)
        .collect::<Vec<_>>()
        .join(".")
}

impl Query {
    /// Add a filter. `field` may be a dot-separated path.
    pub fn filter<V: Serialize>(mut self, field: &str, op: Op, value: V) -> Result<Self> {
        let v = encode_value(serde_json::to_value(value)?);
        self.filters.push(json!({
            "fieldFilter": {
                "field": { "fieldPath": query_field_path(field) },
                "op": op.as_str(),
                "value": v,
            }
        }));
        Ok(self)
    }

    /// Shorthand for `filter(field, Op::Eq, value)`.
    pub fn where_eq<V: Serialize>(self, field: &str, value: V) -> Result<Self> {
        self.filter(field, Op::Eq, value)
    }

    pub fn order_by(mut self, field: &str, dir: Direction) -> Self {
        self.order_by.push(json!({
            "field": { "fieldPath": query_field_path(field) },
            "direction": if dir == Direction::Asc { "ASCENDING" } else { "DESCENDING" },
        }));
        self
    }

    pub fn limit(mut self, n: u32) -> Self {
        self.limit = Some(n);
        self
    }

    pub fn offset(mut self, n: u32) -> Self {
        self.offset = Some(n);
        self
    }

    fn structured_query(&self) -> Value {
        let mut q = Map::new();
        q.insert(
            "from".into(),
            json!([{ "collectionId": self.collection.id() }]),
        );
        match self.filters.len() {
            0 => {}
            1 => {
                q.insert("where".into(), self.filters[0].clone());
            }
            _ => {
                q.insert(
                    "where".into(),
                    json!({ "compositeFilter": { "op": "AND", "filters": self.filters } }),
                );
            }
        }
        if !self.order_by.is_empty() {
            q.insert("orderBy".into(), Value::Array(self.order_by.clone()));
        }
        if let Some(l) = self.limit {
            q.insert("limit".into(), json!(l));
        }
        if let Some(o) = self.offset {
            q.insert("offset".into(), json!(o));
        }
        Value::Object(q)
    }

    /// Run the query.
    pub async fn get<T: DeserializeOwned>(&self) -> Result<Vec<Document<T>>> {
        self.collection.check()?;
        let db = &self.collection.db;
        let url = format!("{}:runQuery", db.url_for(self.collection.parent_path()));
        #[derive(Deserialize)]
        struct Item {
            #[serde(default)]
            document: Option<RawDocument>,
        }
        let req = db
            .request(reqwest::Method::POST, url)
            .await?
            .json(&json!({ "structuredQuery": self.structured_query() }));
        let items: Vec<Item> = send_json(req).await?;
        items
            .into_iter()
            .filter_map(|i| i.document)
            .map(|d| db.convert(d))
            .collect()
    }
}

/// Decode a raw Firestore `Value` JSON into plain JSON (useful for debugging).
pub fn decode_firestore_value(v: Value) -> Value {
    decode_value(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Firebase, FirebaseConfig};

    fn db() -> Firestore {
        Firebase::new(FirebaseConfig::new("proj", "key"))
            .firestore()
            .clone()
    }

    #[test]
    fn urls() {
        let db = db();
        assert_eq!(
            db.url_for("users/a b"),
            "https://firestore.googleapis.com/v1/projects/proj/databases/(default)/documents/users/a%20b"
        );
        let c = db.collection("/users/").doc("u1").collection("posts");
        assert_eq!(c.path(), "users/u1/posts");
        assert_eq!(c.parent_path(), "users/u1");
        assert!(db.doc("users").check().is_err());
        assert!(db.doc("users/x").check().is_ok());
    }

    #[test]
    fn structured_query() {
        let q = db()
            .collection("users")
            .query()
            .where_eq("profile.age", 3)
            .unwrap()
            .filter("score", Op::Gt, 1.5)
            .unwrap()
            .order_by("score", Direction::Desc)
            .limit(10);
        let sq = q.structured_query();
        assert_eq!(sq["from"][0]["collectionId"], "users");
        assert_eq!(
            sq["where"]["compositeFilter"]["filters"][0]["fieldFilter"]["field"]["fieldPath"],
            "profile.age"
        );
        assert_eq!(
            sq["where"]["compositeFilter"]["filters"][0]["fieldFilter"]["value"],
            json!({"integerValue":"3"})
        );
        assert_eq!(sq["orderBy"][0]["direction"], "DESCENDING");
        assert_eq!(sq["limit"], 10);
    }

    #[test]
    fn nested_update_fields() {
        let mut f = Map::new();
        insert_path(&mut f, &["a", "b"], json!({"integerValue": "1"}));
        insert_path(&mut f, &["a", "c"], json!({"integerValue": "2"}));
        assert_eq!(
            Value::Object(f),
            json!({"a": {"mapValue": {"fields": {"b": {"integerValue": "1"}, "c": {"integerValue": "2"}}}}})
        );
    }
}
