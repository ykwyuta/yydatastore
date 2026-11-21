//! JavaScript bindings (enable feature `js`, build with `wasm-pack build --features js`).
//!
//! ```js
//! import init, { FirebaseClient } from "./pkg/yydatastore.js";
//! await init();
//! const fb = new FirebaseClient({ projectId: "...", apiKey: "..." });
//! const user = await fb.signInWithGooglePopup({ clientId: "...", redirectUri: location.origin + "/oauth-callback.html" });
//! await fb.setDoc(`users/${user.uid}`, { name: "Alice", score: 42 });
//! const doc = await fb.getDoc(`users/${user.uid}`);
//! ```

use serde::Serialize;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::auth::google::WebOAuthConfig;
use crate::{Document, Error, Firebase, FirebaseConfig, Session};

fn to_js<T: Serialize>(v: &T) -> Result<JsValue, JsValue> {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsValue::from(JsError::new(&e.to_string())))
}

fn from_js<T: serde::de::DeserializeOwned>(v: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(v).map_err(|e| JsValue::from(JsError::new(&e.to_string())))
}

fn err(e: Error) -> JsValue {
    let o = js_sys::Error::new(&e.to_string());
    if let Error::Api { code, status, .. } = &e {
        let _ = js_sys::Reflect::set(&o, &"code".into(), &code.into());
        let _ = js_sys::Reflect::set(&o, &"status".into(), &(*status).into());
    }
    o.into()
}

#[derive(Serialize)]
struct JsDoc {
    id: String,
    path: String,
    data: Value,
    #[serde(rename = "updateTime")]
    update_time: Option<String>,
}

impl From<Document<Value>> for JsDoc {
    fn from(d: Document<Value>) -> Self {
        JsDoc {
            id: d.id,
            path: d.path,
            data: d.data,
            update_time: d.update_time.map(|t| t.to_rfc3339()),
        }
    }
}

/// Firebase client for JavaScript.
#[wasm_bindgen]
pub struct FirebaseClient {
    fb: Firebase,
}

#[wasm_bindgen]
impl FirebaseClient {
    /// `config`: `{ projectId, apiKey, databaseId?, authEmulatorHost?, firestoreEmulatorHost? }`
    #[wasm_bindgen(constructor)]
    pub fn new(config: JsValue) -> Result<FirebaseClient, JsValue> {
        let config: FirebaseConfig = from_js(config)?;
        Ok(Self {
            fb: Firebase::new(config),
        })
    }

    // ------------------------------------------------------------ auth

    /// `oauth`: `{ clientId, redirectUri, scopes?, loginHint? }`. Resolves to the user.
    #[wasm_bindgen(js_name = signInWithGooglePopup)]
    pub fn sign_in_with_google_popup(&self, oauth: JsValue) -> Result<js_sys::Promise, JsValue> {
        let cfg: WebOAuthConfig = from_js(oauth)?;
        let fb = self.fb.clone();
        Ok(future_to_promise(async move {
            let u = fb
                .auth()
                .sign_in_with_google_popup(&cfg)
                .await
                .map_err(err)?;
            to_js(&u)
        }))
    }

    /// Navigates away to Google. Call `completeGoogleRedirect()` on page load.
    #[wasm_bindgen(js_name = signInWithGoogleRedirect)]
    pub fn sign_in_with_google_redirect(&self, oauth: JsValue) -> Result<(), JsValue> {
        let cfg: WebOAuthConfig = from_js(oauth)?;
        self.fb
            .auth()
            .sign_in_with_google_redirect(&cfg)
            .map_err(err)
    }

    /// Resolves to the user, or `null` if the page was not loaded from a sign-in redirect.
    #[wasm_bindgen(js_name = completeGoogleRedirect)]
    pub fn complete_google_redirect(&self) -> js_sys::Promise {
        let fb = self.fb.clone();
        future_to_promise(async move {
            let u = fb.auth().complete_google_redirect().await.map_err(err)?;
            to_js(&u)
        })
    }

    /// Sign in with a Google ID token obtained elsewhere (e.g. Google Identity Services).
    #[wasm_bindgen(js_name = signInWithGoogleIdToken)]
    pub fn sign_in_with_google_id_token(&self, id_token: String) -> js_sys::Promise {
        let fb = self.fb.clone();
        future_to_promise(async move {
            let u = fb
                .auth()
                .sign_in_with_google_id_token(&id_token)
                .await
                .map_err(err)?;
            to_js(&u)
        })
    }

    #[wasm_bindgen(js_name = currentUser)]
    pub fn current_user(&self) -> Result<JsValue, JsValue> {
        to_js(&self.fb.auth().current_user())
    }

    /// Session as a JSON string (store it to stay signed in), or `undefined`.
    #[wasm_bindgen(js_name = sessionJson)]
    pub fn session_json(&self) -> Option<String> {
        self.fb.auth().session().map(|s| s.to_json())
    }

    #[wasm_bindgen(js_name = restoreSessionJson)]
    pub fn restore_session_json(&self, json: &str) -> Result<(), JsValue> {
        let s = Session::from_json(json).map_err(err)?;
        self.fb.auth().restore_session(s);
        Ok(())
    }

    /// Persist the session in `localStorage` under `key`.
    #[wasm_bindgen(js_name = saveSessionToLocalStorage)]
    pub fn save_session(&self, key: &str) -> Result<(), JsValue> {
        match self.fb.auth().session() {
            Some(s) => {
                crate::auth::google::web::save_session_to_local_storage(key, &s).map_err(err)
            }
            None => crate::auth::google::web::remove_session_from_local_storage(key).map_err(err),
        }
    }

    /// Restore a session saved with `saveSessionToLocalStorage`. Returns the user or `null`.
    #[wasm_bindgen(js_name = loadSessionFromLocalStorage)]
    pub fn load_session(&self, key: &str) -> Result<JsValue, JsValue> {
        let s = crate::auth::google::web::load_session_from_local_storage(key).map_err(err)?;
        let user = s.as_ref().map(|s| s.user.clone());
        if let Some(s) = s {
            self.fb.auth().restore_session(s);
        }
        to_js(&user)
    }

    #[wasm_bindgen(js_name = signOut)]
    pub fn sign_out(&self) {
        self.fb.auth().sign_out();
    }

    /// Fresh Firebase ID token (refreshed automatically).
    #[wasm_bindgen(js_name = idToken)]
    pub fn id_token(&self) -> js_sys::Promise {
        let fb = self.fb.clone();
        future_to_promise(async move { Ok(fb.auth().id_token().await.map_err(err)?.into()) })
    }

    // ------------------------------------------------------- firestore

    /// Resolves to `{ id, path, data, updateTime }` or `null`.
    #[wasm_bindgen(js_name = getDoc)]
    pub fn get_doc(&self, path: String) -> js_sys::Promise {
        let fb = self.fb.clone();
        future_to_promise(async move {
            let d = fb
                .firestore()
                .doc(&path)
                .get::<Value>()
                .await
                .map_err(err)?;
            to_js(&d.map(JsDoc::from))
        })
    }

    /// Create or overwrite.
    #[wasm_bindgen(js_name = setDoc)]
    pub fn set_doc(&self, path: String, data: JsValue) -> Result<js_sys::Promise, JsValue> {
        let data: Value = from_js(data)?;
        let fb = self.fb.clone();
        Ok(future_to_promise(async move {
            fb.firestore().doc(&path).set(&data).await.map_err(err)?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Create or deep-merge (`setDoc(..., { merge: true })`).
    #[wasm_bindgen(js_name = mergeDoc)]
    pub fn merge_doc(&self, path: String, data: JsValue) -> Result<js_sys::Promise, JsValue> {
        let data: Value = from_js(data)?;
        let fb = self.fb.clone();
        Ok(future_to_promise(async move {
            fb.firestore().doc(&path).merge(&data).await.map_err(err)?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Update an existing document; keys may be dotted field paths.
    #[wasm_bindgen(js_name = updateDoc)]
    pub fn update_doc(&self, path: String, data: JsValue) -> Result<js_sys::Promise, JsValue> {
        let data: Value = from_js(data)?;
        let fb = self.fb.clone();
        Ok(future_to_promise(async move {
            fb.firestore().doc(&path).update(&data).await.map_err(err)?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    #[wasm_bindgen(js_name = deleteDoc)]
    pub fn delete_doc(&self, path: String) -> js_sys::Promise {
        let fb = self.fb.clone();
        future_to_promise(async move {
            fb.firestore().doc(&path).delete().await.map_err(err)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Add with an auto ID. Resolves to the new document path.
    #[wasm_bindgen(js_name = addDoc)]
    pub fn add_doc(
        &self,
        collection_path: String,
        data: JsValue,
    ) -> Result<js_sys::Promise, JsValue> {
        let data: Value = from_js(data)?;
        let fb = self.fb.clone();
        Ok(future_to_promise(async move {
            let r = fb
                .firestore()
                .collection(&collection_path)
                .add(&data)
                .await
                .map_err(err)?;
            Ok(r.path().into())
        }))
    }

    /// Resolves to `{ documents: [...], nextPageToken }`.
    #[wasm_bindgen(js_name = listDocs)]
    pub fn list_docs(
        &self,
        collection_path: String,
        page_size: u32,
        page_token: Option<String>,
    ) -> js_sys::Promise {
        let fb = self.fb.clone();
        future_to_promise(async move {
            let page = fb
                .firestore()
                .collection(&collection_path)
                .list::<Value>(page_size, page_token.as_deref())
                .await
                .map_err(err)?;
            #[derive(Serialize)]
            struct Out {
                documents: Vec<JsDoc>,
                #[serde(rename = "nextPageToken")]
                next_page_token: Option<String>,
            }
            to_js(&Out {
                documents: page.documents.into_iter().map(JsDoc::from).collect(),
                next_page_token: page.next_page_token,
            })
        })
    }
}
