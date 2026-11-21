//! # yydatastore
//!
//! Pure Rust Firebase client that works both as a **native** library
//! (Windows / macOS / Linux desktop apps) and on **WebAssembly** (browser).
//!
//! Features:
//! - Firebase Authentication with **Google sign-in**
//!   - native: OAuth 2.0 loopback + PKCE flow (opens the system browser) — see [`auth::google`]
//!   - wasm: popup / redirect flow in the browser — see [`auth::google`]
//!   - any platform: sign in with an existing Google ID token / access token
//! - Automatic ID token refresh, serialisable [`auth::Session`] for persistence
//! - **Cloud Firestore** via the REST API with serde (de)serialisation:
//!   get / set / merge / update / delete / add / list / simple queries
//!
//! ```no_run
//! # async fn run() -> yydatastore::Result<()> {
//! use yydatastore::{Firebase, FirebaseConfig};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct Profile { name: String, score: i64 }
//!
//! let fb = Firebase::new(FirebaseConfig::new("my-project-id", "AIza...web-api-key"));
//!
//! // Native (Windows): opens the browser and waits for the Google login.
//! # #[cfg(not(target_arch = "wasm32"))]
//! let user = fb.auth().sign_in_with_google(
//!     &yydatastore::auth::google::DesktopOAuthConfig::new("CLIENT_ID.apps.googleusercontent.com")
//!         .client_secret("GOCSPX-..."),
//! ).await?;
//! # #[cfg(target_arch = "wasm32")]
//! # let user = fb.auth().current_user().unwrap();
//!
//! let doc = fb.firestore().collection("users").doc(&user.uid);
//! doc.set(&Profile { name: "Alice".into(), score: 42 }).await?;
//! let loaded = doc.get::<Profile>().await?;
//! # Ok(()) }
//! ```

pub mod auth;
pub mod error;
pub mod firestore;
mod http;
mod time;

#[cfg(all(target_arch = "wasm32", feature = "js"))]
pub mod js;

use std::sync::Arc;

pub use auth::{Auth, Session, User};
pub use error::{Error, Result};
pub use firestore::{
    CollectionRef, Document, DocumentRef, Firestore, GeoPoint, Query, Reference, Timestamp,
};

/// Firebase project configuration (values from the Firebase console → Project settings).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirebaseConfig {
    /// Project ID, e.g. `my-app-12345`.
    pub project_id: String,
    /// Web API key (`apiKey` in the Firebase web config).
    pub api_key: String,
    /// Firestore database ID. Defaults to `(default)`.
    #[serde(default = "default_database")]
    pub database_id: String,
    /// Optional Auth emulator host, e.g. `127.0.0.1:9099`.
    #[serde(default)]
    pub auth_emulator_host: Option<String>,
    /// Optional Firestore emulator host, e.g. `127.0.0.1:8080`.
    #[serde(default)]
    pub firestore_emulator_host: Option<String>,
}

fn default_database() -> String {
    "(default)".to_string()
}

impl FirebaseConfig {
    pub fn new(project_id: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            project_id: project_id.into(),
            api_key: api_key.into(),
            database_id: default_database(),
            auth_emulator_host: None,
            firestore_emulator_host: None,
        }
    }

    /// Use a non-default Firestore database.
    pub fn database(mut self, database_id: impl Into<String>) -> Self {
        self.database_id = database_id.into();
        self
    }

    /// Route Auth requests to the Firebase Auth emulator (`host:port`).
    pub fn auth_emulator(mut self, host: impl Into<String>) -> Self {
        self.auth_emulator_host = Some(host.into());
        self
    }

    /// Route Firestore requests to the Firestore emulator (`host:port`).
    pub fn firestore_emulator(mut self, host: impl Into<String>) -> Self {
        self.firestore_emulator_host = Some(host.into());
        self
    }
}

pub(crate) struct AppInner {
    pub(crate) config: FirebaseConfig,
    pub(crate) http: reqwest::Client,
}

/// Entry point. Cheap to clone; all clones share the same auth state.
#[derive(Clone)]
pub struct Firebase {
    auth: Auth,
    firestore: Firestore,
}

impl Firebase {
    pub fn new(config: FirebaseConfig) -> Self {
        let app = Arc::new(AppInner {
            config,
            http: http::build_client(),
        });
        let auth = Auth::new(app.clone());
        let firestore = Firestore::new(app, auth.clone());
        Self { auth, firestore }
    }

    pub fn auth(&self) -> &Auth {
        &self.auth
    }

    pub fn firestore(&self) -> &Firestore {
        &self.firestore
    }
}
