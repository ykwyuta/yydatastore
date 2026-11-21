//! Firebase Authentication (Identity Toolkit REST API).

pub mod google;

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::http::send_json;
use crate::time::now_millis;
use crate::AppInner;

/// Refresh the ID token this long before it actually expires.
const REFRESH_MARGIN_MS: i64 = 5 * 60 * 1000;

/// Signed-in user's profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// Firebase UID (`request.auth.uid` in security rules).
    pub uid: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub photo_url: Option<String>,
    /// e.g. `google.com`
    pub provider_id: Option<String>,
}

/// Credentials of a signed-in user. Serialise it (serde / [`Session::to_json`]) to
/// keep the user signed in across app restarts and restore it with
/// [`Auth::restore_session`].
///
/// Treat it like a password: the refresh token grants long-lived access.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id_token: String,
    pub refresh_token: String,
    /// ID token expiry, Unix epoch milliseconds.
    pub expires_at_ms: i64,
    pub user: User,
}

impl Session {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("session is always serialisable")
    }

    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    fn needs_refresh(&self) -> bool {
        now_millis() + REFRESH_MARGIN_MS >= self.expires_at_ms
    }
}

/// Firebase Auth handle. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Auth {
    app: Arc<AppInner>,
    state: Arc<Mutex<Option<Session>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdpResponse {
    id_token: String,
    refresh_token: String,
    expires_in: String,
    local_id: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    photo_url: Option<String>,
    #[serde(default)]
    provider_id: Option<String>,
}

#[derive(Deserialize)]
struct RefreshResponse {
    id_token: String,
    refresh_token: String,
    expires_in: String,
}

impl Auth {
    pub(crate) fn new(app: Arc<AppInner>) -> Self {
        Self {
            app,
            state: Arc::new(Mutex::new(None)),
        }
    }

    fn identity_url(&self, method: &str) -> String {
        let cfg = &self.app.config;
        match &cfg.auth_emulator_host {
            Some(h) => format!("http://{h}/identitytoolkit.googleapis.com/v1/accounts:{method}"),
            None => format!("https://identitytoolkit.googleapis.com/v1/accounts:{method}"),
        }
    }

    fn securetoken_url(&self) -> String {
        match &self.app.config.auth_emulator_host {
            Some(h) => format!("http://{h}/securetoken.googleapis.com/v1/token"),
            None => "https://securetoken.googleapis.com/v1/token".to_string(),
        }
    }

    // ------------------------------------------------------------------ state

    /// Currently signed-in user, if any.
    pub fn current_user(&self) -> Option<User> {
        self.lock().as_ref().map(|s| s.user.clone())
    }

    /// Current session (for persistence). The refresh token does not change on
    /// refresh, so saving it once after sign-in is enough.
    pub fn session(&self) -> Option<Session> {
        self.lock().clone()
    }

    /// Restore a previously saved session. The ID token is refreshed on demand.
    pub fn restore_session(&self, session: Session) {
        *self.lock() = Some(session);
    }

    /// Forget the current session locally.
    pub fn sign_out(&self) {
        *self.lock() = None;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Session>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Valid Firebase ID token for the current user, refreshing it if it is
    /// close to expiry. Use it as `Authorization: Bearer <token>` for Firebase
    /// services or your own backend.
    pub async fn id_token(&self) -> Result<String> {
        let refresh_token = {
            let guard = self.lock();
            let s = guard.as_ref().ok_or(Error::NotSignedIn)?;
            if !s.needs_refresh() {
                return Ok(s.id_token.clone());
            }
            s.refresh_token.clone()
        };
        self.refresh_with(&refresh_token).await?;
        self.lock()
            .as_ref()
            .map(|s| s.id_token.clone())
            .ok_or(Error::NotSignedIn)
    }

    /// Force an ID token refresh.
    pub async fn refresh(&self) -> Result<()> {
        let rt = self
            .lock()
            .as_ref()
            .map(|s| s.refresh_token.clone())
            .ok_or(Error::NotSignedIn)?;
        self.refresh_with(&rt).await
    }

    async fn refresh_with(&self, refresh_token: &str) -> Result<()> {
        let req = self
            .app
            .http
            .post(self.securetoken_url())
            .query(&[("key", self.app.config.api_key.as_str())])
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ]);
        let r: RefreshResponse = send_json(req).await?;
        let mut guard = self.lock();
        if let Some(s) = guard.as_mut() {
            // Ignore the result if the user signed out / switched meanwhile.
            if s.refresh_token == refresh_token {
                s.id_token = r.id_token;
                s.refresh_token = r.refresh_token;
                s.expires_at_ms = now_millis() + parse_expires_in(&r.expires_in);
            }
        }
        Ok(())
    }

    // --------------------------------------------------------------- sign-in

    /// Sign in to Firebase with a Google **ID token** (OpenID Connect JWT)
    /// obtained by any means (e.g. your own OAuth flow, Google Identity Services).
    pub async fn sign_in_with_google_id_token(&self, google_id_token: &str) -> Result<User> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("id_token", google_id_token)
            .append_pair("providerId", "google.com")
            .finish();
        self.sign_in_with_idp(body).await
    }

    /// Sign in to Firebase with a Google OAuth **access token**.
    pub async fn sign_in_with_google_access_token(&self, access_token: &str) -> Result<User> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("access_token", access_token)
            .append_pair("providerId", "google.com")
            .finish();
        self.sign_in_with_idp(body).await
    }

    async fn sign_in_with_idp(&self, post_body: String) -> Result<User> {
        let req = self
            .app
            .http
            .post(self.identity_url("signInWithIdp"))
            .query(&[("key", self.app.config.api_key.as_str())])
            .json(&serde_json::json!({
                "postBody": post_body,
                "requestUri": "http://localhost",
                "returnSecureToken": true,
                "returnIdpCredential": true,
            }));
        let r: IdpResponse = send_json(req).await?;
        let session = Session {
            expires_at_ms: now_millis() + parse_expires_in(&r.expires_in),
            id_token: r.id_token,
            refresh_token: r.refresh_token,
            user: User {
                uid: r.local_id,
                email: r.email,
                email_verified: r.email_verified,
                display_name: r.display_name,
                photo_url: r.photo_url,
                provider_id: r.provider_id,
            },
        };
        let user = session.user.clone();
        *self.lock() = Some(session);
        Ok(user)
    }

    /// **Native only.** Full Google sign-in for desktop apps: opens the system
    /// browser, receives the result on a `127.0.0.1` loopback redirect (PKCE),
    /// then signs in to Firebase.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn sign_in_with_google(&self, config: &google::DesktopOAuthConfig) -> Result<User> {
        let tokens = google::desktop_sign_in(&self.app.http, config).await?;
        match tokens.id_token {
            Some(t) => self.sign_in_with_google_id_token(&t).await,
            None => {
                self.sign_in_with_google_access_token(&tokens.access_token)
                    .await
            }
        }
    }

    /// **wasm only.** Google sign-in in a popup window. The page keeps its state.
    /// `redirect_uri` in the config must be a same-origin page registered in the
    /// Google Cloud console (it can be the app page itself).
    #[cfg(target_arch = "wasm32")]
    pub async fn sign_in_with_google_popup(&self, config: &google::WebOAuthConfig) -> Result<User> {
        let id_token = google::web::popup_sign_in(config).await?;
        self.sign_in_with_google_id_token(&id_token).await
    }

    /// **wasm only.** Navigate the current page to Google sign-in. After the
    /// redirect back, call [`Auth::complete_google_redirect`].
    #[cfg(target_arch = "wasm32")]
    pub fn sign_in_with_google_redirect(&self, config: &google::WebOAuthConfig) -> Result<()> {
        google::web::start_redirect(config)
    }

    /// **wasm only.** Finish a redirect sign-in started by
    /// [`Auth::sign_in_with_google_redirect`]. Returns `Ok(None)` if the current
    /// URL is not a sign-in redirect result.
    #[cfg(target_arch = "wasm32")]
    pub async fn complete_google_redirect(&self) -> Result<Option<User>> {
        match google::web::take_redirect_result()? {
            Some(id_token) => Ok(Some(self.sign_in_with_google_id_token(&id_token).await?)),
            None => Ok(None),
        }
    }
}

fn parse_expires_in(s: &str) -> i64 {
    s.parse::<i64>().unwrap_or(3600) * 1000
}
