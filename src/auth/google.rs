//! Google sign-in (OAuth 2.0 / OpenID Connect) flows.
//!
//! * **Native** ([`DesktopOAuthConfig`]): "Desktop app" OAuth client, loopback
//!   redirect on `127.0.0.1` with PKCE — the flow Google recommends for
//!   installed applications such as Windows desktop apps.
//! * **wasm** (`WebOAuthConfig`): "Web application" OAuth client, popup or
//!   full-page redirect, `response_type=id_token`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::{Error, Result};

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
#[cfg(not(target_arch = "wasm32"))]
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DEFAULT_SCOPES: &str = "openid email profile";

/// Cryptographically random URL-safe string (`n_bytes` of entropy).
pub(crate) fn random_token(n_bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; n_bytes];
    getrandom::fill(&mut buf).map_err(|e| Error::OAuth(format!("random generator: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// PKCE S256 code challenge for a verifier.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub(crate) fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Parse `a=b&c=d` (query string or URL fragment) into pairs.
pub(crate) fn parse_params(s: &str) -> Vec<(String, String)> {
    let s = s.trim_start_matches(['?', '#']);
    url::form_urlencoded::parse(s.as_bytes())
        .into_owned()
        .collect()
}

fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Check the OAuth `state` and turn an `error=` response into an [`Error`].
fn check_response(params: &[(String, String)], expected_state: &str) -> Result<()> {
    if let Some(err) = param(params, "error") {
        let desc = param(params, "error_description").unwrap_or("");
        return Err(Error::OAuth(format!("{err} {desc}").trim().to_string()));
    }
    if param(params, "state") != Some(expected_state) {
        return Err(Error::OAuth("state mismatch (possible CSRF)".into()));
    }
    Ok(())
}

// =====================================================================
// Native desktop flow
// =====================================================================

#[cfg(not(target_arch = "wasm32"))]
pub use desktop::*;

#[cfg(not(target_arch = "wasm32"))]
mod desktop {
    use std::sync::Arc;
    use std::time::Duration;

    use serde::Deserialize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::http::send_json;

    /// Callback receiving the Google authorization URL.
    pub type AuthUrlCallback = Arc<dyn Fn(&str) + Send + Sync>;

    /// Settings for [`crate::Auth::sign_in_with_google`].
    ///
    /// Create an OAuth client of type **Desktop app** in the Google Cloud console
    /// (same project as Firebase) and enable the Google provider in Firebase
    /// Authentication. For desktop clients the "client secret" is not
    /// confidential and may be embedded in the application.
    #[derive(Clone)]
    pub struct DesktopOAuthConfig {
        pub client_id: String,
        pub client_secret: Option<String>,
        pub scopes: String,
        /// Loopback port. `0` (default) picks a free port.
        pub port: u16,
        /// Open the system browser automatically (default `true`).
        pub open_browser: bool,
        /// Called with the authorization URL (e.g. to show it in the UI as a fallback).
        pub on_auth_url: Option<AuthUrlCallback>,
        /// Give up after this long (default 5 minutes).
        pub timeout: Duration,
        /// Optional `login_hint` (email address).
        pub login_hint: Option<String>,
        /// HTML shown in the browser tab after the redirect.
        pub success_html: String,
    }

    impl DesktopOAuthConfig {
        pub fn new(client_id: impl Into<String>) -> Self {
            Self {
                client_id: client_id.into(),
                client_secret: None,
                scopes: DEFAULT_SCOPES.into(),
                port: 0,
                open_browser: true,
                on_auth_url: None,
                timeout: Duration::from_secs(300),
                login_hint: None,
                success_html: "<!doctype html><meta charset=utf-8><title>Signed in</title>\
                    <body style=\"font-family:sans-serif;text-align:center;padding-top:4em\">\
                    <h2>サインインが完了しました / Sign-in complete</h2>\
                    <p>このウィンドウを閉じてアプリに戻ってください。<br>You can close this window.</p>"
                    .into(),
            }
        }
        pub fn client_secret(mut self, s: impl Into<String>) -> Self {
            self.client_secret = Some(s.into());
            self
        }
        pub fn scopes(mut self, s: impl Into<String>) -> Self {
            self.scopes = s.into();
            self
        }
        pub fn port(mut self, p: u16) -> Self {
            self.port = p;
            self
        }
        pub fn open_browser(mut self, v: bool) -> Self {
            self.open_browser = v;
            self
        }
        pub fn on_auth_url(mut self, f: impl Fn(&str) + Send + Sync + 'static) -> Self {
            self.on_auth_url = Some(Arc::new(f));
            self
        }
        pub fn timeout(mut self, t: Duration) -> Self {
            self.timeout = t;
            self
        }
        pub fn login_hint(mut self, s: impl Into<String>) -> Self {
            self.login_hint = Some(s.into());
            self
        }
    }

    /// Tokens returned by Google's token endpoint.
    #[derive(Debug, Clone, Deserialize)]
    pub struct GoogleTokens {
        pub access_token: String,
        #[serde(default)]
        pub id_token: Option<String>,
        #[serde(default)]
        pub refresh_token: Option<String>,
        #[serde(default)]
        pub expires_in: Option<i64>,
    }

    /// Run the Google OAuth loopback flow and return Google's tokens
    /// (without signing in to Firebase).
    pub async fn desktop_sign_in(
        http: &reqwest::Client,
        cfg: &DesktopOAuthConfig,
    ) -> Result<GoogleTokens> {
        let listener = TcpListener::bind(("127.0.0.1", cfg.port)).await?;
        let port = listener.local_addr()?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}");

        let state = random_token(24)?;
        let verifier = random_token(48)?; // 64 chars
        let mut url = url::Url::parse(GOOGLE_AUTH_URL).expect("static url");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &cfg.client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", &cfg.scopes)
                .append_pair("state", &state)
                .append_pair("code_challenge", &pkce_challenge(&verifier))
                .append_pair("code_challenge_method", "S256")
                .append_pair("prompt", "select_account");
            if let Some(h) = &cfg.login_hint {
                q.append_pair("login_hint", h);
            }
        }
        let url = url.to_string();

        if let Some(cb) = &cfg.on_auth_url {
            cb(&url);
        }
        if cfg.open_browser {
            open_browser(&url)?;
        }

        let code = tokio::time::timeout(cfg.timeout, wait_for_code(&listener, &state, cfg))
            .await
            .map_err(|_| Error::OAuth("timed out waiting for Google sign-in".into()))??;

        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code),
            ("client_id", cfg.client_id.clone()),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ];
        if let Some(s) = &cfg.client_secret {
            form.push(("client_secret", s.clone()));
        }
        send_json(http.post(GOOGLE_TOKEN_URL).form(&form)).await
    }

    async fn wait_for_code(
        listener: &TcpListener,
        state: &str,
        cfg: &DesktopOAuthConfig,
    ) -> Result<String> {
        loop {
            let (mut stream, _) = listener.accept().await?;
            let mut buf = Vec::with_capacity(2048);
            let mut chunk = [0u8; 1024];
            // Read the request head (we only need the request line).
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let head = String::from_utf8_lossy(&buf);
            let target = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/");
            let (path, query) = target.split_once('?').unwrap_or((target, ""));
            let params = parse_params(query);

            if path != "/"
                || (param(&params, "code").is_none() && param(&params, "error").is_none())
            {
                // favicon.ico or a stray request: ignore and keep waiting.
                let _ = respond(&mut stream, "404 Not Found", "").await;
                continue;
            }

            let result = check_response(&params, state).and_then(|_| {
                param(&params, "code")
                    .map(str::to_string)
                    .ok_or_else(|| Error::OAuth("no authorization code".into()))
            });
            let html = match &result {
                Ok(_) => cfg.success_html.clone(),
                Err(e) => format!(
                    "<!doctype html><meta charset=utf-8><title>Sign-in failed</title>\
                     <h2>サインインに失敗しました / Sign-in failed</h2><pre>{}</pre>",
                    html_escape(&e.to_string())
                ),
            };
            let _ = respond(&mut stream, "200 OK", &html).await;
            return result;
        }
    }

    async fn respond(
        stream: &mut tokio::net::TcpStream,
        status: &str,
        html: &str,
    ) -> std::io::Result<()> {
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
            html.len()
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.shutdown().await
    }

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    /// Open `url` in the user's default browser.
    pub fn open_browser(url: &str) -> Result<()> {
        use std::process::Command;
        #[cfg(target_os = "windows")]
        let mut cmd = {
            // rundll32 avoids cmd.exe's special handling of '&' in URLs.
            let mut c = Command::new("rundll32");
            c.args(["url.dll,FileProtocolHandler", url]);
            c
        };
        #[cfg(target_os = "macos")]
        let mut cmd = {
            let mut c = Command::new("open");
            c.arg(url);
            c
        };
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let mut cmd = {
            let mut c = Command::new("xdg-open");
            c.arg(url);
            c
        };
        cmd.spawn()
            .map(|_| ())
            .map_err(|e| Error::OAuth(format!("failed to open browser: {e}")))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        async fn http_get(port: u16, target: &str) -> String {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            s.write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        }

        #[tokio::test]
        async fn loopback_receives_code() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let cfg = DesktopOAuthConfig::new("cid");
            let client = tokio::spawn(async move {
                let r1 = http_get(port, "/favicon.ico").await;
                assert!(r1.starts_with("HTTP/1.1 404"));
                let r2 = http_get(port, "/?state=st&code=4%2Fabc&scope=email").await;
                assert!(r2.contains("Sign-in complete"));
            });
            let code = wait_for_code(&listener, "st", &cfg).await.unwrap();
            assert_eq!(code, "4/abc");
            client.await.unwrap();
        }

        #[tokio::test]
        async fn loopback_rejects_bad_state_and_errors() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let cfg = DesktopOAuthConfig::new("cid");
            let c = tokio::spawn(async move { http_get(port, "/?state=evil&code=x").await });
            assert!(wait_for_code(&listener, "st", &cfg).await.is_err());
            assert!(c.await.unwrap().contains("Sign-in failed"));
            let c =
                tokio::spawn(async move { http_get(port, "/?error=access_denied&state=st").await });
            let e = wait_for_code(&listener, "st", &cfg).await.unwrap_err();
            assert!(e.to_string().contains("access_denied"));
            c.await.unwrap();
        }
    }
}

// =====================================================================
// Browser (wasm) flow
// =====================================================================

/// Settings for the browser sign-in flows (wasm).
///
/// Use an OAuth client of type **Web application**; add the page origin to
/// "Authorized JavaScript origins" and `redirect_uri` to "Authorized redirect URIs".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebOAuthConfig {
    pub client_id: String,
    /// Same-origin URL Google redirects to. For the popup flow a tiny static page
    /// (e.g. `/oauth-callback.html`) is recommended.
    pub redirect_uri: String,
    #[serde(default = "default_scopes")]
    pub scopes: String,
    #[serde(default)]
    pub login_hint: Option<String>,
}

fn default_scopes() -> String {
    DEFAULT_SCOPES.to_string()
}

impl WebOAuthConfig {
    pub fn new(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scopes: default_scopes(),
            login_hint: None,
        }
    }

    /// Authorization URL for the implicit `id_token` flow.
    pub fn authorization_url(&self, state: &str, nonce: &str) -> String {
        let mut url = url::Url::parse(GOOGLE_AUTH_URL).expect("static url");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", &self.redirect_uri)
                .append_pair("response_type", "id_token")
                .append_pair("scope", &self.scopes)
                .append_pair("state", state)
                .append_pair("nonce", nonce)
                .append_pair("prompt", "select_account");
            if let Some(h) = &self.login_hint {
                q.append_pair("login_hint", h);
            }
        }
        url.to_string()
    }
}

/// Extract the ID token from a redirect URL fragment (`#state=..&id_token=..`).
pub fn id_token_from_fragment(fragment: &str, expected_state: &str) -> Result<String> {
    let params = parse_params(fragment);
    check_response(&params, expected_state)?;
    param(&params, "id_token")
        .map(str::to_string)
        .ok_or_else(|| Error::OAuth("no id_token in response".into()))
}

#[cfg(target_arch = "wasm32")]
pub mod web {
    use wasm_bindgen::JsValue;
    use wasm_bindgen_futures::JsFuture;

    use super::*;

    const STATE_KEY: &str = "yydatastore.oauth.state";

    fn window() -> Result<web_sys::Window> {
        web_sys::window().ok_or_else(|| Error::Browser("no window".into()))
    }

    fn session_storage() -> Result<web_sys::Storage> {
        window()?
            .session_storage()?
            .ok_or_else(|| Error::Browser("sessionStorage unavailable".into()))
    }

    async fn sleep_ms(ms: i32) {
        let p = js_sys::Promise::new(&mut |resolve, _| {
            if let Some(w) = web_sys::window() {
                let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
            }
        });
        let _ = JsFuture::from(p).await;
    }

    /// Open Google sign-in in a popup and wait for the ID token.
    pub async fn popup_sign_in(cfg: &WebOAuthConfig) -> Result<String> {
        let state = random_token(24)?;
        let nonce = random_token(24)?;
        let url = cfg.authorization_url(&state, &nonce);
        let w = window()?;
        let popup = w
            .open_with_url_and_target_and_features(
                &url,
                "yydatastore_google_signin",
                "popup,width=500,height=650",
            )?
            .ok_or_else(|| Error::OAuth("popup blocked by the browser".into()))?;

        loop {
            sleep_ms(250).await;
            if popup.closed().unwrap_or(true) {
                return Err(Error::OAuth("sign-in popup was closed".into()));
            }
            // Throws while the popup is on accounts.google.com (cross-origin).
            let Ok(href) = popup.location().href() else {
                continue;
            };
            if !href.starts_with(&cfg.redirect_uri) {
                continue;
            }
            let hash = popup.location().hash().unwrap_or_default();
            if !(hash.contains("id_token=") || hash.contains("error=")) {
                continue;
            }
            let _ = popup.close();
            return id_token_from_fragment(&hash, &state);
        }
    }

    /// Navigate the current page to Google sign-in.
    pub fn start_redirect(cfg: &WebOAuthConfig) -> Result<()> {
        let state = random_token(24)?;
        let nonce = random_token(24)?;
        session_storage()?.set_item(STATE_KEY, &state)?;
        window()?
            .location()
            .set_href(&cfg.authorization_url(&state, &nonce))?;
        Ok(())
    }

    /// If the current URL carries a redirect result started by
    /// [`start_redirect`], consume it and return the Google ID token.
    pub fn take_redirect_result() -> Result<Option<String>> {
        let w = window()?;
        // Inside our own popup: leave the result for the opener to read.
        if w.opener()
            .map(|o| !o.is_null() && !o.is_undefined())
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let storage = session_storage()?;
        let Some(state) = storage.get_item(STATE_KEY)? else {
            return Ok(None);
        };
        let hash = w.location().hash()?;
        if !(hash.contains("id_token=") || hash.contains("error=")) {
            return Ok(None);
        }
        storage.remove_item(STATE_KEY)?;
        // Remove the token from the address bar / history.
        if let Ok(history) = w.history() {
            let loc = w.location();
            let clean = format!(
                "{}{}",
                loc.pathname().unwrap_or_default(),
                loc.search().unwrap_or_default()
            );
            let _ = history.replace_state_with_url(&JsValue::NULL, "", Some(&clean));
        }
        id_token_from_fragment(&hash, &state).map(Some)
    }

    /// Save a session to `localStorage`.
    pub fn save_session_to_local_storage(key: &str, session: &crate::Session) -> Result<()> {
        local_storage()?.set_item(key, &session.to_json())?;
        Ok(())
    }

    /// Load a session saved with [`save_session_to_local_storage`].
    pub fn load_session_from_local_storage(key: &str) -> Result<Option<crate::Session>> {
        match local_storage()?.get_item(key)? {
            Some(s) => Ok(Some(crate::Session::from_json(&s)?)),
            None => Ok(None),
        }
    }

    pub fn remove_session_from_local_storage(key: &str) -> Result<()> {
        local_storage()?.remove_item(key)?;
        Ok(())
    }

    fn local_storage() -> Result<web_sys::Storage> {
        window()?
            .local_storage()?
            .ok_or_else(|| Error::Browser("localStorage unavailable".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_rfc7636_vector() {
        // Expected value cross-checked with Python's hashlib + base64.urlsafe_b64encode.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mJ92IZ7MIy4kSaxA2m9-K4gjzVp4"),
            "xwTd8ojLgm4zhIIXRECSTo323qHn-LRJzkB9QhBznLM"
        );
    }

    #[test]
    fn random_tokens_differ() {
        let a = random_token(32).unwrap();
        let b = random_token(32).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn fragment_parsing() {
        assert_eq!(
            id_token_from_fragment("#state=abc&id_token=tok.en&authuser=0", "abc").unwrap(),
            "tok.en"
        );
        assert!(id_token_from_fragment("#state=xyz&id_token=t", "abc").is_err());
        assert!(id_token_from_fragment("#error=access_denied&state=abc", "abc").is_err());
    }

    #[test]
    fn web_auth_url() {
        let url = WebOAuthConfig::new("cid", "https://example.com/cb").authorization_url("s", "n");
        assert!(url.contains("response_type=id_token"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcb"));
        assert!(url.contains("scope=openid+email+profile"));
    }
}
