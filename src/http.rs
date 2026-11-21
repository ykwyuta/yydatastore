use serde::de::DeserializeOwned;

use crate::error::{api_error, Result};

pub(crate) fn build_client() -> reqwest::Client {
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Pure-Rust crypto provider (no OpenSSL / aws-lc / cmake needed on Windows).
        // Ignore the error if the application already installed a provider.
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder()
            .user_agent(concat!("yydatastore/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build HTTP client")
    }
    #[cfg(target_arch = "wasm32")]
    {
        reqwest::Client::new()
    }
}

/// Send a request and decode a JSON body, mapping error responses to [`crate::Error::Api`].
pub(crate) async fn send_json<T: DeserializeOwned>(req: reqwest::RequestBuilder) -> Result<T> {
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(api_error(status.as_u16(), &text));
    }
    let body = if text.trim().is_empty() { "{}" } else { &text };
    Ok(serde_json::from_str(body)?)
}
