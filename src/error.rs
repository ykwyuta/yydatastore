use serde::Deserialize;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Network / transport failure.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// The Google / Firebase API returned an error response.
    #[error("api error ({status}): {message}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Machine-readable code, e.g. `INVALID_IDP_RESPONSE`, `NOT_FOUND`, `PERMISSION_DENIED`.
        code: String,
        message: String,
    },

    /// An operation requiring a signed-in user was called while signed out.
    #[error("not signed in")]
    NotSignedIn,

    /// The OAuth (Google sign-in) flow failed or was cancelled.
    #[error("oauth error: {0}")]
    OAuth(String),

    /// Value could not be converted to / from Firestore format.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Error raised by a browser API (wasm only).
    #[error("browser error: {0}")]
    Browser(String),
}

impl Error {
    /// `true` for Firestore "document not found".
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::Api { status: 404, .. })
            || matches!(self, Error::Api { code, .. } if code == "NOT_FOUND")
    }

    /// `true` when security rules rejected the request.
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Error::Api { status: 403, .. })
            || matches!(self, Error::Api { code, .. } if code == "PERMISSION_DENIED")
    }
}

#[derive(Deserialize)]
struct GoogleErrorEnvelope {
    error: GoogleError,
}

#[derive(Deserialize)]
struct GoogleError {
    #[serde(default)]
    message: String,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Build an [`Error::Api`] from a non-success response body.
pub(crate) fn api_error(status: u16, body: &str) -> Error {
    if let Ok(env) = serde_json::from_str::<GoogleErrorEnvelope>(body) {
        // Identity Toolkit puts the code in `message` (e.g. "INVALID_IDP_RESPONSE : ...").
        let code = env.error.status.clone().unwrap_or_else(|| {
            env.error
                .message
                .split([' ', ':'])
                .next()
                .unwrap_or_default()
                .to_string()
        });
        return Error::Api {
            status,
            code,
            message: env.error.message,
        };
    }
    if let Ok(e) = serde_json::from_str::<OAuthError>(body) {
        return Error::Api {
            status,
            message: e.error_description.unwrap_or_else(|| e.error.clone()),
            code: e.error,
        };
    }
    Error::Api {
        status,
        code: String::new(),
        message: body.to_string(),
    }
}

#[cfg(target_arch = "wasm32")]
impl From<wasm_bindgen::JsValue> for Error {
    fn from(v: wasm_bindgen::JsValue) -> Self {
        Error::Browser(format!("{v:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_identity_toolkit_error() {
        let e = api_error(
            400,
            r#"{"error":{"code":400,"message":"INVALID_IDP_RESPONSE : bad token","errors":[]}}"#,
        );
        match e {
            Error::Api { code, .. } => assert_eq!(code, "INVALID_IDP_RESPONSE"),
            _ => panic!(),
        }
    }

    #[test]
    fn parses_firestore_error() {
        let e = api_error(
            404,
            r#"{"error":{"code":404,"message":"Document not found","status":"NOT_FOUND"}}"#,
        );
        assert!(e.is_not_found());
    }

    #[test]
    fn parses_oauth_error() {
        let e = api_error(
            400,
            r#"{"error":"invalid_grant","error_description":"Bad Request"}"#,
        );
        match e {
            Error::Api { code, message, .. } => {
                assert_eq!(code, "invalid_grant");
                assert_eq!(message, "Bad Request");
            }
            _ => panic!(),
        }
    }
}
