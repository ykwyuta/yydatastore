//! Native desktop example (Windows / macOS / Linux).
//!
//! ```powershell
//! $env:FIREBASE_PROJECT_ID="my-project"; $env:FIREBASE_API_KEY="AIza..."
//! $env:GOOGLE_CLIENT_ID="xxxx.apps.googleusercontent.com"; $env:GOOGLE_CLIENT_SECRET="GOCSPX-..."
//! cargo run --example desktop
//! ```
//! The first run opens the browser for Google sign-in; the session is then saved
//! to `%APPDATA%\yydatastore-example\session.json` and reused on later runs.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use yydatastore::auth::google::DesktopOAuthConfig;
use yydatastore::{Firebase, FirebaseConfig, Session, Timestamp};

#[derive(Debug, Serialize, Deserialize)]
struct Profile {
    name: Option<String>,
    email: Option<String>,
    launches: i64,
    last_launch: Timestamp,
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("environment variable {name} is not set"))
}

fn session_path() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("yydatastore-example").join("session.json")
}

#[tokio::main]
async fn main() -> yydatastore::Result<()> {
    let fb = Firebase::new(FirebaseConfig::new(
        env("FIREBASE_PROJECT_ID"),
        env("FIREBASE_API_KEY"),
    ));

    // 1. Restore a saved session, or sign in with Google.
    let path = session_path();
    let restored = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| Session::from_json(&s).ok());
    let user = match restored {
        Some(s) => {
            fb.auth().restore_session(s);
            // Validates (and refreshes) the saved credentials.
            match fb.auth().refresh().await {
                Ok(()) => fb.auth().current_user().unwrap(),
                Err(e) => {
                    eprintln!("saved session is no longer valid ({e}); signing in again");
                    sign_in(&fb).await?
                }
            }
        }
        None => sign_in(&fb).await?,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, fb.auth().session().unwrap().to_json())?;
    println!(
        "signed in as {} ({})",
        user.display_name.as_deref().unwrap_or("?"),
        user.uid
    );

    // 2. Read-modify-write the user's document in Firestore.
    let doc = fb.firestore().collection("users").doc(&user.uid);
    let launches = doc
        .get::<Profile>()
        .await?
        .map(|d| d.data.launches)
        .unwrap_or(0)
        + 1;
    doc.set(&Profile {
        name: user.display_name.clone(),
        email: user.email.clone(),
        launches,
        last_launch: Timestamp::now(),
    })
    .await?;
    println!("saved users/{}: launches = {launches}", user.uid);

    // 3. Append to a sub-collection.
    let log = doc
        .collection("launch_log")
        .add(&serde_json::json!({ "at": Timestamp::now(), "os": std::env::consts::OS }))
        .await?;
    println!("added {}", log.path());
    Ok(())
}

async fn sign_in(fb: &Firebase) -> yydatastore::Result<yydatastore::User> {
    let mut oauth = DesktopOAuthConfig::new(env("GOOGLE_CLIENT_ID"))
        .on_auth_url(|url| println!("If the browser does not open, visit:\n{url}\n"));
    if let Ok(secret) = std::env::var("GOOGLE_CLIENT_SECRET") {
        oauth = oauth.client_secret(secret);
    }
    fb.auth().sign_in_with_google(&oauth).await
}
