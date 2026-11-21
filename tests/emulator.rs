//! End-to-end test against the Firebase Local Emulator Suite.
//!
//! ```sh
//! cd emulator && firebase emulators:start --only auth,firestore --project demo-yyds
//! FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 \
//!     cargo test --test emulator -- --nocapture
//! ```
//! Skipped automatically when the environment variables are not set.

use serde::{Deserialize, Serialize};
use serde_json::json;
use yydatastore::firestore::{Direction, Op};
use yydatastore::{Firebase, FirebaseConfig, GeoPoint, Session, Timestamp};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Profile {
    name: String,
    score: i64,
    tags: Vec<String>,
    settings: Settings,
    created: Timestamp,
    home: Option<GeoPoint>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Settings {
    theme: String,
    notify: bool,
}

fn emulator() -> Option<Firebase> {
    let auth = std::env::var("FIREBASE_AUTH_EMULATOR_HOST").ok()?;
    let fs = std::env::var("FIRESTORE_EMULATOR_HOST").ok()?;
    Some(Firebase::new(
        FirebaseConfig::new("demo-yyds", "fake-api-key")
            .auth_emulator(auth)
            .firestore_emulator(fs),
    ))
}

/// The Auth emulator accepts an unsigned JSON object as a Google ID token.
fn fake_google_id_token(sub: &str, email: &str) -> String {
    json!({ "sub": sub, "email": email, "email_verified": true, "name": "Test User" }).to_string()
}

#[tokio::test]
async fn google_sign_in_and_firestore_crud() {
    let Some(fb) = emulator() else {
        eprintln!("emulator env vars not set; skipping");
        return;
    };

    // ---- Auth -----------------------------------------------------------
    let user = fb
        .auth()
        .sign_in_with_google_id_token(&fake_google_id_token("google-sub-1", "alice@example.com"))
        .await
        .expect("sign in");
    assert_eq!(user.email.as_deref(), Some("alice@example.com"));
    assert_eq!(user.provider_id.as_deref(), Some("google.com"));
    let uid = user.uid.clone();

    // Signing in again with the same Google account yields the same UID.
    let again = fb
        .auth()
        .sign_in_with_google_id_token(&fake_google_id_token("google-sub-1", "alice@example.com"))
        .await
        .unwrap();
    assert_eq!(again.uid, uid);

    // Forced refresh works and keeps the user.
    fb.auth().refresh().await.expect("refresh");
    assert_eq!(fb.auth().current_user().unwrap().uid, uid);

    // ---- Firestore: set / get --------------------------------------------
    let db = fb.firestore();
    let doc = db.collection("users").doc(&uid);
    let profile = Profile {
        name: "Alice".into(),
        score: 10,
        tags: vec!["a".into(), "b".into()],
        settings: Settings {
            theme: "dark".into(),
            notify: true,
        },
        created: Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        },
        home: Some(GeoPoint {
            latitude: 35.68,
            longitude: 139.76,
        }),
    };
    doc.set(&profile).await.expect("set");
    let got = doc.get::<Profile>().await.unwrap().expect("exists");
    assert_eq!(got.data, profile);
    assert_eq!(got.id, uid);
    assert_eq!(got.path, format!("users/{uid}"));
    assert!(got.update_time.is_some());

    // ---- update (dotted paths) -------------------------------------------
    doc.update(&json!({ "score": 20, "settings.theme": "light" }))
        .await
        .expect("update");
    let got = doc.get::<Profile>().await.unwrap().unwrap().data;
    assert_eq!(got.score, 20);
    assert_eq!(
        got.settings,
        Settings {
            theme: "light".into(),
            notify: true
        }
    );
    assert_eq!(got.name, "Alice");

    // ---- merge -------------------------------------------------------------
    doc.merge(&json!({ "settings": { "notify": false }, "extra": 1 }))
        .await
        .expect("merge");
    let raw = doc.get::<serde_json::Value>().await.unwrap().unwrap().data;
    assert_eq!(
        raw["settings"],
        json!({ "theme": "light", "notify": false })
    );
    assert_eq!(raw["extra"], 1);
    assert_eq!(raw["created"], "2023-11-14T22:13:20Z");

    // ---- delete_fields -----------------------------------------------------
    doc.delete_fields(&["extra"]).await.unwrap();
    let raw = doc.get::<serde_json::Value>().await.unwrap().unwrap().data;
    assert!(raw.get("extra").is_none());

    // ---- update on a missing doc fails -------------------------------------
    let missing = db
        .collection("users")
        .doc(&uid)
        .collection("notes")
        .doc("nope");
    let e = missing.update(&json!({ "x": 1 })).await.unwrap_err();
    assert!(e.is_not_found(), "{e:?}");
    assert!(missing.get::<serde_json::Value>().await.unwrap().is_none());

    // ---- create fails if it exists -----------------------------------------
    assert!(doc.create(&profile).await.is_err());

    // ---- sub-collection add / list / query --------------------------------
    let notes = doc.collection("notes");
    for i in 0..5 {
        notes
            .add(&json!({ "n": i, "title": format!("note {i}"), "at": Timestamp::now() }))
            .await
            .expect("add");
    }
    let page1 = notes.list::<serde_json::Value>(3, None).await.unwrap();
    assert_eq!(page1.documents.len(), 3);
    let page2 = notes
        .list::<serde_json::Value>(3, page1.next_page_token.as_deref())
        .await
        .unwrap();
    assert_eq!(page2.documents.len(), 2);

    #[derive(Deserialize)]
    struct Note {
        n: i64,
    }
    let top = notes
        .query()
        .filter("n", Op::Ge, 2)
        .unwrap()
        .order_by("n", Direction::Desc)
        .limit(2)
        .get::<Note>()
        .await
        .expect("query");
    assert_eq!(top.iter().map(|d| d.data.n).collect::<Vec<_>>(), vec![4, 3]);

    // ---- security rules: other users' data is denied ----------------------
    let other = db.collection("users").doc("someone-else");
    let e = other.set(&json!({ "x": 1 })).await.unwrap_err();
    assert!(e.is_permission_denied(), "{e:?}");

    // ---- session persistence ------------------------------------------------
    let saved = fb.auth().session().unwrap().to_json();
    let fb2 = emulator().unwrap();
    fb2.auth()
        .restore_session(Session::from_json(&saved).unwrap());
    assert!(fb2
        .firestore()
        .doc(&format!("users/{uid}"))
        .get::<Profile>()
        .await
        .unwrap()
        .is_some());
    // An expired ID token is refreshed transparently.
    let mut expired = Session::from_json(&saved).unwrap();
    expired.expires_at_ms = 0;
    expired.id_token = "garbage".into();
    fb2.auth().restore_session(expired);
    assert!(fb2
        .firestore()
        .doc(&format!("users/{uid}"))
        .get::<Profile>()
        .await
        .unwrap()
        .is_some());

    // ---- signed out: denied -----------------------------------------------
    fb.auth().sign_out();
    assert!(fb.auth().id_token().await.is_err());
    let e = doc.get::<Profile>().await.unwrap_err();
    assert!(e.is_permission_denied(), "{e:?}");

    // ---- delete ----------------------------------------------------------------
    fb.auth()
        .restore_session(Session::from_json(&saved).unwrap());
    doc.delete().await.unwrap();
    assert!(doc.get::<Profile>().await.unwrap().is_none());
}
