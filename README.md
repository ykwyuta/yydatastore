# yydatastore

Pure Rust で書かれた Firebase クライアントです。同じ API で次の 2 つの環境から使えます。

| 環境 | ターゲット | Google サインインの方式 |
|---|---|---|
| **Windows ネイティブアプリ**（macOS / Linux も可） | `x86_64-pc-windows-msvc` など | システムブラウザ + `127.0.0.1` ループバック + PKCE |
| **WebAssembly**（ブラウザ） | `wasm32-unknown-unknown` | ポップアップ、またはページ全体のリダイレクト |

機能:

- **Firebase Authentication**: Google サインイン、ID トークンの自動リフレッシュ、セッションの保存と復元
- **Cloud Firestore**（REST API v1）: `get` / `set` / `create` / `merge` / `update` / `delete` / `delete_fields` / `add` / `list`（ページング） / クエリ（`where`、`orderBy`、`limit`）
- serde で任意の構造体を保存・読み込みできます。`Timestamp`、`GeoPoint`、`Reference`、`Bytes` 型もあります
- Firebase Emulator Suite に対応しています
- JS / TS から使う wasm-bindgen バインディング（feature `js`）

HTTP には `reqwest` を使います。ネイティブでは rustls と ring で TLS を処理するので、OpenSSL、cmake、NASM は要りません。証明書は Windows の証明書ストアで検証し、Windows のシステムプロキシ設定にも従います。wasm ではブラウザの `fetch` を使います。

> ring はビルド時に C コンパイラを使います。Windows では Rust の MSVC ツールチェーンに必要な Visual Studio Build Tools にコンパイラが含まれているので、追加でインストールするものはありません。

---

## 1. Firebase / Google Cloud の準備

1. Firebase コンソールで **Authentication → Sign-in method → Google** を有効にします。
2. **Firestore Database** を作成します。
3. Google Cloud コンソール（Firebase と同じプロジェクト）の **API とサービス → 認証情報** で OAuth クライアント ID を作成します。
   - **Windows アプリ用**: 種類は「**デスクトップ アプリ**」です。ここで発行される client secret は機密情報として扱われないので、アプリに埋め込んでかまいません。
   - **Web（wasm）用**: 種類は「**ウェブ アプリケーション**」です。
     - 承認済みの JavaScript 生成元に `https://your-app.example`（開発中は `http://localhost:8000`）を追加します。
     - 承認済みのリダイレクト URI に `https://your-app.example/oauth-callback.html` を追加します。
4. 別プロジェクトの OAuth クライアントを使う場合は、Firebase の Google プロバイダ設定の「外部プロジェクトからのクライアント ID を許可リストに追加」に、そのクライアント ID を登録します。登録しないと `INVALID_IDP_RESPONSE` になります。
5. Firestore のセキュリティルールの例です（[`emulator/firestore.rules`](emulator/firestore.rules)）。

```
match /users/{uid}/{document=**} {
  allow read, write: if request.auth != null && request.auth.uid == uid;
}
```

## 2. Windows ネイティブアプリから使う

```toml
[dependencies]
yydatastore = { git = "https://github.com/ykwyuta/yydatastore" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
serde = { version = "1", features = ["derive"] }
```

```rust
use serde::{Deserialize, Serialize};
use yydatastore::auth::google::DesktopOAuthConfig;
use yydatastore::{Firebase, FirebaseConfig, Timestamp};

#[derive(Serialize, Deserialize)]
struct Profile { name: String, score: i64, updated: Timestamp }

#[tokio::main]
async fn main() -> yydatastore::Result<()> {
    let fb = Firebase::new(FirebaseConfig::new("my-project-id", "AIza...(Web API キー)"));

    // ブラウザが開き、Google でログインすると戻ってくる
    let oauth = DesktopOAuthConfig::new("xxxx.apps.googleusercontent.com")
        .client_secret("GOCSPX-...");
    let user = fb.auth().sign_in_with_google(&oauth).await?;

    // Firestore に保存
    let doc = fb.firestore().collection("users").doc(&user.uid);
    doc.set(&Profile { name: "Alice".into(), score: 42, updated: Timestamp::now() }).await?;

    // 読み込み（存在しなければ None）
    if let Some(d) = doc.get::<Profile>().await? {
        println!("{} {}", d.data.name, d.data.score);
    }
    Ok(())
}
```

動く例が [`examples/desktop.rs`](examples/desktop.rs) にあります。セッションを `%APPDATA%` に保存するので、2 回目以降はログイン不要です。

```powershell
$env:FIREBASE_PROJECT_ID="my-project"; $env:FIREBASE_API_KEY="AIza..."
$env:GOOGLE_CLIENT_ID="xxxx.apps.googleusercontent.com"; $env:GOOGLE_CLIENT_SECRET="GOCSPX-..."
cargo run --example desktop
```

### ログイン状態を保存する

```rust
// 保存。リフレッシュトークンを含むので、パスワードと同じように扱ってください
std::fs::write(path, fb.auth().session().unwrap().to_json())?;
// 復元。期限が切れた ID トークンは必要になった時点で自動的に更新されます
fb.auth().restore_session(yydatastore::Session::from_json(&std::fs::read_to_string(path)?)?);
```

Windows で保存する場合は、DPAPI（`CryptProtectData`）や資格情報マネージャーで暗号化することを推奨します。

## 3. WebAssembly から使う

### Rust の wasm アプリ（Leptos / Yew / Dioxus など）から

```rust
use yydatastore::auth::google::{web, WebOAuthConfig};

let oauth = WebOAuthConfig::new(
    "xxxx.apps.googleusercontent.com",
    format!("{}/oauth-callback.html", origin),
);
let user = fb.auth().sign_in_with_google_popup(&oauth).await?; // クリックイベントの中で呼ぶ
web::save_session_to_local_storage("session", &fb.auth().session().unwrap())?;

fb.firestore().doc(&format!("users/{}", user.uid)).merge(&data).await?;
```

ポップアップの代わりにリダイレクトも使えます。`fb.auth().sign_in_with_google_redirect(&oauth)` で Google のページへ移動し、戻ってきたページの読み込み時に `fb.auth().complete_google_redirect().await` を呼びます。

### JavaScript / TypeScript から（feature `js`）

```sh
cargo build --release --target wasm32-unknown-unknown --features js
wasm-bindgen --target web --out-dir examples/web/pkg \
    target/wasm32-unknown-unknown/release/yydatastore.wasm
# wasm-pack を使う場合: wasm-pack build --target web -- --features js
```

```js
import init, { FirebaseClient } from "./pkg/yydatastore.js";
await init();
const fb = new FirebaseClient({ projectId: "...", apiKey: "..." });
const user = await fb.signInWithGooglePopup({
  clientId: "xxxx.apps.googleusercontent.com",
  redirectUri: location.origin + "/oauth-callback.html",
});
await fb.setDoc(`users/${user.uid}`, { name: "Alice", score: 42 });
const doc = await fb.getDoc(`users/${user.uid}`); // { id, path, data, updateTime } | null
```

サンプルが [`examples/web/`](examples/web/) にあります。`oauth-callback.html` は中身のない静的ページで、ポップアップのリダイレクト先として使います。

JS API の一覧:

- 認証: `signInWithGooglePopup`、`signInWithGoogleRedirect`、`completeGoogleRedirect`、`signInWithGoogleIdToken`、`currentUser`、`signOut`、`idToken`、`sessionJson`、`restoreSessionJson`、`saveSessionToLocalStorage`、`loadSessionFromLocalStorage`
- Firestore: `getDoc`、`setDoc`、`mergeDoc`、`updateDoc`、`deleteDoc`、`addDoc`、`listDocs`

## 4. Firestore API

```rust
let db = fb.firestore();
let users = db.collection("users");
let me = users.doc(&uid);

me.set(&data).await?;                         // 上書き（なければ作成）
me.create(&data).await?;                      // 既にあればエラー（ALREADY_EXISTS）
me.merge(&json!({"settings": {"theme": "dark"}})).await?;          // 指定したフィールドだけ深くマージ
me.update(&json!({"score": 10, "settings.notify": false})).await?; // ドキュメントがないと NOT_FOUND。キーはドット区切りのパス
me.delete_fields(&["settings.legacy"]).await?;
me.delete().await?;

let note = me.collection("notes").add(&json!({"text": "hi", "at": Timestamp::now()})).await?;
let page = me.collection("notes").list::<serde_json::Value>(50, None).await?; // page.next_page_token で次のページ

use yydatastore::firestore::{Op, Direction};
let top = users.query()
    .filter("score", Op::Ge, 10)?
    .order_by("score", Direction::Desc)
    .limit(20)
    .get::<Profile>().await?;
```

Rust の型と Firestore の型は次のように対応します。

| Rust | Firestore |
|---|---|
| `i64` などの整数 | `integerValue` |
| `f64` | `doubleValue` |
| `String` | `stringValue` |
| `bool` | `booleanValue` |
| `Option::None` | `nullValue` |
| `Vec<T>` | `arrayValue` |
| 構造体 / マップ | `mapValue` |
| `Timestamp` | `timestampValue` |
| `GeoPoint` | `geoPointValue` |
| `Reference` | `referenceValue` |
| `Bytes` | `bytesValue` |

Firestore の `timestampValue` は `String` でも受け取れます（RFC 3339 形式）。

エラーは `Error::Api { status, code, message }` で返ります。`e.is_not_found()` と `e.is_permission_denied()` で判定できます。

## 5. テスト

```sh
cargo test                                   # 単体テスト
# Emulator を使った E2E テスト（Google サインイン、CRUD、クエリ、セキュリティルール、セッション復元）
npm i -g firebase-tools
(cd emulator && firebase emulators:start --only auth,firestore --project demo-yyds) &
FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 \
    cargo test --test emulator
```

アプリから Emulator を使う場合は `FirebaseConfig::new(..).auth_emulator("127.0.0.1:9099").firestore_emulator("127.0.0.1:8080")` を指定します。

## 未対応の機能

- リアルタイムリスナー（`onSnapshot`）。REST API では使えません。必要ならポーリングで代用してください
- トランザクションとバッチ書き込み
- `serverTimestamp` などのフィールド変換
- Google 以外の認証プロバイダ。`sign_in_with_idp` に相当する内部 API を拡張すれば対応できます
