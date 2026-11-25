//! `logmastctl login` as an agent runs it: start, relay the code, wait, then use the login. The
//! stub server sees only hashes, as Logmast does; the token never reaches any output.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
use axum::{
    Json, Router,
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use uuid::Uuid;

#[derive(Clone, Default)]
struct Stub {
    workspace: Uuid,
    origin: Arc<Mutex<String>>,
    starts: Arc<Mutex<Vec<Value>>>,
    failed_starts: Arc<AtomicUsize>,
    decision: Arc<Mutex<Value>>,
    revoked: Arc<Mutex<Vec<String>>>,
}

fn digest(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn bearer_hash(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(digest)
}

impl Stub {
    /// A bearer token is valid once some start asked for it, the decision approved it, and it
    /// has not been revoked.
    fn valid(&self, headers: &HeaderMap) -> bool {
        let Some(hash) = bearer_hash(headers) else {
            return false;
        };
        let started = self
            .starts
            .lock()
            .unwrap()
            .iter()
            .any(|start| start["token_hash"] == json!(hash));
        let approved = self.decision.lock().unwrap()["status"] == json!("approved");
        started && approved && !self.revoked.lock().unwrap().contains(&hash)
    }
}

async fn start(State(stub): State<Stub>, Json(request): Json<Value>) -> (StatusCode, Json<Value>) {
    stub.starts.lock().unwrap().push(request);
    if stub.failed_starts.load(Ordering::SeqCst) > 0 {
        stub.failed_starts.fetch_sub(1, Ordering::SeqCst);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"code":"UNAVAILABLE"})),
        );
    }
    let origin = stub.origin.lock().unwrap().clone();
    (
        StatusCode::OK,
        Json(
            json!({"version":1,"user_code":"BCDFGHJK","verification_uri":format!("{origin}/device"),
            "expires_at":chrono::Utc::now()+chrono::Duration::minutes(10),"interval":1}),
        ),
    )
}

async fn poll(State(stub): State<Stub>, UrlPath(_id): UrlPath<Uuid>) -> Json<Value> {
    let mut decided = stub.decision.lock().unwrap().clone();
    decided["interval"] = json!(1);
    Json(decided)
}

async fn revoke(State(stub): State<Stub>, headers: HeaderMap) -> Json<Value> {
    if let Some(hash) = bearer_hash(&headers) {
        stub.revoked.lock().unwrap().push(hash);
    }
    Json(json!({"version":1,"status":"revoked"}))
}

async fn token(State(stub): State<Stub>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    if !stub.valid(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"code":"UNAUTHORIZED"})),
        );
    }
    (
        StatusCode::OK,
        Json(
            json!({"version":1,"workspace_id":stub.workspace,"workspace_name":"Acme","project_id":null,"project_name":null,
            "scopes":["read","manage"],"expires_at":"2026-12-24T00:00:00Z","agent_name":"logmastctl on test"}),
        ),
    )
}

async fn workspaces(State(stub): State<Stub>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    if !stub.valid(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"code":"UNAUTHORIZED"})),
        );
    }
    (
        StatusCode::OK,
        Json(json!([{"id":stub.workspace,"name":"Acme","role":"member"}])),
    )
}

struct Machine {
    origin: String,
    root: PathBuf,
    repository: PathBuf,
    stub: Stub,
    server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl Machine {
    async fn start() -> Machine {
        let stub = Stub {
            workspace: Uuid::now_v7(),
            decision: Arc::new(Mutex::new(json!({"version":1,"status":"pending"}))),
            ..Stub::default()
        };
        let application = Router::new()
            .route("/api/v1/device/authorizations", post(start))
            .route("/api/v1/device/authorizations/{id}/poll", post(poll))
            .route("/api/v1/auth/token/revoke", post(revoke))
            .route("/api/v1/auth/token", get(token))
            .route("/api/v1/workspaces", get(workspaces))
            .with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        *stub.origin.lock().unwrap() = origin.clone();
        let server = tokio::spawn(async move { axum::serve(listener, application).await });
        let root = std::env::temp_dir().join(format!("logmast-login-{}", Uuid::now_v7()));
        let repository = root.join("src/ledger");
        std::fs::create_dir_all(&repository).unwrap();
        Machine {
            origin,
            root,
            repository,
            stub,
            server,
        }
    }

    fn state(&self) -> PathBuf {
        self.root.join("state/logmast")
    }

    /// `logmastctl` without a terminal and without any configured credential.
    fn run(&self, arguments: &[&str], agent_token: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_logmastctl"));
        command
            .current_dir(&self.repository)
            .args(["--url", &self.origin])
            .args(arguments)
            .env("LOGMAST_STATE", self.state().join("session.json"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env_remove("LOGMAST_AGENT_TOKEN")
            .env_remove("LOGMAST_CREDENTIAL")
            .env_remove("LOGMAST_FORMAT");
        if let Some(token) = agent_token {
            command.env("LOGMAST_AGENT_TOKEN", token);
        }
        let output = command.output().unwrap();
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for secret in self.held_secrets() {
            assert!(
                !printed.contains(&secret[..32]),
                "a secret reached the output of {arguments:?}"
            );
        }
        output
    }

    fn json(&self, arguments: &[&str]) -> Value {
        let output = self.run(arguments, None);
        assert!(
            output.status.success(),
            "{arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn failure(&self, arguments: &[&str]) -> Value {
        let output = self.run(arguments, None);
        assert!(!output.status.success(), "{arguments:?} should have failed");
        serde_json::from_slice(&output.stderr).unwrap()
    }

    fn logins(&self) -> PathBuf {
        self.state()
            .join("logins")
            .join(self.origin.trim_start_matches("http://").replace(':', "_"))
    }

    /// Every token and device code in the CLI's private files, pending or kept.
    fn held_secrets(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(self.logins()) else {
            return Vec::new();
        };
        let mut secrets = Vec::new();
        for entry in entries {
            let text = std::fs::read_to_string(entry.unwrap().path()).unwrap_or_default();
            if let Ok(file) = serde_json::from_str::<Value>(&text) {
                for key in ["token", "device_code"] {
                    if let Some(secret) = file[key].as_str() {
                        secrets.push(secret.to_owned());
                    }
                }
            }
        }
        secrets
    }

    fn login_files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(self.logins())
            .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default();
        files.retain(|path| path.file_name().unwrap() != "pending.json");
        files
    }

    fn approve(&self, workspace: Uuid) {
        *self.stub.decision.lock().unwrap() = json!({"version":1,"status":"approved","workspace_id":workspace,"workspace_name":"Acme",
            "project_id":null,"project_name":null,"scopes":["read","manage"],"expires_at":"2026-12-24T00:00:00Z","agent_id":Uuid::now_v7()});
    }

    fn reset_decision(&self) {
        *self.stub.decision.lock().unwrap() = json!({"version":1,"status":"pending"});
    }

    fn latest_token_hash(&self) -> String {
        self.stub.starts.lock().unwrap().last().unwrap()["token_hash"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().mode() & 0o777
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_logs_in_with_a_relayed_code_and_never_sees_its_token() {
    let machine = Machine::start().await;
    let workspace = machine.stub.workspace.to_string();

    // The request is saved before it is sent: a failed start, retried, repeats the same request.
    machine.stub.failed_starts.store(1, Ordering::SeqCst);
    let refused = machine.failure(&["login", "--workspace", &workspace, "--permission", "manage"]);
    assert_eq!(refused["code"], json!("HTTP_ERROR"));
    assert_eq!(mode(&machine.logins().join("pending.json")), 0o600);
    let started = machine.json(&["login", "--workspace", &workspace, "--permission", "manage"]);
    assert_eq!(
        (started["status"].clone(), started["user_code"].clone()),
        (json!("pending"), json!("BCDF-GHJK"))
    );
    assert_eq!(
        started["verification_uri"],
        json!(format!("{}/device", machine.origin))
    );
    {
        let starts = machine.stub.starts.lock().unwrap();
        assert_eq!(
            (starts[0]["id"].clone(), starts[0]["token_hash"].clone()),
            (starts[1]["id"].clone(), starts[1]["token_hash"].clone())
        );
        assert_eq!(
            (starts[1]["scope"].clone(), starts[1]["workspace"].clone()),
            (json!("manage"), json!(workspace))
        );
    }

    // Nothing is approved yet, so nothing works; then the person approves and the agent waits.
    assert_eq!(
        machine.failure(&["workspaces"])["code"],
        json!("NO_MANAGEMENT_CREDENTIAL")
    );
    machine.approve(machine.stub.workspace);
    let kept = machine.json(&["login", "--wait"]);
    assert_eq!(
        (kept["status"].clone(), kept["secrets_printed"].clone()),
        (json!("approved"), json!(false))
    );
    assert!(!machine.logins().join("pending.json").exists());
    let files = machine.login_files();
    assert_eq!(files.len(), 1);
    assert_eq!((mode(&files[0]), mode(&machine.logins())), (0o600, 0o700));

    // Later commands use the login; whoami says so without printing the token.
    assert_eq!(machine.json(&["workspaces"])[0]["id"], json!(workspace));
    let whoami = machine.json(&["whoami"]);
    assert_eq!(
        (
            whoami["source"]["kind"].clone(),
            whoami["workspace_name"].clone()
        ),
        (json!("login"), json!("Acme"))
    );
    // An explicit agent token still comes first.
    let other = "7777777777777777777777777777777777777777777777777777777777777777";
    let output = machine.run(&["workspaces"], Some(other));
    assert!(
        !output.status.success(),
        "the environment's token must take precedence"
    );

    // A second login for the same reach replaces the first after approval, revoking it.
    let first_hash = machine.latest_token_hash();
    machine.reset_decision();
    machine.json(&["login", "--workspace", &workspace]);
    let second_hash = machine.latest_token_hash();
    machine.approve(machine.stub.workspace);
    let replaced = machine.json(&["login", "--wait"]);
    assert_eq!(replaced["replaced"], json!(true));
    assert!(machine.stub.revoked.lock().unwrap().contains(&first_hash));
    assert!(!machine.stub.revoked.lock().unwrap().contains(&second_hash));
    assert_eq!(machine.login_files().len(), 1);

    // A grant for another workspace than asked for is revoked, never kept.
    machine.reset_decision();
    machine.json(&["login", "--workspace", &workspace]);
    let mismatched_hash = machine.latest_token_hash();
    machine.approve(Uuid::now_v7());
    assert_eq!(
        machine.failure(&["login", "--wait"])["code"],
        json!("LOGIN_MISMATCH")
    );
    assert!(
        machine
            .stub
            .revoked
            .lock()
            .unwrap()
            .contains(&mismatched_hash)
    );
    assert_eq!(machine.login_files().len(), 1);

    // Without a terminal, a login must name its workspace: otherwise whoever approves the
    // code would choose where this machine's access goes.
    assert_eq!(
        machine.failure(&["login"])["code"],
        json!("LOGIN_WORKSPACE_REQUIRED")
    );

    // One login waits at a time: a different request is refused until the first is finished
    // or cancelled, so a person and an agent never finish each other's logins.
    machine.reset_decision();
    machine.json(&["login", "--workspace", &workspace]);
    let waiting_hash = machine.latest_token_hash();
    assert_eq!(
        machine.failure(&["login", "--workspace", &workspace, "--days", "1"])["code"],
        json!("LOGIN_PENDING")
    );
    assert_eq!(
        machine.json(&["login", "--cancel"])["status"],
        json!("cancelled")
    );
    assert!(machine.stub.revoked.lock().unwrap().contains(&waiting_hash));
    machine.json(&["login", "--workspace", &workspace, "--days", "1"]);
    assert_eq!(
        machine.stub.starts.lock().unwrap().last().unwrap()["days"],
        json!(1)
    );
    *machine.stub.decision.lock().unwrap() = json!({"version":1,"status":"denied"});
    assert_eq!(
        machine.failure(&["login", "--wait"])["code"],
        json!("LOGIN_DENIED")
    );
    assert_eq!(
        machine.failure(&["login", "--wait"])["code"],
        json!("NO_PENDING_LOGIN")
    );

    // Repeating a login someone already approved says so instead of showing a dead code.
    machine.reset_decision();
    machine.json(&["login", "--workspace", &workspace]);
    let resumed_hash = machine.latest_token_hash();
    machine.approve(machine.stub.workspace);
    assert_eq!(
        machine.json(&["login", "--workspace", &workspace])["status"],
        json!("approved")
    );
    machine.json(&["login", "--wait"]);
    assert!(machine.stub.revoked.lock().unwrap().contains(&second_hash));

    // Logging out revokes the kept login and removes it.
    assert_eq!(machine.json(&["logout"])["status"], json!("logged_out"));
    assert!(machine.stub.revoked.lock().unwrap().contains(&resumed_hash));
    assert!(machine.login_files().is_empty());
    assert_eq!(
        machine.failure(&["workspaces"])["code"],
        json!("NO_MANAGEMENT_CREDENTIAL")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_scoped_login_applies_only_inside_its_tree() {
    let machine = Machine::start().await;
    let workspace = machine.stub.workspace.to_string();
    let scope = machine.repository.to_string_lossy().into_owned();
    machine.json(&["login", "--workspace", &workspace, "--scope", &scope]);
    let reported = machine.stub.starts.lock().unwrap()[0]["client"]["directory"].clone();
    assert_eq!(reported, json!(machine.repository.canonicalize().unwrap()));
    machine.approve(machine.stub.workspace);
    machine.json(&["login", "--wait"]);
    assert_eq!(machine.json(&["whoami"])["source"]["kind"], json!("login"));
    // From a sibling directory the login does not apply.
    let sibling = machine.root.join("src/other");
    std::fs::create_dir_all(&sibling).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_logmastctl"))
        .current_dir(&sibling)
        .args(["--url", &machine.origin, "workspaces"])
        .env("LOGMAST_STATE", machine.state().join("session.json"))
        .env("XDG_CONFIG_HOME", machine.root.join("config"))
        .env_remove("LOGMAST_AGENT_TOKEN")
        .env_remove("LOGMAST_CREDENTIAL")
        .env_remove("LOGMAST_FORMAT")
        .output()
        .unwrap();
    let failure: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(failure["code"], json!("NO_MANAGEMENT_CREDENTIAL"));
}
