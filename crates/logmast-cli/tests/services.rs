//! A person and an agent sharing one machine: bind a directory, create a service, keep its
//! credential private, export it, verify delivery, and get a next step when refused. The
//! server is a stub; the CLI is the real binary, run without a terminal as an agent runs it.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
use axum::{
    Json, Router,
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use uuid::Uuid;

const MANAGEMENT_TOKEN: &str = "5555555555555555555555555555555555555555555555555555555555555555";

#[derive(Clone)]
struct Stub {
    workspace: Uuid,
    project: Uuid,
    service: Uuid,
    // Every ingest secret ever issued, newest last; only the newest is accepted.
    ingest_secrets: Arc<Mutex<Vec<String>>>,
    batches: Arc<Mutex<Vec<Value>>>,
    creates: Arc<AtomicUsize>,
    enrollments: Arc<AtomicUsize>,
    // Acknowledgments to lose before answering properly, as an uncertain transport would.
    lost_acknowledgments: Arc<AtomicUsize>,
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some(format!("Bearer {token}").as_str())
}

fn refused(status: StatusCode) -> (StatusCode, Json<Value>) {
    (status, Json(json!({"code":"REFUSED"})))
}

impl Stub {
    /// Management requests must carry the agent token and name this stub's workspace.
    fn admit(&self, headers: &HeaderMap, workspace: Uuid) -> Result<(), (StatusCode, Json<Value>)> {
        if !authorized(headers, MANAGEMENT_TOKEN) {
            return Err(refused(StatusCode::UNAUTHORIZED));
        }
        if workspace != self.workspace {
            return Err(refused(StatusCode::NOT_FOUND));
        }
        Ok(())
    }
    fn issue(&self) -> String {
        let secret = Uuid::now_v7().simple().to_string().repeat(2);
        self.ingest_secrets.lock().unwrap().push(secret.clone());
        secret
    }
    fn current_secret(&self) -> Option<String> {
        self.ingest_secrets.lock().unwrap().last().cloned()
    }
}

async fn workspaces(State(stub): State<Stub>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    if !authorized(&headers, MANAGEMENT_TOKEN) {
        return refused(StatusCode::UNAUTHORIZED);
    }
    (
        StatusCode::OK,
        Json(json!([{"id":stub.workspace,"name":"Acme","role":"member"}])),
    )
}

async fn enrollment(
    State(stub): State<Stub>,
    headers: HeaderMap,
    UrlPath(workspace): UrlPath<Uuid>,
) -> (StatusCode, Json<Value>) {
    if let Err(refusal) = stub.admit(&headers, workspace) {
        return refusal;
    }
    (
        StatusCode::OK,
        Json(
            json!({"version":1,"projects":[{"id":stub.project,"name":"Production"}],"services":[{"id":stub.service,"name":"api","project_id":stub.project,"last_received":null}]}),
        ),
    )
}

async fn enroll(State(stub): State<Stub>, Json(request): Json<Value>) -> Json<Value> {
    // A replayed enrollment changes nothing, as on the server: only the first registers its secret.
    if stub.enrollments.fetch_add(1, Ordering::SeqCst) == 0 {
        stub.ingest_secrets
            .lock()
            .unwrap()
            .push(request["ingest_secret"].as_str().unwrap().to_owned());
    }
    Json(
        json!({"workspace_id":stub.workspace,"service_id":stub.service,"project_id":stub.project,"status":"provisional"}),
    )
}

async fn control(
    State(stub): State<Stub>,
    headers: HeaderMap,
    UrlPath(workspace): UrlPath<Uuid>,
    Json(command): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(refusal) = stub.admit(&headers, workspace) {
        return refusal;
    }
    match command["action"].as_str() {
        Some("create_service") => {
            stub.creates.fetch_add(1, Ordering::SeqCst);
            let secret = stub.issue();
            (
                StatusCode::OK,
                Json(
                    json!({"id":stub.service,"service_id":stub.service,"ingest_token":secret,"sentry_dsn":"ignored"}),
                ),
            )
        }
        Some("rotate_credential") if command["service_id"] == json!(stub.service) => {
            let secret = stub.issue();
            (
                StatusCode::OK,
                Json(json!({"id":Uuid::now_v7(),"service_id":stub.service,"ingest_token":secret})),
            )
        }
        Some("rotate_credential") => refused(StatusCode::NOT_FOUND),
        _ => refused(StatusCode::FORBIDDEN),
    }
}

async fn ingest(
    State(stub): State<Stub>,
    headers: HeaderMap,
    Json(batch): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(current) = stub.current_secret() else {
        return refused(StatusCode::UNAUTHORIZED);
    };
    if !authorized(&headers, &current) {
        return refused(StatusCode::UNAUTHORIZED);
    }
    stub.batches.lock().unwrap().push(batch);
    if stub.lost_acknowledgments.load(Ordering::SeqCst) > 0 {
        stub.lost_acknowledgments.fetch_sub(1, Ordering::SeqCst);
        return (StatusCode::OK, Json(json!({})));
    }
    (
        StatusCode::OK,
        Json(json!({"receipt_id":Uuid::now_v7(),"new_events":1,"duplicates":0})),
    )
}

async fn occurrence(
    State(stub): State<Stub>,
    headers: HeaderMap,
    UrlPath((workspace, service, occurrence)): UrlPath<(Uuid, Uuid, Uuid)>,
) -> (StatusCode, Json<Value>) {
    if let Err(refusal) = stub.admit(&headers, workspace) {
        return refusal;
    }
    if service != stub.service {
        return refused(StatusCode::NOT_FOUND);
    }
    let batches = stub.batches.lock().unwrap();
    let event = batches
        .iter()
        .flat_map(|batch| batch["events"].as_array().cloned().unwrap_or_default())
        .find(|event| event["occurrence_id"] == json!(occurrence));
    let body = match event {
        Some(event) => {
            json!({"event":{"occurrence_id":occurrence,"service_id":stub.service,"workspace_id":stub.workspace,"group_id":Uuid::now_v7(),"payload":{"code":event["code"],"correlation_ids":event["correlation_ids"]}}})
        }
        None => json!({"event":null}),
    };
    (StatusCode::OK, Json(body))
}

async fn receipt() -> Json<Value> {
    Json(json!({"processed_at":"2026-11-24T00:00:00Z","processing_gap":false,"notifications":[]}))
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
            project: Uuid::now_v7(),
            service: Uuid::now_v7(),
            ingest_secrets: Arc::default(),
            batches: Arc::default(),
            creates: Arc::default(),
            enrollments: Arc::default(),
            lost_acknowledgments: Arc::default(),
        };
        let application = Router::new()
            .route("/api/v1/workspaces", get(workspaces))
            .route("/api/v1/enrollments", post(enroll))
            .route("/api/v1/workspaces/{workspace}/enrollment", get(enrollment))
            .route("/api/v1/workspaces/{workspace}/control", post(control))
            .route("/api/v1/ingest/batches", post(ingest))
            .route(
                "/api/v1/workspaces/{workspace}/services/{service}/occurrences/{occurrence}",
                get(occurrence),
            )
            .route(
                "/api/v1/workspaces/{workspace}/receipts/{receipt}",
                get(receipt),
            )
            .with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, application).await });
        let root = std::env::temp_dir().join(format!("logmast-machine-{}", Uuid::now_v7()));
        let repository = root.join("src/ledger");
        std::fs::create_dir_all(&repository).unwrap();
        // A checkout with a user-private group is group-writable; that is fine.
        std::fs::set_permissions(&repository, std::fs::Permissions::from_mode(0o775)).unwrap();
        Machine {
            origin,
            root,
            repository,
            stub,
            server,
        }
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_logmastctl"));
        command
            .current_dir(&self.repository)
            .args(["--url", &self.origin])
            .args(arguments)
            .env(
                "LOGMAST_STATE",
                self.root.join("state/logmast/session.json"),
            )
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env_remove("LOGMAST_CREDENTIAL")
            .env_remove("LOGMAST_FORMAT");
        command
    }

    /// `logmastctl` as an agent runs it: in the repository, without a terminal, with an agent token.
    fn run(&self, arguments: &[&str]) -> Output {
        let output = self
            .command(arguments)
            .env("LOGMAST_AGENT_TOKEN", MANAGEMENT_TOKEN)
            .output()
            .unwrap();
        self.assert_no_secret(&output);
        output
    }

    fn json(&self, arguments: &[&str]) -> Value {
        let output = self.run(arguments);
        assert!(
            output.status.success(),
            "{arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn failure(&self, arguments: &[&str]) -> Value {
        let output = self.run(arguments);
        assert!(!output.status.success(), "{arguments:?} should have failed");
        serde_json::from_slice(&output.stderr).unwrap()
    }

    /// No secret, current or earlier, nor the DSN key or the agent token, ever reaches the output.
    fn assert_no_secret(&self, output: &Output) {
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let secrets = self.stub.ingest_secrets.lock().unwrap().clone();
        for secret in secrets
            .iter()
            .chain(std::iter::once(&MANAGEMENT_TOKEN.to_owned()))
        {
            assert!(
                !printed.contains(secret.as_str()),
                "a secret reached the output"
            );
            assert!(
                !printed.contains(&secret[..32]),
                "part of a secret reached the output"
            );
        }
        let dsn_files = [self.repository.join("sentry.env")];
        for file in dsn_files.iter().filter(|file| file.exists()) {
            let dsn = std::fs::read_to_string(file).unwrap();
            let key = dsn
                .trim()
                .trim_start_matches("SENTRY_DSN=http://")
                .split('@')
                .next()
                .unwrap()
                .to_owned();
            assert!(!printed.contains(&key), "the DSN key reached the output");
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o777
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_binds_the_repository_creates_a_service_and_verifies_it_without_seeing_a_secret() {
    let machine = Machine::start().await;
    let (workspace, project, service) = (
        machine.stub.workspace,
        machine.stub.project,
        machine.stub.service,
    );
    let service_text = service.to_string();

    // Without a binding the credential's own workspace is used: reads need no ID, and a
    // service, which belongs to a project, is refused with how to choose one.
    assert_eq!(
        machine.json(&["projects"])["projects"][0]["id"],
        json!(project),
        "the credential's only workspace"
    );
    let failure = machine.failure(&["services", "create", "--name", "api"]);
    assert_eq!(failure["code"], json!("PROJECT_REQUIRED"));
    assert!(
        failure["next"]
            .as_str()
            .unwrap()
            .contains("logmastctl setup --project"),
        "{failure}"
    );

    let bound = machine.json(&["setup", "--project", &project.to_string()]);
    assert_eq!(
        (bound["workspace"].clone(), bound["project"].clone()),
        (json!(workspace), json!(project)),
        "the only reachable workspace is chosen"
    );
    assert_eq!(
        machine.json(&["projects"])["projects"][0]["id"],
        json!(project)
    );
    assert_eq!(
        machine.json(&["status"])["projects"][0]["id"],
        json!(project),
        "status falls back to the binding"
    );

    // An output that cannot be written is refused before anything changes on the server.
    std::fs::write(machine.repository.join("taken.env"), "").unwrap();
    let failure = machine.failure(&[
        "services",
        "create",
        "--name",
        "api",
        "--env-file",
        "taken.env",
    ]);
    assert_eq!(failure["code"], json!("OUTPUT_EXISTS"));
    assert_eq!(
        machine.stub.creates.load(Ordering::SeqCst),
        0,
        "no service was created"
    );

    let created = machine.json(&[
        "services",
        "create",
        "--name",
        "api",
        "--env-file",
        ".env.logmast",
    ]);
    assert_eq!(
        (
            created["service_id"].clone(),
            created["outputs_written"].clone(),
            created["secrets_printed"].clone()
        ),
        (json!(service), json!(true), json!(false))
    );
    let services_directory = machine.root.join("state/logmast/services");
    assert_eq!(Machine::mode(&services_directory), 0o700);
    assert_eq!(
        Machine::mode(&services_directory.join(format!("{service}.json"))),
        0o600
    );
    let environment = machine.repository.join(".env.logmast");
    assert_eq!(Machine::mode(&environment), 0o600);
    let secret = machine.stub.current_secret().unwrap();
    assert!(
        std::fs::read_to_string(&environment)
            .unwrap()
            .contains(&format!("LOGMAST_TOKEN={secret}"))
    );

    let failure = machine.failure(&[
        "credentials",
        "export",
        "--service",
        &service_text,
        "--env-file",
        ".env.logmast",
    ]);
    assert!(
        failure["error"]
            .as_str()
            .unwrap()
            .contains("never overwritten"),
        "{failure}"
    );
    let exported = machine.json(&[
        "credentials",
        "export",
        "--service",
        &service_text,
        "--dsn-file",
        "sentry.env",
    ]);
    assert_eq!(exported["secrets_printed"], json!(false));
    assert_eq!(Machine::mode(&machine.repository.join("sentry.env")), 0o600);
    assert!(
        std::fs::read_to_string(machine.repository.join("sentry.env"))
            .unwrap()
            .starts_with("SENTRY_DSN=http://")
    );

    // --reveal is for a person at a terminal; an agent's captured output is refused.
    assert_eq!(
        machine.failure(&[
            "credentials",
            "export",
            "--service",
            &service_text,
            "--reveal"
        ])["code"],
        json!("REVEAL_NEEDS_TERMINAL")
    );

    // A lost acknowledgment leaves the run uncertain; the next verify resumes the same run.
    machine.stub.lost_acknowledgments.store(1, Ordering::SeqCst);
    assert_eq!(
        machine.failure(&["verify", "--service", &service_text])["code"],
        json!("VERIFICATION_MISMATCH")
    );
    let verified = machine.json(&["verify", "--service", &service_text]);
    assert_eq!(
        (verified["verified"].clone(), verified["historical"].clone()),
        (json!(true), json!(false))
    );
    {
        let batches = machine.stub.batches.lock().unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(
            batches[0]["batch_id"], batches[1]["batch_id"],
            "the uncertain run was resumed, not replaced"
        );
    }
    let run_id = verified["run_id"].as_str().unwrap().to_owned();
    assert_eq!(
        machine.json(&["verify", "--service", &service_text, "--run-id", &run_id])["historical"],
        json!(true)
    );
    let fresh = machine.json(&["verify", "--service", &service_text]);
    assert_ne!(
        fresh["run_id"].as_str(),
        Some(run_id.as_str()),
        "after completion the next run is fresh"
    );
    assert_eq!(
        machine.stub.batches.lock().unwrap().len(),
        3,
        "the replay sent nothing"
    );

    // Rotation replaces the saved credential, so verification keeps working with the new one.
    machine.json(&["credentials", "rotate", "--service", &service_text]);
    assert_eq!(
        machine.json(&["verify", "--service", &service_text])["verified"],
        json!(true)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_enrolled_service_is_exported_and_verified_from_local_state_after_a_rotation() {
    let machine = Machine::start().await;
    let service = machine.stub.service.to_string();
    let enrolled = machine
        .command(&[
            "enroll",
            "--workspace",
            "Acme",
            "--project",
            "Production",
            "--service",
            "api",
        ])
        .output()
        .unwrap();
    assert!(
        enrolled.status.success(),
        "{}",
        String::from_utf8_lossy(&enrolled.stderr)
    );
    machine.assert_no_secret(&enrolled);
    let exported = machine
        .command(&[
            "credentials",
            "export",
            "--service",
            &service,
            "--env-file",
            "enrolled.env",
        ])
        .output()
        .unwrap();
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert_eq!(
        machine.stub.enrollments.load(Ordering::SeqCst),
        1,
        "export sends nothing"
    );

    // After a rotation the enrollment's own verify uses the new, saved credential.
    machine.json(&[
        "credentials",
        "rotate",
        "--service",
        &service,
        "--workspace",
        &machine.stub.workspace.to_string(),
    ]);
    // The agent's own token reads the evidence back; the enrollment's state supplies the service.
    assert_eq!(machine.json(&["verify"])["verified"], json!(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusals_link_the_console_page_that_grants_what_was_missing() {
    let machine = Machine::start().await;
    let workspace = machine.stub.workspace.to_string();
    std::fs::write(
        machine.root.join("invite.json"),
        r#"{"action":"invite","email":"a@example.test","role":"viewer"}"#,
    )
    .unwrap();
    let invite = machine.root.join("invite.json");
    let output_file = machine.root.join("state/logmast/invite-result.json");
    let failure = machine.failure(&[
        "control",
        &workspace,
        "--command-file",
        invite.to_str().unwrap(),
        "--output",
        output_file.to_str().unwrap(),
    ]);
    assert_eq!(failure["code"], json!("PERMISSION_DENIED"));
    assert!(
        failure["next"].as_str().unwrap().contains(&format!(
            "{}/access?workspace={workspace}&tab=agents",
            machine.origin
        )),
        "{failure}"
    );

    // A binding's project belongs to its own workspace, never to one named explicitly.
    machine.json(&["setup", "--project", &machine.stub.project.to_string()]);
    let other = Uuid::now_v7().to_string();
    assert_eq!(
        machine.failure(&["services", "create", "--name", "api", "--workspace", &other])["code"],
        json!("PROJECT_REQUIRED")
    );

    // A delegated agent with no enrollment state is pointed at service verification.
    assert!(
        machine.failure(&["verify"])["next"]
            .as_str()
            .unwrap()
            .contains("verify --service")
    );
    // A credential this machine never held is explained, and export never asks the server.
    let failure = machine.failure(&[
        "credentials",
        "export",
        "--service",
        &Uuid::now_v7().to_string(),
        "--env-file",
        "x.env",
    ]);
    assert_eq!(failure["code"], json!("NO_SAVED_CREDENTIAL"));
    // No credential at all names where to get one.
    let none = machine.command(&["workspaces"]).output().unwrap();
    let failure: Value = serde_json::from_slice(&none.stderr).unwrap();
    assert_eq!(failure["code"], json!("NO_MANAGEMENT_CREDENTIAL"));
    assert!(
        failure["next"]
            .as_str()
            .unwrap()
            .contains("logmastctl login")
            && failure["next"].as_str().unwrap().contains("/access"),
        "{failure}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_person_reads_short_text_and_an_agent_reads_json() {
    let machine = Machine::start().await;
    let human = machine.run(&[
        "--format",
        "human",
        "projects",
        &machine.stub.workspace.to_string(),
    ]);
    assert!(human.status.success());
    assert_eq!(
        String::from_utf8_lossy(&human.stdout).trim(),
        format!(
            "Production ({})\n  api ({})",
            machine.stub.project, machine.stub.service
        )
    );
    let failure = machine.run(&["--format", "human", "services", "create", "--name", "api"]);
    let text = String::from_utf8_lossy(&failure.stderr);
    assert!(
        text.starts_with("error: no project chosen\nnext: "),
        "{text}"
    );
}
