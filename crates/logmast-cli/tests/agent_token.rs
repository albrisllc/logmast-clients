use axum::{Json, Router, extract::State, http::HeaderMap, http::StatusCode, routing::get};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    os::unix::ffi::OsStringExt,
    path::Path,
    process::{Command, Output},
};
use uuid::Uuid;

fn cli(origin: &str, state: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_logmastctl"));
    command
        .args(["--url", origin])
        .env("LOGMAST_STATE", state)
        .env_remove("LOGMAST_AGENT_TOKEN")
        .env_remove("LOGMAST_CREDENTIAL")
        .env_remove("LOGMAST_TOKEN");
    command
}

fn assert_secret_absent(output: &Output, token: &str) {
    assert!(!String::from_utf8_lossy(&output.stdout).contains(token));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(token));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copied_token_authenticates_cli_without_state() -> anyhow::Result<()> {
    async fn workspaces(
        State(token): State<String>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<Value>) {
        if headers
            .get("authorization")
            .and_then(|header| header.to_str().ok())
            != Some(format!("Bearer {token}").as_str())
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"code":"AUTH_REQUIRED"})),
            );
        }
        (
            StatusCode::OK,
            Json(json!([{"name":"Authorized workspace"}])),
        )
    }
    let token = "a".repeat(64);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let application = Router::new()
        .route("/api/v1/workspaces", get(workspaces))
        .with_state(token.clone());
    let server = tokio::spawn(async move { axum::serve(listener, application).await });
    let state = std::env::temp_dir()
        .join(format!("logmast-missing-{}", Uuid::now_v7()))
        .join("session.json");
    let output = cli(&origin, &state)
        .env("LOGMAST_AGENT_TOKEN", &token)
        .arg("workspaces")
        .output()?;
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)?,
        json!([{"name":"Authorized workspace"}])
    );
    assert_secret_absent(&output, &token);
    assert!(!state.exists());

    server.abort();
    assert!(server.await.is_err_and(|error| error.is_cancelled()));
    Ok(())
}

#[test]
fn invalid_tokens_and_conflicting_sources_fail_without_secrets() -> anyhow::Result<()> {
    let state = std::env::temp_dir()
        .join(format!("logmast-missing-{}", Uuid::now_v7()))
        .join("session.json");
    // No server: these requests must fail during local credential resolution.
    let origin = "http://127.0.0.1:9";
    for token in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        format!("{}\n", "b".repeat(64)),
    ] {
        let output = cli(origin, &state)
            .env("LOGMAST_AGENT_TOKEN", &token)
            .arg("workspaces")
            .output()?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid LOGMAST_AGENT_TOKEN"));
        if !token.is_empty() {
            assert_secret_absent(&output, &token);
        }
    }
    let output = cli(origin, &state)
        .env("LOGMAST_AGENT_TOKEN", OsString::from_vec(vec![0xff]))
        .arg("workspaces")
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid LOGMAST_AGENT_TOKEN"));

    let token = "c".repeat(64);
    for use_environment in [false, true] {
        let mut command = cli(origin, &state);
        command.env("LOGMAST_AGENT_TOKEN", &token);
        if use_environment {
            command.env("LOGMAST_CREDENTIAL", &state);
        } else {
            command.arg("--credential").arg(&state);
        }
        let output = command.arg("workspaces").output()?;
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("choose LOGMAST_AGENT_TOKEN or --credential/LOGMAST_CREDENTIAL")
        );
        assert_secret_absent(&output, &token);
    }
    let help = cli(origin, &state)
        .env("LOGMAST_AGENT_TOKEN", &token)
        .arg("--help")
        .output()?;
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("LOGMAST_AGENT_TOKEN"));
    assert_secret_absent(&help, &token);
    Ok(())
}
