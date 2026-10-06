//! Management only: no file tailing, host collection, background installation,
//! or payload capture. Verification is an explicit, synthetic API submission.
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    version,
    about = "Manage Logmast accounts and services. Does not capture logs."
)]
struct Arguments {
    #[arg(long, default_value = "https://app.logmast.com", env = "LOGMAST_URL")]
    url: String,
    /// Private state file. Enrollment secrets are saved before network requests.
    #[arg(long,env="LOGMAST_STATE",default_value_os_t=default_state())]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Catalog,
    Enroll {
        #[arg(long)]
        workspace: String,
        #[arg(long)]
        project: String,
        #[arg(long)]
        service: String,
    },
    Workspaces,
    Status {
        workspace: Uuid,
    },
    Claim {
        workspace: Uuid,
        #[arg(long)]
        email: String,
    },
    Verify,
    /// Start a stdio MCP server using this private enrollment state.
    Mcp,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("private state unavailable or unsafe")]
    State(#[source] std::io::Error),
    #[error("invalid state; preserve it and inspect its structure without printing credentials")]
    InvalidState,
    #[error("HTTPS is required, except on loopback; URL must be an origin without credentials")]
    Origin,
    #[error("transport unavailable; retry with the same state file")]
    Transport(#[source] ureq::Error),
    #[error("Logmast returned HTTP {0}; credentials and response body suppressed")]
    Http(u16),
    #[error("enrollment arguments differ from saved state")]
    Conflict,
    #[error("invalid MCP request")]
    Mcp,
    #[error("readback did not match the submitted verification event")]
    Verification,
}

// Intentionally no Debug or Serialize. Serialization is confined to explicit
// mode-0600 persistence and the authenticated enrollment request below.
#[derive(Deserialize)]
struct Saved {
    version: u32,
    origin: String,
    id: Uuid,
    workspace: String,
    project: String,
    service: String,
    bootstrap_secret: String,
    ingest_secret: String,
    verification_batch: Uuid,
    verification_occurrence: Uuid,
    verification_time: String,
}

struct Client {
    origin: String,
    agent: ureq::Agent,
}

fn default_state() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from(".logmast-state"))
        .join("logmast/session.json")
}
impl Client {
    fn new(origin: &str) -> Result<Self, Error> {
        let url = url::Url::parse(origin).map_err(|_| Error::Origin)?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(Error::Origin);
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();
        Ok(Self {
            origin: url.origin().ascii_serialization(),
            agent,
        })
    }
    fn call(&self, path: &str, token: Option<&str>, body: Option<Value>) -> Result<Value, Error> {
        let authorization = token
            .map(|value| format!("Bearer {value}"))
            .unwrap_or_default();
        let url = format!("{}{path}", self.origin);
        let mut response = match body {
            Some(body) => self
                .agent
                .post(url)
                .header("Authorization", &authorization)
                .send_json(body),
            None => self
                .agent
                .get(url)
                .header("Authorization", &authorization)
                .call(),
        }
        .map_err(Error::Transport)?;
        if !response.status().is_success() {
            return Err(Error::Http(response.status().as_u16()));
        }
        response
            .body_mut()
            .with_config()
            .limit(2 * 1024 * 1024)
            .read_json()
            .map_err(Error::Transport)
    }
    fn enroll(&self, saved: &Saved) -> Result<Value, Error> {
        self.call("/api/v1/enrollments",None,Some(json!({"id":saved.id,"workspace":saved.workspace,"project":saved.project,"service":saved.service,"bootstrap_secret":saved.bootstrap_secret,"ingest_secret":saved.ingest_secret})))
    }
    fn verify(&self, saved: &Saved) -> Result<Value, Error> {
        let enrollment = self.enroll(saved)?;
        let workspace: Uuid = serde_json::from_value(
            enrollment
                .get("workspace_id")
                .cloned()
                .ok_or(Error::InvalidState)?,
        )
        .map_err(|_| Error::InvalidState)?;
        let service: Uuid = serde_json::from_value(
            enrollment
                .get("service_id")
                .cloned()
                .ok_or(Error::InvalidState)?,
        )
        .map_err(|_| Error::InvalidState)?;
        let receipt=self.call("/api/v1/ingest/batches",Some(&saved.ingest_secret),Some(json!({"batch_id":saved.verification_batch,"service_id":service,"events":[{
            "occurrence_id":saved.verification_occurrence,"timestamp":saved.verification_time,"environment":"verification","severity":"error","outcome":"failed",
            "message":"Logmast synthetic enrollment verification","code":"LOGMAST.ONBOARDING.VERIFY","correlation_ids":[saved.id.to_string()]
        }]})))?;
        let occurrence = self.call(
            &format!(
                "/api/v1/workspaces/{workspace}/services/{service}/occurrences/{}",
                saved.verification_occurrence
            ),
            Some(&saved.bootstrap_secret),
            None,
        )?;
        let verified = occurrence.get("event").is_some_and(|event| {
            event.get("occurrence_id").and_then(Value::as_str)
                == Some(saved.verification_occurrence.to_string().as_str())
                && event.get("service_id").and_then(Value::as_str)
                    == Some(service.to_string().as_str())
                && event.get("workspace_id").and_then(Value::as_str)
                    == Some(workspace.to_string().as_str())
                && event.pointer("/payload/code").and_then(Value::as_str)
                    == Some("LOGMAST.ONBOARDING.VERIFY")
        });
        if !verified {
            return Err(Error::Verification);
        }
        Ok(
            json!({"version":1,"verified":verified,"receipt":receipt,"workspace_id":workspace,"service_id":service,"occurrence_id":saved.verification_occurrence,
            "investigation_url":format!("{}/?workspace={workspace}&service={service}&view=all",self.origin)}),
        )
    }
}

fn secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn open_state(path: &PathBuf, create: bool) -> Result<File, Error> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or(Error::InvalidState)?;
    if create {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(Error::State)?;
    }
    let metadata = fs::symlink_metadata(parent).map_err(Error::State)?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(Error::InvalidState);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(Error::State)?;
    let metadata = file.metadata().map_err(Error::State)?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.len() > 16384 {
        return Err(Error::InvalidState);
    }
    Ok(file)
}

fn load(path: &PathBuf, origin: &str) -> Result<Saved, Error> {
    let mut file = open_state(path, false)?;
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(Error::State)?;
    let saved: Saved = serde_json::from_str(&text).map_err(|_| Error::InvalidState)?;
    if saved.version != 1 || saved.origin != origin {
        return Err(Error::InvalidState);
    }
    Ok(saved)
}

fn prepare(
    path: &PathBuf,
    origin: &str,
    workspace: String,
    project: String,
    service: String,
) -> Result<Saved, Error> {
    if path.try_exists().map_err(Error::State)? {
        let saved = load(path, origin)?;
        if saved.workspace != workspace || saved.project != project || saved.service != service {
            return Err(Error::Conflict);
        }
        return Ok(saved);
    }
    let saved = Saved {
        version: 1,
        origin: origin.into(),
        id: Uuid::now_v7(),
        workspace,
        project,
        service,
        bootstrap_secret: secret(),
        ingest_secret: secret(),
        verification_batch: Uuid::now_v7(),
        verification_occurrence: Uuid::now_v7(),
        verification_time: chrono::Utc::now().to_rfc3339(),
    };
    let persisted = json!({"version":saved.version,"origin":saved.origin,"id":saved.id,"workspace":saved.workspace,"project":saved.project,"service":saved.service,"bootstrap_secret":saved.bootstrap_secret,"ingest_secret":saved.ingest_secret,"verification_batch":saved.verification_batch,"verification_occurrence":saved.verification_occurrence,"verification_time":saved.verification_time});
    let mut file = open_state(path, true)?;
    file.write_all(persisted.to_string().as_bytes())
        .map_err(Error::State)?;
    file.sync_all().map_err(Error::State)?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(Error::State)?;
    }
    Ok(saved)
}

fn execute(arguments: Arguments) -> Result<Value, Error> {
    let client = Client::new(&arguments.url)?;
    match arguments.command {
        Command::Catalog => client.call("/api/v1/catalog", None, None),
        Command::Enroll {
            workspace,
            project,
            service,
        } => client.enroll(&prepare(
            &arguments.state,
            &client.origin,
            workspace,
            project,
            service,
        )?),
        command => {
            let saved = load(&arguments.state, &client.origin)?;
            match command {
                Command::Workspaces => {
                    client.call("/api/v1/workspaces", Some(&saved.bootstrap_secret), None)
                }
                Command::Status { workspace } => client.call(
                    &format!("/api/v1/workspaces/{workspace}/enrollment"),
                    Some(&saved.bootstrap_secret),
                    None,
                ),
                Command::Claim { workspace, email } => client.call(
                    &format!("/api/v1/workspaces/{workspace}/claim"),
                    Some(&saved.bootstrap_secret),
                    Some(json!({"email":email})),
                ),
                Command::Verify => client.verify(&saved),
                Command::Mcp => {
                    mcp(&client, &saved)?;
                    Ok(Value::Null)
                }
                Command::Catalog | Command::Enroll { .. } => Err(Error::InvalidState),
            }
        }
    }
}

fn mcp(client: &Client, saved: &Saved) -> Result<(), Error> {
    use std::io::BufRead;
    let mut input = std::io::stdin().lock();
    loop {
        let mut line = String::new();
        let bytes = input
            .by_ref()
            .take(65537)
            .read_line(&mut line)
            .map_err(Error::State)?;
        if bytes == 0 {
            return Ok(());
        }
        if bytes > 65536 {
            return Err(Error::Mcp);
        }
        let request: Value = serde_json::from_str(&line).map_err(|_| Error::Mcp)?;
        let Some(id) = request.get("id") else {
            continue;
        };
        let result = match request.get("method").and_then(Value::as_str) {
            Some("initialize") => Ok(
                json!({"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"logmastctl","version":env!("CARGO_PKG_VERSION")}}),
            ),
            Some("ping") => Ok(json!({})),
            Some("tools/list") => Ok(json!({"tools":[
                {"name":"logmast_catalog","description":"Read current allowances and available capabilities","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true}},
                {"name":"logmast_workspaces","description":"List authorized workspaces","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true}},
                {"name":"logmast_verify","description":"Submit one persisted synthetic verification event and verify evidence readback; requires user authorization to send it","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":false,"idempotentHint":true}}
            ]})),
            Some("tools/call") => {
                let value = match request.pointer("/params/name").and_then(Value::as_str) {
                    Some("logmast_catalog") => client.call("/api/v1/catalog", None, None),
                    Some("logmast_workspaces") => {
                        client.call("/api/v1/workspaces", Some(&saved.bootstrap_secret), None)
                    }
                    Some("logmast_verify") => client.verify(saved),
                    _ => Err(Error::Mcp),
                };
                Ok(match value {
                    Ok(value) => {
                        json!({"content":[{"type":"text","text":value.to_string()}],"isError":false})
                    }
                    Err(error) => {
                        json!({"content":[{"type":"text","text":error.to_string()}],"isError":true})
                    }
                })
            }
            _ => Err(Error::Mcp),
        };
        let response = match result {
            Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
            Err(_) => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}})
            }
        };
        println!("{response}");
        std::io::stdout().flush().map_err(Error::State)?;
    }
}

fn main() {
    match execute(Arguments::parse()) {
        Ok(value) => {
            if !value.is_null() {
                println!("{value}");
            }
        }
        Err(error) => {
            eprintln!("{}", json!({"version":1,"error":error.to_string()}));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn enrollment_retry_preserves_proofs_and_refuses_changed_intent() -> anyhow::Result<()> {
        let directory = std::env::temp_dir().join(format!("logmast-cli-{}", Uuid::now_v7()));
        let path = directory.join("session.json");
        let first = prepare(
            &path,
            "https://app.logmast.com",
            "Team".into(),
            "Prod".into(),
            "API".into(),
        )?;
        let retry = prepare(
            &path,
            "https://app.logmast.com",
            "Team".into(),
            "Prod".into(),
            "API".into(),
        )?;
        assert_eq!(first.id, retry.id);
        assert_eq!(first.verification_occurrence, retry.verification_occurrence);
        assert!(first.bootstrap_secret == retry.bootstrap_secret);
        assert!(first.ingest_secret == retry.ingest_secret);
        assert!(first.bootstrap_secret != first.ingest_secret);
        assert!(matches!(
            prepare(
                &path,
                "https://app.logmast.com",
                "Changed".into(),
                "Prod".into(),
                "API".into()
            ),
            Err(Error::Conflict)
        ));
        assert!(load(&path, "https://other.example").is_err());
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(&directory)?.permissions().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn secrets_refuse_symlinks_and_accessible_state() -> anyhow::Result<()> {
        let directory = std::env::temp_dir().join(format!("logmast-cli-{}", Uuid::now_v7()));
        let path = directory.join("session.json");
        prepare(
            &path,
            "https://app.logmast.com",
            "Team".into(),
            "Prod".into(),
            "API".into(),
        )?;
        let link = directory.join("link.json");
        symlink(&path, &link)?;
        assert!(load(&link, "https://app.logmast.com").is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(load(&path, "https://app.logmast.com").is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
        assert!(load(&path, "https://app.logmast.com").is_err());
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn credentials_can_only_target_an_explicit_safe_origin() {
        for origin in [
            "http://example.com",
            "https://user:secret@example.com",
            "https://example.com/path",
            "https://example.com?token=secret",
            "https://example.com#secret",
        ] {
            assert!(matches!(Client::new(origin), Err(Error::Origin)));
        }
        assert!(Client::new("https://app.logmast.com").is_ok());
        assert!(Client::new("http://127.0.0.1:8670").is_ok());
    }
}
