//! Management only: no file tailing, host collection, background installation,
//! or payload capture. Verification is an explicit, synthetic API submission.
mod binding;
mod login;
mod output;
mod services;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    version,
    about = "Manage Logmast workspaces, services and credentials. Does not capture logs.",
    long_about = "Manage Logmast workspaces, services and credentials. Does not capture logs.\n\nOn a terminal the output is short text; piped, or with --format json, it is stable JSON. Secrets are never printed: they are saved privately or written to files you name.",
    after_help = "Credentials, in order: LOGMAST_AGENT_TOKEN; --credential (or LOGMAST_CREDENTIAL), a JSON file downloaded from Access > Agents; the nearest `logmastctl login`; the enrollment state.\nStart with `logmastctl login`. Run `logmastctl setup` in a repository to give its commands a default workspace and project; `logmastctl whoami` shows what a command here would use."
)]
struct Arguments {
    /// The Logmast installation.
    #[arg(
        long,
        global = true,
        default_value = "https://app.logmast.com",
        env = "LOGMAST_URL"
    )]
    url: String,
    /// Private state file. Enrollment secrets are saved before network requests.
    #[arg(long,global = true,env="LOGMAST_STATE",default_value_os_t=default_state())]
    state: PathBuf,
    /// Origin-bound agent credential JSON; alternative to LOGMAST_AGENT_TOKEN.
    #[arg(long, global = true, env = "LOGMAST_CREDENTIAL")]
    credential: Option<PathBuf>,
    /// Output for people (text) or programs (JSON). Auto picks text on a terminal.
    #[arg(
        long,
        global = true,
        value_enum,
        default_value = "auto",
        env = "LOGMAST_FORMAT"
    )]
    format: output::OutputFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read the installation's allowances, prices and capabilities, without signing in.
    Catalog,
    /// Read the installation's current OpenAPI contract without signing in.
    Schema,
    /// Start a trial: create a workspace, project and service for this machine's enrollment.
    Enroll {
        #[arg(long)]
        workspace: String,
        #[arg(long)]
        project: String,
        #[arg(long)]
        service: String,
    },
    /// Sign this machine in: a person approves a code in the console. The access is kept in a
    /// private file and never printed. At a terminal it opens the browser and waits; otherwise
    /// it prints the link and code, and `login --wait` finishes once someone has approved.
    Login {
        /// Ask for this workspace; omitted, the approver chooses one of theirs.
        #[arg(long)]
        workspace: Option<Uuid>,
        /// Ask for access to one project only.
        #[arg(long)]
        project: Option<Uuid>,
        /// Read only, or management (services, credentials, rules); management needs the
        /// approver's authenticator code.
        #[arg(long, value_enum, default_value = "read")]
        permission: login::Permission,
        /// How long the access lasts.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u16).range(1..=360))]
        days: u16,
        /// Use this login only in this directory tree; omitted, anywhere on this machine.
        #[arg(long)]
        scope: Option<PathBuf>,
        /// Wait for the decision on the login already started here.
        #[arg(long)]
        wait: bool,
        /// Cancel the login waiting on this machine.
        #[arg(long, conflicts_with = "wait")]
        cancel: bool,
    },
    /// End the login a command here would use; its access is revoked at Logmast.
    Logout {
        #[arg(long)]
        workspace: Option<Uuid>,
    },
    /// Show which credential and directory binding a command here would use. Never prints secrets.
    Whoami {
        #[arg(long)]
        workspace: Option<Uuid>,
    },
    /// List the workspaces this credential can reach.
    Workspaces,
    /// Give this directory a default workspace and project for later commands.
    Setup {
        /// Defaults to the only workspace this credential reaches.
        #[arg(long)]
        workspace: Option<Uuid>,
        #[arg(long)]
        project: Option<Uuid>,
        /// Defaults to the current directory.
        #[arg(long)]
        directory: Option<PathBuf>,
    },
    /// List a workspace's projects and services.
    Projects { workspace: Option<Uuid> },
    /// Read a workspace's trial, services and the next human action, if any.
    Status { workspace: Option<Uuid> },
    /// Ask the owner to claim an enrolled workspace; the proof goes to their inbox, not here.
    Claim {
        workspace: Uuid,
        #[arg(long)]
        email: String,
    },
    /// Send one synthetic failure and read it back: the enrollment's service, or --service.
    Verify {
        /// A service whose credential this machine holds (created or rotated here, or enrolled).
        #[arg(long)]
        service: Option<Uuid>,
        /// Resume or re-read one persisted run; omitted resumes an uncertain run or starts fresh.
        #[arg(long)]
        run_id: Option<Uuid>,
    },
    /// Read a workspace's balance and top-ups; never buys anything.
    Billing { workspace: Option<Uuid> },
    /// List the agent grants of a workspace (owners only).
    Agents { workspace: Option<Uuid> },
    /// Create services.
    #[command(subcommand)]
    Services(ServicesCommand),
    /// Rotate or export services' ingest credentials.
    #[command(subcommand)]
    Credentials(CredentialsCommand),
    /// Send one management command. Save its result privately, including any
    /// newly issued ingestion secret. Never automatically retries a mutation.
    Control {
        workspace: Option<Uuid>,
        #[arg(long)]
        command_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Save the Sentry DSN of the enrollment's original credential to a private file. The
    /// DSN is a credential, so it is never printed. After a rotation, use
    /// `credentials export --service ID --dsn-file PATH` instead.
    SentryDsn {
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum ServicesCommand {
    /// Create a service and keep its ingest credential privately on this machine.
    Create {
        #[arg(long)]
        name: String,
        /// Defaults to this directory's project (see `setup`).
        #[arg(long)]
        project: Option<Uuid>,
        #[arg(long)]
        workspace: Option<Uuid>,
        /// Also write LOGMAST_* settings to this new file (mode 600).
        #[arg(long)]
        env_file: Option<PathBuf>,
        /// Also write SENTRY_DSN to this new file (mode 600), for a Sentry SDK.
        #[arg(long)]
        dsn_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CredentialsCommand {
    /// Issue a new ingest credential; the service's earlier credentials stop at once.
    Rotate {
        #[arg(long)]
        service: Uuid,
        #[arg(long)]
        workspace: Option<Uuid>,
        #[arg(long)]
        env_file: Option<PathBuf>,
        #[arg(long)]
        dsn_file: Option<PathBuf>,
    },
    /// Write a credential this machine holds to new files, or show it on a terminal.
    Export {
        #[arg(long)]
        service: Uuid,
        #[arg(long)]
        env_file: Option<PathBuf>,
        #[arg(long)]
        dsn_file: Option<PathBuf>,
        /// Print the settings, only when output is a terminal a person reads.
        #[arg(long, conflicts_with_all = ["env_file", "dsn_file"])]
        reveal: bool,
    },
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("private state unavailable or unsafe")]
    State(#[source] std::io::Error),
    #[error("invalid state; preserve it and inspect its structure without printing credentials")]
    InvalidState,
    #[error("invalid LOGMAST_AGENT_TOKEN; expected a 64-character lowercase hexadecimal token")]
    InvalidAgentToken,
    #[error("choose LOGMAST_AGENT_TOKEN or --credential/LOGMAST_CREDENTIAL, not both")]
    CredentialSources,
    #[error("HTTPS is required, except on loopback; URL must be an origin without credentials")]
    Origin,
    #[error("transport unavailable; outcome uncertain; follow the operation's recovery rules")]
    Transport(#[source] ureq::Error),
    #[error("Logmast returned HTTP {0}; credentials and response body suppressed")]
    Http(u16),
    #[error(
        "Logmast returned HTTP 402: the allowance is used up; run `logmastctl claim` for an unverified workspace, otherwise renew its coverage"
    )]
    AllowanceUsed,
    #[error("enrollment arguments differ from saved state")]
    Conflict,
    #[error("readback did not match the submitted verification event")]
    Verification,
    #[error(
        "the verification event was counted but not stored because the balance has run out; add credit and verify again"
    )]
    NotStored,
    #[error("no enrollment state on this machine")]
    NoEnrollmentState,
    #[error("no workspace chosen")]
    NeedsWorkspace,
    #[error("no project chosen")]
    NeedsProject,
    #[error("this machine holds no credential for service {0}")]
    NoSavedCredential(Uuid),
    #[error("service {service} has a new credential, but it could not be saved here: {cause}")]
    CredentialNotSaved {
        service: Uuid,
        #[source]
        cause: Box<Error>,
    },
    #[error("Logmast's response could not be read; the change may have been made")]
    UnreadableResponse,
    #[error("{0} already exists; it is never overwritten")]
    OutputExists(PathBuf),
    #[error("{0} can be written by other users")]
    UnsafeOutputDirectory(PathBuf),
    #[error("--reveal prints a secret, so it only prints to a terminal")]
    RevealNeedsTerminal,
    #[error("nothing to export to")]
    NoExportTarget,
    #[error(
        "the outcome of creating service {name} is unknown; it may exist without a credential here"
    )]
    UncertainCreate { name: String },
    #[error(
        "the outcome of rotating service {service} is unknown; its credential may already have changed"
    )]
    UncertainRotate { service: Uuid },
    #[error("Logmast refused service {0}'s ingest credential: it was rotated or revoked")]
    IngestRefused(Uuid),
    #[error("no credential: no agent token, credential file, login or enrollment state")]
    NoManagementCredential,
    #[error("no login is waiting for approval on this machine")]
    NoPendingLogin,
    #[error("the login was denied in the console")]
    LoginDenied,
    #[error("the login code expired before anyone approved it")]
    LoginExpired,
    #[error(
        "the login was approved for a different workspace or project than it asked for; it was revoked and not kept"
    )]
    LoginMismatch,
    #[error("another login is waiting for approval on this machine")]
    PendingLoginExists,
    #[error(
        "a login without --workspace lets whoever approves it choose the workspace; only a person at a terminal may accept that"
    )]
    LoginNeedsWorkspace,
    #[error("the --scope directory's path is not valid Unicode")]
    ScopeNotUnicode,
    #[error("the login was not kept; its access was revoked")]
    LoginDiscarded,
    #[error("several logins apply here")]
    AmbiguousLogin,
    #[error("no login applies here")]
    NoLogin,
    #[error(transparent)]
    Binding(#[from] binding::BindingError),
}

impl Error {
    /// A stable code for programs; the message is for people and may change.
    fn code(&self) -> &'static str {
        match self {
            Error::State(_) => "STATE_UNAVAILABLE",
            Error::InvalidState => "STATE_INVALID",
            Error::InvalidAgentToken => "AGENT_TOKEN_INVALID",
            Error::CredentialSources => "CREDENTIAL_SOURCES_CONFLICT",
            Error::Origin => "ORIGIN_INVALID",
            Error::Transport(_) => "TRANSPORT_UNCERTAIN",
            Error::Http(401) => "AUTH_REQUIRED",
            Error::Http(403) => "PERMISSION_DENIED",
            Error::Http(404) => "NOT_FOUND",
            Error::Http(409) => "CONFLICT",
            Error::Http(429) => "LIMITED",
            Error::Http(_) => "HTTP_ERROR",
            Error::AllowanceUsed => "ALLOWANCE_USED",
            Error::Conflict => "STATE_CONFLICT",
            Error::Verification => "VERIFICATION_MISMATCH",
            Error::NotStored => "NOT_STORED",
            Error::NoEnrollmentState => "NO_ENROLLMENT_STATE",
            Error::NeedsWorkspace => "WORKSPACE_REQUIRED",
            Error::NeedsProject => "PROJECT_REQUIRED",
            Error::NoSavedCredential(_) => "NO_SAVED_CREDENTIAL",
            Error::CredentialNotSaved { .. } => "CREDENTIAL_NOT_SAVED",
            Error::UnreadableResponse => "RESPONSE_UNREADABLE",
            Error::OutputExists(_) => "OUTPUT_EXISTS",
            Error::UnsafeOutputDirectory(_) => "OUTPUT_DIRECTORY_UNSAFE",
            Error::RevealNeedsTerminal => "REVEAL_NEEDS_TERMINAL",
            Error::NoExportTarget => "EXPORT_TARGET_REQUIRED",
            Error::UncertainCreate { .. } => "CREATE_UNCERTAIN",
            Error::UncertainRotate { .. } => "ROTATE_UNCERTAIN",
            Error::IngestRefused(_) => "INGEST_CREDENTIAL_REFUSED",
            Error::NoManagementCredential => "NO_MANAGEMENT_CREDENTIAL",
            Error::NoPendingLogin => "NO_PENDING_LOGIN",
            Error::LoginDenied => "LOGIN_DENIED",
            Error::LoginExpired => "LOGIN_EXPIRED",
            Error::LoginMismatch => "LOGIN_MISMATCH",
            Error::PendingLoginExists => "LOGIN_PENDING",
            Error::LoginNeedsWorkspace => "LOGIN_WORKSPACE_REQUIRED",
            Error::ScopeNotUnicode => "SCOPE_INVALID",
            Error::LoginDiscarded => "LOGIN_DISCARDED",
            Error::AmbiguousLogin => "LOGIN_AMBIGUOUS",
            Error::NoLogin => "NO_LOGIN",
            Error::Binding(_) => "BINDINGS_UNAVAILABLE",
        }
    }
}

/// What the failed command needed, so a refusal links to the console page that grants it.
#[derive(Clone, Copy)]
enum NeededAuthority {
    Read,
    Management,
    Owner,
}

/// The console link and authority a failure's next step refers to.
struct HintContext {
    origin: String,
    workspace: Option<Uuid>,
    needed: NeededAuthority,
}

/// What to do next after a failure. Every failure has one; human-only work is handed off as
/// a console link rather than attempted.
fn next_step(error: &Error, context: &HintContext) -> String {
    let console = |path: &str, tab: Option<&str>| {
        let mut link = format!("{}{path}", context.origin);
        let mut separator = '?';
        if let Some(workspace) = context.workspace {
            link.push_str(&format!("{separator}workspace={workspace}"));
            separator = '&';
        }
        if let Some(tab) = tab {
            link.push_str(&format!("{separator}tab={tab}"));
        }
        link
    };
    match error {
        Error::Http(401) => format!("this credential was refused: it is missing, expired or revoked. An owner can give agent access at {}", console("/access", Some("agents"))),
        Error::Http(403) => match context.needed {
            NeededAuthority::Read => format!("this credential cannot read this workspace; check the workspace ID, or ask an owner for access at {}", console("/access", Some("agents"))),
            NeededAuthority::Management => format!("this needs management permission: ask an owner for agent access with management at {}", console("/access", Some("agents"))),
            NeededAuthority::Owner => format!("only an owner can do this, in the console at {}", console("/settings", None)),
        },
        Error::Http(404) => "not found: check the workspace and service IDs with `logmastctl projects`".into(),
        Error::Http(409) => "this conflicts with what was saved; inspect the current state before retrying".into(),
        Error::Http(429) => "a limit was reached; wait before retrying with the same identities".into(),
        Error::Http(_) | Error::Transport(_) => "the outcome is uncertain: read the current state (`logmastctl projects`, `status`) before repeating a change".into(),
        Error::UncertainCreate { name } => format!("run `logmastctl projects`: if a service named {name} exists, run `logmastctl credentials rotate --service SERVICE_ID` to get its credential here instead of creating another"),
        Error::UncertainRotate { service } => format!("producers may already be cut off: rotate again (`logmastctl credentials rotate --service {service}`) and update every producer with the result"),
        Error::IngestRefused(service) => format!("get a current credential here with `logmastctl credentials rotate --service {service}` (producers using the old one stop), then verify again"),
        Error::NoManagementCredential => format!("run `logmastctl login --workspace WORKSPACE_ID` (add `--permission manage` to change services) and have an owner approve the code; for CI, use a credential file from {}", console("/access", Some("agents"))),
        Error::NoPendingLogin => "start one with `logmastctl login`".into(),
        Error::LoginDenied => "ask the person who denied it, then run `logmastctl login` again".into(),
        Error::LoginExpired => "run `logmastctl login` again and approve the new code within ten minutes".into(),
        Error::LoginMismatch => "run `logmastctl login` again; whoever approves must keep the workspace and project it asks for".into(),
        Error::PendingLoginExists => "finish it with `logmastctl login --wait`, cancel it with `logmastctl login --cancel`, or wait ten minutes for it to expire".into(),
        Error::LoginNeedsWorkspace => "pass --workspace WORKSPACE_ID (the person handing you the work can copy it from the console), or run `logmastctl login` yourself in a terminal".into(),
        Error::ScopeNotUnicode => "choose a --scope directory whose path is valid Unicode".into(),
        Error::LoginDiscarded => "run `logmastctl login --workspace WORKSPACE_ID` to ask for a specific workspace".into(),
        Error::AmbiguousLogin => "pass the workspace ID, run `logmastctl setup --workspace WORKSPACE_ID` here, or log in with `--scope DIR`".into(),
        Error::NoLogin => "`logmastctl whoami` shows which credential a command here uses".into(),
        Error::NoEnrollmentState => "to verify a service you manage, run `logmastctl verify --service SERVICE_ID`; `logmastctl projects` lists them".into(),
        Error::NeedsWorkspace => "pass the workspace ID, or run `logmastctl setup --workspace WORKSPACE_ID` in this directory; `logmastctl workspaces` lists them".into(),
        Error::NeedsProject => "pass --project, or run `logmastctl setup --project PROJECT_ID`; `logmastctl projects` lists them".into(),
        Error::NoSavedCredential(service) => format!("credentials are shown only once. Rotate to get one here: `logmastctl credentials rotate --service {service}` (producers using the current one stop)"),
        Error::CredentialNotSaved { service, .. } => format!("fix the state directory, then `logmastctl credentials rotate --service {service}`"),
        Error::UnreadableResponse => "inspect the workspace with `logmastctl projects` before repeating".into(),
        Error::OutputExists(_) => "choose a new path, or remove the old file after checking it".into(),
        Error::UnsafeOutputDirectory(_) => "write into a directory that other users cannot write to".into(),
        Error::RevealNeedsTerminal => "use --env-file or --dsn-file, or run it yourself in a terminal with text output".into(),
        Error::NoExportTarget => "pass --env-file, --dsn-file or, at a terminal, --reveal".into(),
        Error::AllowanceUsed => format!("an owner can claim the workspace or add credit at {}", console("/billing", None)),
        Error::State(_) | Error::InvalidState => "check that the state directory is yours and private (mode 700, files 600) and not a symlink; preserve it rather than deleting it".into(),
        Error::Conflict => "another logmastctl is verifying, or the saved enrollment differs: wait, or repeat with the same arguments".into(),
        Error::InvalidAgentToken => format!("copy the token again from {}, or use --credential with the downloaded file", console("/access", Some("agents"))),
        Error::CredentialSources => "unset LOGMAST_AGENT_TOKEN or drop --credential".into(),
        Error::Origin => "use an https:// origin (http only for loopback) with no path or credentials".into(),
        Error::Verification => "the readback did not match; run `logmastctl verify` again with the same run ID".into(),
        Error::NotStored => format!("add credit at {}, then verify again", console("/billing", None)),
        Error::Binding(_) => "inspect or remove the named bindings file; commands with explicit IDs do not need it".into(),
    }
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

/// One verification run, persisted before anything is sent. Its owner is the enrollment it
/// verifies, or the service whose saved credential it uses.
#[derive(Serialize, Deserialize)]
struct VerificationRun {
    version: u32,
    origin: String,
    #[serde(rename = "enrollment")]
    owner: Uuid,
    run_id: Uuid,
    occurrence_id: Uuid,
    timestamp: String,
    result: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagementCredential {
    version: u32,
    origin: String,
    token: String,
}

struct Client {
    origin: String,
    agent: ureq::Agent,
}

/// Where a verification sends its synthetic event, and with which ingest secret.
struct DeliveryTarget<'a> {
    workspace: Uuid,
    service: Uuid,
    ingest_secret: &'a str,
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
        if response.status().as_u16() == 402 {
            return Err(Error::AllowanceUsed);
        }
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
    /// Verifies an enrollment's own service with the enrollment's ingest secret.
    fn verify_enrollment(
        &self,
        state: &Path,
        saved: &Saved,
        run: &VerificationRun,
        token: &str,
    ) -> Result<Value, Error> {
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
        record_enrolled_credential(state, &self.origin, saved, &enrollment)?;
        // After a rotation the saved credential is the current one; the enrollment's is revoked.
        let current = services::load_credential(state, &self.origin, service)?;
        let ingest_secret = current
            .as_ref()
            .map_or(saved.ingest_secret.as_str(), |credential| {
                credential.ingest_secret()
            });
        self.verify_delivery(
            &DeliveryTarget {
                workspace,
                service,
                ingest_secret,
            },
            run,
            token,
        )
    }

    /// Sends one synthetic failure with the ingest secret, checks its durable receipt, and
    /// reads the occurrence back with the management credential.
    fn verify_delivery(
        &self,
        target: &DeliveryTarget<'_>,
        run: &VerificationRun,
        token: &str,
    ) -> Result<Value, Error> {
        let (workspace, service) = (target.workspace, target.service);
        let receipt=self.call("/api/v1/ingest/batches",Some(target.ingest_secret),Some(json!({"batch_id":run.run_id,"service_id":service,"events":[{
            "occurrence_id":run.occurrence_id,"timestamp":run.timestamp,"environment":"verification","severity":"error","outcome":"failed",
            "message":"Logmast synthetic enrollment verification","code":"LOGMAST.ONBOARDING.VERIFY","correlation_ids":[run.run_id.to_string()]
        }]}))).map_err(|error| match error {
            // A rotated or revoked ingest credential, not the management credential.
            Error::Http(401) => Error::IngestRefused(service),
            other => other,
        })?;
        let receipt_id = receipt
            .get("receipt_id")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
            .filter(|id| !id.is_nil())
            .ok_or(Error::Verification)?;
        let accepted = receipt
            .get("new_events")
            .and_then(Value::as_u64)
            .and_then(|new| {
                receipt
                    .get("duplicates")
                    .and_then(Value::as_u64)
                    .and_then(|duplicates| new.checked_add(duplicates))
            });
        if accepted != Some(1) {
            return Err(Error::Verification);
        }
        if receipt.get("stored_events").and_then(Value::as_u64) == Some(0)
            && receipt.get("new_events").and_then(Value::as_u64) == Some(1)
        {
            return Err(Error::NotStored);
        }
        let occurrence = self.call(
            &format!(
                "/api/v1/workspaces/{workspace}/services/{service}/occurrences/{}",
                run.occurrence_id
            ),
            Some(token),
            None,
        )?;
        let verified = occurrence.get("event").is_some_and(|event| {
            event.get("occurrence_id").and_then(Value::as_str)
                == Some(run.occurrence_id.to_string().as_str())
                && event.get("service_id").and_then(Value::as_str)
                    == Some(service.to_string().as_str())
                && event.get("workspace_id").and_then(Value::as_str)
                    == Some(workspace.to_string().as_str())
                && event.pointer("/payload/code").and_then(Value::as_str)
                    == Some("LOGMAST.ONBOARDING.VERIFY")
                && event
                    .pointer("/payload/correlation_ids")
                    .and_then(Value::as_array)
                    .is_some_and(|ids| {
                        ids.iter()
                            .any(|id| id.as_str() == Some(run.run_id.to_string().as_str()))
                    })
        });
        if !verified {
            return Err(Error::Verification);
        }
        let group_query = occurrence
            .pointer("/event/group_id")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
            .map(|id| format!("&group={id}"))
            .unwrap_or_default();
        let mut processing = self
            .call(
                &format!("/api/v1/workspaces/{workspace}/receipts/{receipt_id}"),
                Some(token),
                None,
            )
            .ok();
        for _ in 0..10 {
            if !processing
                .as_ref()
                .is_some_and(|status| status.get("processed_at").is_some_and(Value::is_null))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
            processing = self
                .call(
                    &format!("/api/v1/workspaces/{workspace}/receipts/{receipt_id}"),
                    Some(token),
                    None,
                )
                .ok();
        }
        Ok(
            json!({"version":2,"verified":verified,"historical":false,"run_id":run.run_id,"observed_at":run.timestamp,"verified_at":chrono::Utc::now(),"receipt":receipt,"workspace_id":workspace,"service_id":service,"occurrence_id":run.occurrence_id,
            "stages":{"durable_acceptance":true,"evidence_readback":true,"application_instrumentation":"not_proven","inbox_delivery":"not_proven","processing":processing},
            "investigation_url":format!("{}/?workspace={workspace}&service={service}&occurrence={}&view=all{group_query}",self.origin,run.occurrence_id)}),
        )
    }
}

fn secret() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
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

fn agent_token_from_environment() -> Result<Option<String>, Error> {
    match std::env::var("LOGMAST_AGENT_TOKEN") {
        Ok(token) => Ok(Some(token)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        // Do not retain the non-Unicode secret in an error source.
        Err(std::env::VarError::NotUnicode(_)) => Err(Error::InvalidAgentToken),
    }
}

fn valid_agent_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Where the credential a command uses came from, for `logmastctl whoami`.
enum CredentialSource {
    Environment,
    CredentialFile(PathBuf),
    Login {
        path: PathBuf,
        scope: Option<PathBuf>,
    },
    Enrollment,
}

impl CredentialSource {
    fn describe(&self) -> Value {
        match self {
            CredentialSource::Environment => {
                json!({"kind":"environment","name":"LOGMAST_AGENT_TOKEN"})
            }
            CredentialSource::CredentialFile(path) => json!({"kind":"credential_file","path":path}),
            CredentialSource::Login { path, scope } => {
                json!({"kind":"login","path":path,"scope":scope})
            }
            CredentialSource::Enrollment => json!({"kind":"enrollment"}),
        }
    }
}

// Intentionally no Debug: it holds the token.
struct HeldCredential {
    token: String,
    source: CredentialSource,
}

/// The credential a command uses: LOGMAST_AGENT_TOKEN, then --credential, then the login that
/// applies here (looked up only when needed), then the enrollment state.
fn management_token(
    agent_token: Option<String>,
    path: &Option<PathBuf>,
    state: &PathBuf,
    origin: &str,
    applicable_login: impl FnOnce() -> Result<Option<login::FoundLogin>, Error>,
) -> Result<HeldCredential, Error> {
    if let Some(token) = agent_token {
        if path.is_some() {
            return Err(Error::CredentialSources);
        }
        if !valid_agent_token(&token) {
            return Err(Error::InvalidAgentToken);
        }
        return Ok(HeldCredential {
            token,
            source: CredentialSource::Environment,
        });
    }
    let Some(path) = path else {
        if let Some(found) = applicable_login()? {
            return Ok(HeldCredential {
                token: found.login.token().to_owned(),
                source: CredentialSource::Login {
                    scope: found.login.scope.clone(),
                    path: found.path,
                },
            });
        }
        return match load(state, origin) {
            Ok(saved) => Ok(HeldCredential {
                token: saved.bootstrap_secret,
                source: CredentialSource::Enrollment,
            }),
            Err(Error::State(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::NoManagementCredential)
            }
            Err(error) => Err(error),
        };
    };
    let mut file = open_state(path, false)?;
    let mut bytes = String::new();
    file.read_to_string(&mut bytes).map_err(Error::State)?;
    let credential: ManagementCredential =
        serde_json::from_str(&bytes).map_err(|_| Error::InvalidState)?;
    if credential.version != 1
        || credential.origin != origin
        || !valid_agent_token(&credential.token)
    {
        return Err(Error::InvalidState);
    }
    Ok(HeldCredential {
        token: credential.token,
        source: CredentialSource::CredentialFile(path.clone()),
    })
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

fn read_run(path: &PathBuf, origin: &str, owner: Uuid) -> Result<VerificationRun, Error> {
    let mut file = open_state(path, false)?;
    let mut bytes = String::new();
    file.read_to_string(&mut bytes).map_err(Error::State)?;
    let run: VerificationRun = serde_json::from_str(&bytes).map_err(|_| Error::InvalidState)?;
    if run.version != 1
        || run.origin != origin
        || run.owner != owner
        || run.run_id.is_nil()
        || run.occurrence_id.is_nil()
    {
        return Err(Error::InvalidState);
    }
    Ok(run)
}

fn save_run(path: &PathBuf, run: &VerificationRun) -> Result<(), Error> {
    // Write and fsync a new private file, then atomically replace the pointer or
    // result. The separate stable lock inode serializes concurrent invocations.
    let temporary = path.with_extension(format!("{}.tmp", Uuid::now_v7()));
    let mut file = open_state(&temporary, true)?;
    let bytes = serde_json::to_vec(run).map_err(|_| Error::InvalidState)?;
    file.write_all(&bytes).map_err(Error::State)?;
    file.sync_all().map_err(Error::State)?;
    fs::rename(&temporary, path).map_err(Error::State)?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(Error::State)?;
    }
    Ok(())
}

/// Records the enrolled service's ingest credential beside the others, unless this machine
/// already holds a newer one for it (after a rotation).
fn record_enrolled_credential(
    state: &Path,
    origin: &str,
    saved: &Saved,
    enrolled: &Value,
) -> Result<(), Error> {
    let identity = |name: &str| -> Result<Uuid, Error> {
        serde_json::from_value(enrolled.get(name).cloned().ok_or(Error::InvalidState)?)
            .map_err(|_| Error::InvalidState)
    };
    let service = identity("service_id")?;
    if services::load_credential(state, origin, service)?.is_some() {
        return Ok(());
    }
    services::save_credential(
        state,
        &services::ServiceCredential::new(
            origin.to_owned(),
            identity("workspace_id")?,
            service,
            saved.ingest_secret.clone(),
        ),
    )
}

fn verify_run(
    client: &Client,
    state: &PathBuf,
    token: &str,
    requested: Option<Uuid>,
) -> Result<Value, Error> {
    let saved = match load(state, &client.origin) {
        Err(Error::State(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::NoEnrollmentState);
        }
        other => other?,
    };
    persisted_verification(state, &client.origin, saved.id, requested, |run| {
        client.verify_enrollment(state, &saved, run, token)
    })
}

/// Runs, resumes or replays one verification persisted beside `base`. An interrupted run
/// resumes unchanged; after completion the next call starts a fresh run, and a completed
/// run asked for by ID returns its historical proof.
fn persisted_verification(
    base: &Path,
    origin: &str,
    owner: Uuid,
    requested: Option<Uuid>,
    execute: impl FnOnce(&VerificationRun) -> Result<Value, Error>,
) -> Result<Value, Error> {
    let lock_path = base.with_extension("verify.lock");
    let lock = match open_state(&lock_path, true) {
        Ok(file) => file,
        Err(Error::State(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            open_state(&lock_path, false)?
        }
        Err(error) => return Err(error),
    };
    lock.try_lock().map_err(|_| Error::Conflict)?;
    let current = base.with_extension("verification.json");
    let pending = if requested.is_none() && current.try_exists().map_err(Error::State)? {
        let previous = read_run(&current, origin, owner)?;
        let previous_path = base.with_extension(format!("verification-{}.json", previous.run_id));
        Some(read_run(&previous_path, origin, owner)?)
    } else {
        None
    };
    let id = requested
        .or_else(|| {
            pending
                .as_ref()
                .filter(|run| run.result.is_none())
                .map(|run| run.run_id)
        })
        .unwrap_or_else(Uuid::now_v7);
    if id.is_nil() {
        return Err(Error::InvalidState);
    }
    let path = base.with_extension(format!("verification-{id}.json"));
    let mut run = if path.try_exists().map_err(Error::State)? {
        read_run(&path, origin, owner)?
    } else {
        VerificationRun {
            version: 1,
            origin: origin.to_owned(),
            owner,
            run_id: id,
            occurrence_id: Uuid::now_v7(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            result: None,
        }
    };
    if run.run_id != id {
        return Err(Error::InvalidState);
    }
    if let Some(mut result) = run.result {
        result
            .as_object_mut()
            .ok_or(Error::InvalidState)?
            .insert("historical".into(), Value::Bool(true));
        return Ok(result);
    }
    save_run(&path, &run)?;
    if requested.is_none() {
        save_run(&current, &run)?;
    }
    let result = match execute(&run) {
        Err(Error::NotStored) => {
            // Logmast replays this run's receipt, so it can never be stored now.
            // Close it, so the next verify starts a fresh run.
            run.result = Some(json!({"version":1,"stored":false,"reason":"balance_exhausted"}));
            save_run(&path, &run)?;
            if requested.is_none() {
                save_run(&current, &run)?;
            }
            return Err(Error::NotStored);
        }
        other => other?,
    };
    run.result = Some(result.clone());
    save_run(&path, &run)?;
    Ok(result)
}

/// A JSON member, or null: response fields read for display only.
fn field<'value>(value: &'value Value, key: &str) -> &'value Value {
    value.get(key).unwrap_or(&Value::Null)
}

fn workspace_lines(workspaces: &Value) -> String {
    let lines: Vec<String> = workspaces
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    format!(
                        "{} ({}) · {}",
                        field(item, "name").as_str().unwrap_or("?"),
                        field(item, "id").as_str().unwrap_or("?"),
                        field(item, "role").as_str().unwrap_or("?")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if lines.is_empty() {
        "No workspaces.".into()
    } else {
        lines.join("\n")
    }
}

fn project_lines(status: &Value) -> String {
    let services = field(status, "services")
        .as_array()
        .cloned()
        .unwrap_or_default();
    let projects = field(status, "projects")
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut lines = Vec::new();
    for project in &projects {
        lines.push(format!(
            "{} ({})",
            field(project, "name").as_str().unwrap_or("?"),
            field(project, "id").as_str().unwrap_or("?")
        ));
        let own: Vec<&Value> = services
            .iter()
            .filter(|service| field(service, "project_id") == field(project, "id"))
            .collect();
        for service in own {
            lines.push(format!(
                "  {} ({})",
                field(service, "name").as_str().unwrap_or("?"),
                field(service, "id").as_str().unwrap_or("?")
            ));
        }
    }
    if lines.is_empty() {
        "No projects.".into()
    } else {
        lines.join("\n")
    }
}

fn verification_text(result: &Value) -> String {
    let historical = if field(result, "historical") == &Value::Bool(true) {
        "Earlier verification (historical): "
    } else {
        ""
    };
    format!(
        "{historical}delivered and read back for service {}: receipt {}, occurrence {}.\nOpen: {}\nThis proves the API connection, not your application's instrumentation: trigger one real failure next.",
        field(result, "service_id").as_str().unwrap_or("?"),
        result
            .pointer("/receipt/receipt_id")
            .and_then(Value::as_str)
            .unwrap_or("?"),
        field(result, "occurrence_id").as_str().unwrap_or("?"),
        field(result, "investigation_url").as_str().unwrap_or("?"),
    )
}

/// The only workspace a credential reaches; with none or several, the command must name one.
fn only_workspace(client: &Client, token: &str) -> Result<Uuid, Error> {
    let reachable = client.call("/api/v1/workspaces", Some(token), None)?;
    let ids: Vec<Uuid> = reachable
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    field(item, "id")
                        .as_str()
                        .and_then(|id| Uuid::parse_str(id).ok())
                })
                .collect()
        })
        .unwrap_or_default();
    match ids.as_slice() {
        [only] => Ok(*only),
        _ => Err(Error::NeedsWorkspace),
    }
}

fn setup(
    client: &Client,
    token: &str,
    bindings: &Path,
    workspace: Option<Uuid>,
    project: Option<Uuid>,
    directory: PathBuf,
) -> Result<output::Report, Error> {
    let workspace = match workspace {
        Some(workspace) => workspace,
        None => only_workspace(client, token)?,
    };
    let status = client.call(
        &format!("/api/v1/workspaces/{workspace}/enrollment"),
        Some(token),
        None,
    )?;
    let project_name = match project {
        None => None,
        Some(project) => {
            let name = field(&status, "projects")
                .as_array()
                .and_then(|projects| {
                    projects.iter().find(|item| {
                        field(item, "id").as_str() == Some(project.to_string().as_str())
                    })
                })
                .and_then(|item| field(item, "name").as_str())
                .map(str::to_owned);
            Some(name.ok_or(Error::NeedsProject)?)
        }
    };
    let directory = directory.canonicalize().map_err(Error::State)?;
    binding::bind(
        bindings,
        binding::Binding {
            directory: directory.clone(),
            origin: client.origin.clone(),
            workspace,
            project,
        },
    )?;
    let project_text = project_name
        .map(|name| format!(", project {name}"))
        .unwrap_or_default();
    Ok(output::Report::with_text(
        json!({"version":1,"directory":directory,"origin":client.origin,"workspace":workspace,"project":project}),
        format!(
            "{} now uses workspace {workspace}{project_text}.",
            directory.display()
        ),
    ))
}

/// The directory binding, read only when a command omits an ID it could supply.
fn bound_directory(origin: &str) -> Result<Option<binding::Binding>, Error> {
    let directory = std::env::current_dir().map_err(Error::State)?;
    Ok(binding::resolve(
        &binding::default_path(),
        origin,
        &directory,
    )?)
}

/// The login a command run here would use: for the workspace it names, else the directory's
/// binding. Bindings are read only when this machine holds a login.
fn applicable_login(
    state: &Path,
    origin: &str,
    named: Option<Uuid>,
) -> Result<Option<login::FoundLogin>, Error> {
    if !login::any(state, origin)? {
        return Ok(None);
    }
    let directory = std::env::current_dir().map_err(Error::State)?;
    let target = match named {
        Some(workspace) => Some(login::Target {
            workspace,
            project: None,
        }),
        None => bound_directory(origin)?.map(|binding| login::Target {
            workspace: binding.workspace,
            project: binding.project,
        }),
    };
    login::resolve(state, origin, &directory, target)
}

/// Opens the approval page in the person's browser; failing to is harmless, the link is printed.
fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _spawned = std::process::Command::new(opener)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Asks the person at the terminal; anything but yes is no.
fn confirmed(question: &str) -> Result<bool, Error> {
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().map_err(Error::State)?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(Error::State)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

fn execute(arguments: Arguments, mode: output::OutputMode) -> Result<output::Report, Error> {
    let client = Client::new(&arguments.url)?;
    let named = named_workspace(&arguments.command);
    let bindings = binding::default_path();
    match arguments.command {
        Command::Catalog => Ok(output::Report::json(client.call(
            "/api/v1/catalog",
            None,
            None,
        )?)),
        Command::Schema => Ok(output::Report::json(client.call(
            "/openapi.json",
            None,
            None,
        )?)),
        Command::Enroll {
            workspace,
            project,
            service,
        } => {
            let saved = prepare(
                &arguments.state,
                &client.origin,
                workspace,
                project,
                service,
            )?;
            let mut enrolled = client.enroll(&saved)?;
            record_enrolled_credential(&arguments.state, &client.origin, &saved, &enrolled)?;
            // The DSN is a credential and output is printed; `credentials export` writes it privately.
            if let Some(fields) = enrolled.as_object_mut() {
                fields.remove("sentry_dsn");
            }
            Ok(output::Report::json(enrolled))
        }
        Command::SentryDsn { output } => {
            let saved = load(&arguments.state, &client.origin)?;
            let dsn = sentry_dsn(&client.origin, &saved.ingest_secret)?;
            let mut file = open_state(&output, true)?;
            file.write_all(json!({"version":1,"sentry_dsn":dsn}).to_string().as_bytes())
                .map_err(Error::State)?;
            file.sync_all().map_err(Error::State)?;
            Ok(output::Report::json(
                json!({"version":1,"saved_to":output,"secrets_printed":false}),
            ))
        }
        // Exporting reads only what this machine holds; it needs no management credential.
        Command::Credentials(CredentialsCommand::Export {
            service,
            env_file,
            dsn_file,
            reveal,
        }) => {
            let credential = services::credential_for(&client, &arguments.state, service)?;
            services::export(
                &client.origin,
                &credential,
                &services::CredentialOutputs { env_file, dsn_file },
                reveal,
                mode,
            )
        }
        Command::Login {
            workspace,
            project,
            permission,
            days,
            scope,
            wait,
            cancel,
        } => {
            if cancel {
                return login::cancel(&client, &arguments.state);
            }
            // A person at a terminal gets the browser opened and one command that finishes;
            // an agent relays the link and code, then runs `login --wait`.
            let interactive = mode == output::OutputMode::Human
                && std::io::stdin().is_terminal()
                && std::io::stderr().is_terminal();
            if !wait {
                // Without a named workspace the approver chooses it, so a code seen by someone
                // else could capture this machine into their workspace. Only a person who can
                // check the result at a terminal may ask that way.
                if workspace.is_none() && !interactive {
                    return Err(Error::LoginNeedsWorkspace);
                }
                let request = login::LoginRequest {
                    workspace,
                    project,
                    permission,
                    days,
                    scope,
                };
                let started = login::start(&client, &arguments.state, &request)?;
                if !interactive {
                    return Ok(started);
                }
                eprintln!("{}", started.render(mode));
                if let Some(url) = started.json.get("verification_uri").and_then(Value::as_str) {
                    open_browser(url);
                }
                eprintln!("Waiting for approval…");
            }
            let (pending, decided) = login::wait_for_decision(&client, &arguments.state)?;
            if pending.approver_chose_workspace() {
                if !interactive {
                    login::discard(&client, &arguments.state, &pending)?;
                    return Err(Error::LoginNeedsWorkspace);
                }
                let text = |key: &str| decided.get(key).and_then(Value::as_str);
                let reach = text("project_name").map_or_else(
                    || "the whole workspace".to_owned(),
                    |name| format!("project {name}"),
                );
                if !confirmed(&format!(
                    "Approved for workspace {} ({}), {reach}. Keep this login?",
                    text("workspace_name").unwrap_or("unnamed"),
                    text("workspace_id").unwrap_or("unknown")
                ))? {
                    login::discard(&client, &arguments.state, &pending)?;
                    return Err(Error::LoginDiscarded);
                }
            }
            login::keep(&client, &arguments.state, pending, &decided)
        }
        Command::Logout { .. } => {
            let found =
                applicable_login(&arguments.state, &client.origin, named)?.ok_or(Error::NoLogin)?;
            login::logout(&client, found)
        }
        Command::Whoami { .. } => {
            let held = management_token(
                agent_token_from_environment()?,
                &arguments.credential,
                &arguments.state,
                &client.origin,
                || applicable_login(&arguments.state, &client.origin, named),
            )?;
            let binding = bound_directory(&client.origin)?;
            let reached = client.call("/api/v1/auth/token", Some(&held.token), None)?;
            let field = |key: &str| reached.get(key).and_then(Value::as_str).map(str::to_owned);
            let reach = field("project_name").map_or_else(
                || "the whole workspace".to_owned(),
                |name| format!("project {name}"),
            );
            let source = held.source.describe();
            let from = match &held.source {
                CredentialSource::Environment => "LOGMAST_AGENT_TOKEN".to_owned(),
                CredentialSource::CredentialFile(path) => {
                    format!("the credential file {}", path.display())
                }
                CredentialSource::Login {
                    scope: Some(scope), ..
                } => format!("the login for {}", scope.display()),
                CredentialSource::Login { scope: None, .. } => "this machine's login".to_owned(),
                CredentialSource::Enrollment => "the enrollment on this machine".to_owned(),
            };
            let bound = binding.as_ref().map_or_else(
                || "This directory has no binding (`logmastctl setup`).".to_owned(),
                |binding| {
                    format!(
                        "This directory is bound to workspace {}{}.",
                        binding.workspace,
                        binding
                            .project
                            .map(|project| format!(", project {project}"))
                            .unwrap_or_default()
                    )
                },
            );
            let scopes = reached
                .get("scopes")
                .and_then(Value::as_array)
                .map(|scopes| {
                    scopes
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<&str>>()
                        .join(", ")
                })
                .unwrap_or_default();
            Ok(output::Report::with_text(
                json!({"version":1,"source":source,"binding":binding,"workspace_id":reached.get("workspace_id"),"workspace_name":reached.get("workspace_name"),
                    "project_id":reached.get("project_id"),"project_name":reached.get("project_name"),"scopes":reached.get("scopes"),
                    "expires_at":reached.get("expires_at"),"agent_name":reached.get("agent_name"),"secrets_printed":false}),
                format!(
                    "Using {from}: {} ({reach}), {scopes}, until {}.\n{bound}",
                    field("workspace_name").unwrap_or_default(),
                    field("expires_at").unwrap_or_default()
                ),
            ))
        }
        command => {
            let token = management_token(
                agent_token_from_environment()?,
                &arguments.credential,
                &arguments.state,
                &client.origin,
                || applicable_login(&arguments.state, &client.origin, named),
            )?
            .token;
            // The workspace a command names, else the directory's binding, else the only
            // workspace this credential reaches.
            let workspace_of = |explicit: Option<Uuid>| -> Result<Uuid, Error> {
                match explicit {
                    Some(workspace) => Ok(workspace),
                    None => match bound_directory(&client.origin)? {
                        Some(binding) => Ok(binding.workspace),
                        None => only_workspace(&client, &token),
                    },
                }
            };
            match command {
                Command::Workspaces => {
                    let workspaces = client.call("/api/v1/workspaces", Some(&token), None)?;
                    let text = workspace_lines(&workspaces);
                    Ok(output::Report::with_text(workspaces, text))
                }
                Command::Setup {
                    workspace,
                    project,
                    directory: chosen,
                } => setup(
                    &client,
                    &token,
                    &bindings,
                    workspace,
                    project,
                    match chosen {
                        Some(directory) => directory,
                        None => std::env::current_dir().map_err(Error::State)?,
                    },
                ),
                Command::Projects { workspace } => {
                    let workspace = workspace_of(workspace)?;
                    let status = client.call(
                        &format!("/api/v1/workspaces/{workspace}/enrollment"),
                        Some(&token),
                        None,
                    )?;
                    let text = project_lines(&status);
                    Ok(output::Report::with_text(
                        json!({"version":1,"workspace_id":workspace,"projects":field(&status, "projects"),"services":field(&status, "services")}),
                        text,
                    ))
                }
                Command::Status { workspace } => Ok(output::Report::json(client.call(
                    &format!("/api/v1/workspaces/{}/enrollment", workspace_of(workspace)?),
                    Some(&token),
                    None,
                )?)),
                Command::Claim { workspace, email } => Ok(output::Report::json(client.call(
                    &format!("/api/v1/workspaces/{workspace}/claim"),
                    Some(&token),
                    Some(json!({"email":email})),
                )?)),
                Command::Verify {
                    service: None,
                    run_id,
                } => {
                    let result = verify_run(&client, &arguments.state, &token, run_id)?;
                    let text = verification_text(&result);
                    Ok(output::Report::with_text(result, text))
                }
                Command::Verify {
                    service: Some(service),
                    run_id,
                } => {
                    let credential = services::credential_for(&client, &arguments.state, service)?;
                    let result =
                        services::verify(&client, &token, &arguments.state, &credential, run_id)?;
                    let text = verification_text(&result);
                    Ok(output::Report::with_text(result, text))
                }
                Command::Billing { workspace } => Ok(output::Report::json(client.call(
                    &format!("/api/v1/workspaces/{}/billing", workspace_of(workspace)?),
                    Some(&token),
                    None,
                )?)),
                Command::Agents { workspace } => Ok(output::Report::json(client.call(
                    &format!("/api/v1/workspaces/{}/agents", workspace_of(workspace)?),
                    Some(&token),
                    None,
                )?)),
                Command::Services(ServicesCommand::Create {
                    name,
                    project,
                    workspace,
                    env_file,
                    dsn_file,
                }) => {
                    let workspace = workspace_of(workspace)?;
                    let project = match project {
                        Some(project) => project,
                        // A binding's project belongs to its own workspace only.
                        None => bound_directory(&client.origin)?
                            .filter(|binding| binding.workspace == workspace)
                            .and_then(|binding| binding.project)
                            .ok_or(Error::NeedsProject)?,
                    };
                    services::create(
                        &client,
                        &token,
                        &arguments.state,
                        workspace,
                        project,
                        &name,
                        &services::CredentialOutputs { env_file, dsn_file },
                    )
                }
                Command::Credentials(CredentialsCommand::Rotate {
                    service,
                    workspace,
                    env_file,
                    dsn_file,
                }) => {
                    let saved_workspace =
                        services::load_credential(&arguments.state, &client.origin, service)?
                            .map(|credential| credential.workspace_id);
                    let workspace = workspace
                        .or(saved_workspace)
                        .map_or_else(|| workspace_of(None), Ok)?;
                    services::rotate(
                        &client,
                        &token,
                        &arguments.state,
                        workspace,
                        service,
                        &services::CredentialOutputs { env_file, dsn_file },
                    )
                }
                Command::Control {
                    workspace,
                    command_file,
                    output,
                } => {
                    let workspace = workspace_of(workspace)?;
                    let mut bytes = Vec::new();
                    File::open(command_file)
                        .map_err(Error::State)?
                        .take(32769)
                        .read_to_end(&mut bytes)
                        .map_err(Error::State)?;
                    if bytes.len() > 32768 {
                        return Err(Error::InvalidState);
                    }
                    let command: Value =
                        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidState)?;
                    // Reserve a safe output before the mutation. A transport
                    // failure leaves it empty: inspect workspace state before
                    // deciding whether the command should be submitted again.
                    let mut file = open_state(&output, true)?;
                    let result = client.call(
                        &format!("/api/v1/workspaces/{workspace}/control"),
                        Some(&token),
                        Some(command),
                    )?;
                    file.write_all(result.to_string().as_bytes())
                        .map_err(Error::State)?;
                    file.sync_all().map_err(Error::State)?;
                    Ok(output::Report::with_text(
                        json!({"version":1,"saved_to":output,"secrets_printed":false}),
                        format!(
                            "Done. The result is saved privately in {}.",
                            output.display()
                        ),
                    ))
                }
                Command::Catalog
                | Command::Schema
                | Command::Enroll { .. }
                | Command::Login { .. }
                | Command::Logout { .. }
                | Command::Whoami { .. }
                | Command::SentryDsn { .. }
                | Command::Credentials(CredentialsCommand::Export { .. }) => {
                    Err(Error::InvalidState)
                }
            }
        }
    }
}

/// The DSN for an ingest secret, derived as the server does: the first 32 hex
/// of HMAC-SHA256(secret, "logmast/sentry-dsn/1"). See docs/public/sentry.md.
fn sentry_dsn(origin: &str, ingest_secret: &str) -> Result<String, Error> {
    use hmac::{KeyInit, Mac};
    let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(ingest_secret.as_bytes())
        .map_err(|_| Error::InvalidState)?;
    mac.update(b"logmast/sentry-dsn/1");
    let mut key = hex::encode(mac.finalize().into_bytes());
    key.truncate(32);
    let (scheme, host) = origin.split_once("://").ok_or(Error::Origin)?;
    Ok(format!("{scheme}://{key}@{host}/1"))
}

/// What a command needs, for the console link a refusal points to.
fn needed_authority(command: &Command) -> NeededAuthority {
    match command {
        Command::Services(_)
        | Command::Credentials(CredentialsCommand::Rotate { .. })
        | Command::Control { .. } => NeededAuthority::Management,
        Command::Agents { .. } => NeededAuthority::Owner,
        Command::Catalog
        | Command::Schema
        | Command::Enroll { .. }
        | Command::Login { .. }
        | Command::Logout { .. }
        | Command::Whoami { .. }
        | Command::Workspaces
        | Command::Setup { .. }
        | Command::Projects { .. }
        | Command::Status { .. }
        | Command::Claim { .. }
        | Command::Verify { .. }
        | Command::Billing { .. }
        | Command::Credentials(CredentialsCommand::Export { .. })
        | Command::SentryDsn { .. } => NeededAuthority::Read,
    }
}

/// The workspace a command names, for the console link a refusal points to.
fn named_workspace(command: &Command) -> Option<Uuid> {
    match command {
        Command::Projects { workspace }
        | Command::Status { workspace }
        | Command::Billing { workspace }
        | Command::Agents { workspace }
        | Command::Login { workspace, .. }
        | Command::Logout { workspace }
        | Command::Whoami { workspace }
        | Command::Control { workspace, .. }
        | Command::Setup { workspace, .. }
        | Command::Services(ServicesCommand::Create { workspace, .. })
        | Command::Credentials(CredentialsCommand::Rotate { workspace, .. }) => *workspace,
        Command::Claim { workspace, .. } => Some(*workspace),
        Command::Catalog
        | Command::Schema
        | Command::Enroll { .. }
        | Command::Workspaces
        | Command::Verify { .. }
        | Command::Credentials(CredentialsCommand::Export { .. })
        | Command::SentryDsn { .. } => None,
    }
}

fn main() {
    let arguments = Arguments::parse();
    let mode = arguments.format.mode();
    let origin = Client::new(&arguments.url)
        .map(|client| client.origin)
        .unwrap_or_else(|_| arguments.url.trim_end_matches('/').to_owned());
    let needed = needed_authority(&arguments.command);
    let named = named_workspace(&arguments.command);
    match execute(arguments, mode) {
        Ok(report) => println!("{}", report.render(mode)),
        Err(error) => {
            // A hint may name the directory's workspace; failing to read bindings only makes it less specific.
            let workspace = named.or_else(|| {
                bound_directory(&origin)
                    .ok()
                    .flatten()
                    .map(|binding| binding.workspace)
            });
            let context = HintContext {
                origin,
                workspace,
                needed,
            };
            eprintln!(
                "{}",
                output::render_failure(
                    mode,
                    error.code(),
                    &error.to_string(),
                    &next_step(&error, &context)
                )
            );
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_sentry_dsn_matches_the_server_derivation() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(
            sentry_dsn("https://app.logmast.com", secret).is_ok_and(
                |dsn| dsn == "https://ea354b521ea7174e028622aed1474e10@app.logmast.com/1"
            )
        );
    }

    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_credential_reaching_one_workspace_supplies_it_and_several_need_a_choice()
    -> anyhow::Result<()> {
        use axum::{Json, Router, extract::State, http::HeaderMap, routing::get};
        let one = Uuid::now_v7();
        let other = Uuid::now_v7();
        // The fake answers by token: one workspace, two, or none.
        async fn workspaces(
            State((one, other)): State<(Uuid, Uuid)>,
            headers: HeaderMap,
        ) -> Json<Value> {
            let bearer = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            Json(match bearer {
                "Bearer single" => json!([{"id":one,"name":"Team","role":"owner"}]),
                "Bearer several" => json!([
                    {"id":one,"name":"Team","role":"owner"},
                    {"id":other,"name":"Other","role":"member"}
                ]),
                _ => json!([]),
            })
        }
        let router = Router::new()
            .route("/api/v1/workspaces", get(workspaces))
            .with_state((one, other));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client = Client::new(&origin)?;
        assert_eq!(only_workspace(&client, "single")?, one);
        assert!(matches!(
            only_workspace(&client, "several"),
            Err(Error::NeedsWorkspace)
        ));
        assert!(matches!(
            only_workspace(&client, "none"),
            Err(Error::NeedsWorkspace)
        ));
        server.abort();
        let _ = server.await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::expect_used)]
    async fn verification_resumes_uncertainty_then_creates_fresh_runs_and_labels_history()
    -> anyhow::Result<()> {
        use axum::{
            Json, Router,
            extract::State,
            routing::{get, post},
        };
        use std::sync::{Arc, Mutex};
        #[derive(Clone)]
        struct Evidence {
            workspace: Uuid,
            service: Uuid,
            group: Uuid,
            batches: Arc<Mutex<Vec<Value>>>,
        }
        async fn enroll(State(state): State<Evidence>) -> Json<Value> {
            Json(json!({"workspace_id":state.workspace,"service_id":state.service}))
        }
        async fn ingest(State(state): State<Evidence>, Json(batch): Json<Value>) -> Json<Value> {
            let mut batches = state.batches.lock().expect("fixture lock");
            batches.push(batch);
            // The first HTTP success is deliberately not a valid acknowledgment.
            if batches.len() == 1 {
                return Json(json!({}));
            }
            Json(json!({"receipt_id":Uuid::now_v7(),"new_events":1,"duplicates":0}))
        }
        async fn occurrence(State(state): State<Evidence>) -> Json<Value> {
            let batches = state.batches.lock().expect("fixture lock");
            let batch = batches.last().expect("submitted batch");
            let event = batch
                .get("events")
                .and_then(Value::as_array)
                .and_then(|events| events.first())
                .expect("event");
            Json(
                json!({"event":{"workspace_id":state.workspace,"service_id":state.service,"group_id":state.group,"occurrence_id":event.get("occurrence_id"),"payload":event}}),
            )
        }
        let evidence = Evidence {
            workspace: Uuid::now_v7(),
            service: Uuid::now_v7(),
            group: Uuid::now_v7(),
            batches: Arc::new(Mutex::new(Vec::new())),
        };
        let router=Router::new().route("/api/v1/enrollments",post(enroll)).route("/api/v1/ingest/batches",post(ingest))
            .route("/api/v1/workspaces/{workspace}/services/{service}/occurrences/{occurrence}",get(occurrence))
            .route("/api/v1/workspaces/{workspace}/receipts/{receipt}",get(||async { Json(json!({"processed_at":"2026-10-06T00:00:00Z","processing_gap":false,"notifications":[]})) }))
            .with_state(evidence.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let directory = std::env::temp_dir().join(format!("logmast-verify-{}", Uuid::now_v7()));
        let path = directory.join("session.json");
        let saved = prepare(
            &path,
            &origin,
            "Team".into(),
            "Project".into(),
            "Service".into(),
        )?;
        let client = Client::new(&origin)?;
        assert!(matches!(
            verify_run(&client, &path, &saved.bootstrap_secret, None),
            Err(Error::Verification)
        ));
        let pending = read_run(
            &path.with_extension("verification.json"),
            &saved.origin,
            saved.id,
        )?;
        assert!(pending.result.is_none());
        let first = verify_run(&client, &path, &saved.bootstrap_secret, None)?;
        assert_eq!(first.get("run_id"), Some(&json!(pending.run_id)));
        assert_eq!(first.get("historical"), Some(&json!(false)));
        let history = verify_run(
            &client,
            &path,
            &saved.bootstrap_secret,
            Some(pending.run_id),
        )?;
        assert_eq!(history.get("historical"), Some(&json!(true)));
        assert_eq!(history.get("observed_at"), first.get("observed_at"));
        assert_eq!(evidence.batches.lock().expect("fixture lock").len(), 2);
        let fresh = verify_run(&client, &path, &saved.bootstrap_secret, None)?;
        assert_ne!(fresh.get("run_id"), first.get("run_id"));
        assert_ne!(fresh.get("occurrence_id"), first.get("occurrence_id"));
        assert_eq!(
            fresh.pointer("/stages/application_instrumentation"),
            Some(&json!("not_proven"))
        );
        assert_eq!(
            fresh.pointer("/stages/inbox_delivery"),
            Some(&json!("not_proven"))
        );
        assert!(
            fresh
                .get("investigation_url")
                .and_then(Value::as_str)
                .is_some_and(|url| url.contains("occurrence=") && url.contains("group="))
        );
        {
            let batches = evidence.batches.lock().expect("fixture lock");
            let mut attempts = batches.iter();
            assert_eq!(attempts.next(), attempts.next());
        }
        // Files are private; the services directory beside them is private too.
        for entry in fs::read_dir(&directory)? {
            let metadata = entry?.metadata()?;
            let expected = if metadata.is_dir() { 0o700 } else { 0o600 };
            assert_eq!(metadata.permissions().mode() & 0o777, expected);
        }
        fs::remove_dir_all(directory)?;
        server.abort();
        let _ = server.await;
        Ok(())
    }

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
    fn delegated_credentials_are_origin_bound_and_strict() -> anyhow::Result<()> {
        let directory = std::env::temp_dir().join(format!("logmast-cli-{}", Uuid::now_v7()));
        let path = directory.join("agent.json");
        let origin = "https://app.logmast.com";
        let token = secret();
        let mut file = open_state(&path, true)?;
        serde_json::to_writer(
            &mut file,
            &json!({"version":1,"origin":origin,"token":token}),
        )?;
        file.sync_all()?;
        assert!(
            management_token(None, &Some(path.clone()), &path, origin, || Ok(None))?.token == token
        );
        assert!(
            management_token(
                None,
                &Some(path.clone()),
                &path,
                "https://other.example",
                || Ok(None)
            )
            .is_err()
        );
        for invalid in [
            json!({"version":2,"origin":origin,"token":token}),
            json!({"version":1,"origin":origin,"token":"not-a-credential"}),
            json!({"version":1,"origin":origin,"token":token,"extra":true}),
        ] {
            fs::write(&path, serde_json::to_vec(&invalid)?)?;
            assert!(
                management_token(None, &Some(path.clone()), &path, origin, || Ok(None)).is_err()
            );
        }
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
