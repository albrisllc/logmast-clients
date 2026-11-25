//! Device login: `logmastctl login` asks a person to approve this machine in the console with
//! a code shown here. The CLI generates its token itself and sends only its hash; the approved
//! token lands in a private file and is never printed. A login is machine-wide, or limited to a
//! directory tree with `--scope DIR`; commands use the login whose scope is nearest, preferring
//! the workspace (and project) the command or the directory's binding names.
//!
//! One request waits at a time per installation, so a person and an agent sharing the machine
//! never finish each other's logins: a second `login` is refused until the first is finished,
//! cancelled or expired.
use crate::{Client, Error, open_state, output::Report, secret};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Read,
    Manage,
}

impl Permission {
    fn as_str(self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Manage => "manage",
        }
    }
}

/// What a login asks for. Without a workspace the approver chooses one, which only a person at
/// a terminal may accept.
#[derive(Clone, PartialEq, Eq)]
pub struct LoginRequest {
    pub workspace: Option<Uuid>,
    pub project: Option<Uuid>,
    pub permission: Permission,
    pub days: u16,
    pub scope: Option<PathBuf>,
}

/// The workspace, and possibly project, a command works on: chosen by the command, or by the
/// directory's binding.
#[derive(Clone, Copy)]
pub struct Target {
    pub workspace: Uuid,
    pub project: Option<Uuid>,
}

// Intentionally no Debug or Serialize: it holds secrets.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingLogin {
    version: u32,
    origin: String,
    id: Uuid,
    device_code: String,
    token: String,
    workspace: Option<Uuid>,
    project: Option<Uuid>,
    permission: Permission,
    days: u16,
    scope: Option<PathBuf>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl PendingLogin {
    fn asks_for(&self, request: &LoginRequest) -> bool {
        self.workspace == request.workspace
            && self.project == request.project
            && self.permission == request.permission
            && self.days == request.days
            && self.scope == request.scope
    }
    fn expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at <= chrono::Utc::now())
    }
    /// Whether the approver chose the workspace because this login named none.
    pub fn approver_chose_workspace(&self) -> bool {
        self.workspace.is_none()
    }
}

// Intentionally no Debug or Serialize: it holds the token.
#[derive(Deserialize)]
pub struct LoginFile {
    version: u32,
    origin: String,
    token: String,
    pub workspace_id: Uuid,
    pub workspace_name: String,
    pub project_id: Option<Uuid>,
    pub scope: Option<PathBuf>,
}

impl LoginFile {
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// A login found for a directory, and where it is kept.
pub struct FoundLogin {
    pub path: PathBuf,
    pub login: LoginFile,
}

fn digest_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn host_of(origin: &str) -> String {
    origin
        .split_once("://")
        .map_or(origin, |(_, host)| host)
        .replace([':', '/'], "_")
}

fn logins_directory(state: &Path, origin: &str) -> Result<PathBuf, Error> {
    let root = state
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(Error::InvalidState)?;
    Ok(root.join("logins").join(host_of(origin)))
}

fn pending_path(state: &Path, origin: &str) -> Result<PathBuf, Error> {
    Ok(logins_directory(state, origin)?.join("pending.json"))
}

/// One file per workspace, project and scope, so two repositories on a machine can hold
/// different logins. The scope's digest only keeps names distinct.
fn login_path(
    state: &Path,
    origin: &str,
    workspace: Uuid,
    project: Option<Uuid>,
    scope: Option<&Path>,
) -> Result<PathBuf, Error> {
    let project_part = project
        .map(|project| format!(".{project}"))
        .unwrap_or_default();
    let scope_part = scope
        .map(|scope| format!(".{}", &digest_hex(&scope.to_string_lossy())[..16]))
        .unwrap_or_default();
    Ok(
        logins_directory(state, origin)?
            .join(format!("{workspace}{project_part}{scope_part}.json")),
    )
}

/// Writes a private file atomically. A temporary file left by a failure is removed, since it
/// may hold a token.
fn write_private(path: &Path, value: &Value) -> Result<(), Error> {
    let temporary = path.with_extension(format!("{}.tmp", Uuid::now_v7()));
    let written = (|| {
        let mut file = open_state(&temporary, true)?;
        file.write_all(value.to_string().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(Error::State)?;
        fs::rename(&temporary, path).map_err(Error::State)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(Error::State)?;
    }
    Ok(())
}

fn read_private(path: &Path) -> Result<String, Error> {
    let mut text = String::new();
    open_state(&path.to_path_buf(), false)?
        .read_to_string(&mut text)
        .map_err(Error::State)?;
    Ok(text)
}

fn exists(path: &Path) -> Result<bool, Error> {
    path.try_exists().map_err(Error::State)
}

/// The machine's name as the approval page shows it: what the server accepts, or "unknown".
fn hostname() -> String {
    let raw = fs::read_to_string("/etc/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default();
    let cleaned = reported_hostname(&raw);
    if cleaned.is_empty() {
        "unknown".into()
    } else {
        cleaned
    }
}

fn reported_hostname(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-'))
        .take(64)
        .collect()
}

/// Characters the server refuses in a reported directory: they hide or reorder text.
fn invisible(character: char) -> bool {
    character.is_control()
        || matches!(character,
            '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// A scope as the approval page shows it: without invisible characters, at most 200
/// characters, keeping the end, which names the repository.
fn reported_directory(scope: &str) -> String {
    let text: String = scope
        .chars()
        .filter(|character| !invisible(*character))
        .collect();
    let length = text.chars().count();
    if length <= 200 {
        return text;
    }
    let tail: String = text.chars().skip(length - 199).collect();
    format!("…{tail}")
}

fn read_pending(path: &Path, origin: &str) -> Result<PendingLogin, Error> {
    let pending: PendingLogin =
        serde_json::from_str(&read_private(path)?).map_err(|_| Error::InvalidState)?;
    if pending.version != 1 || pending.origin != origin {
        return Err(Error::InvalidState);
    }
    Ok(pending)
}

fn save_pending(path: &Path, pending: &PendingLogin) -> Result<(), Error> {
    if exists(path)? {
        fs::remove_file(path).map_err(Error::State)?;
    }
    write_private(
        path,
        &json!({"version":pending.version,"origin":pending.origin,"id":pending.id,"device_code":pending.device_code,"token":pending.token,
            "workspace":pending.workspace,"project":pending.project,"permission":pending.permission,"days":pending.days,"scope":pending.scope,
            "expires_at":pending.expires_at}),
    )
}

/// Removes the pending file if it still holds this request; another request's file is left.
fn forget_pending(path: &Path, origin: &str, pending: &PendingLogin) -> Result<(), Error> {
    if exists(path)? && read_pending(path, origin).is_ok_and(|current| current.id == pending.id) {
        fs::remove_file(path).map_err(Error::State)?;
    }
    Ok(())
}

fn poll(client: &Client, pending: &PendingLogin) -> Result<Value, Error> {
    client.call(
        &format!("/api/v1/device/authorizations/{}/poll", pending.id),
        None,
        Some(json!({"device_code":pending.device_code})),
    )
}

/// Drops a pending request. Its token is revoked in case someone approved it meanwhile; an
/// unapproved token is simply unknown to Logmast.
fn retire_pending(client: &Client, path: &Path, pending: &PendingLogin) -> Result<(), Error> {
    revoke_token(client, &pending.token)?;
    forget_pending(path, &client.origin, pending)
}

/// Cancels the request waiting on this machine, if any.
pub fn cancel(client: &Client, state: &Path) -> Result<Report, Error> {
    let path = pending_path(state, &client.origin)?;
    if !exists(&path)? {
        return Err(Error::NoPendingLogin);
    }
    let pending = read_pending(&path, &client.origin)?;
    retire_pending(client, &path, &pending)?;
    Ok(Report::with_text(
        json!({"version":1,"status":"cancelled"}),
        "The waiting login was cancelled.".into(),
    ))
}

/// Starts a device login, or repeats the one already waiting for the same request: the token
/// and request are saved before anything is sent, so a retry shows the same code. A different
/// request still waiting is refused, never replaced behind its owner's back.
pub fn start(client: &Client, state: &Path, request: &LoginRequest) -> Result<Report, Error> {
    let path = pending_path(state, &client.origin)?;
    let scope = match &request.scope {
        Some(scope) => {
            let canonical = scope.canonicalize().map_err(Error::State)?;
            canonical.to_str().ok_or(Error::ScopeNotUnicode)?;
            Some(canonical)
        }
        None => None,
    };
    let request = LoginRequest {
        scope,
        ..request.clone()
    };
    let resumable = if exists(&path)? {
        let pending = read_pending(&path, &client.origin)?;
        if pending.expired() {
            retire_pending(client, &path, &pending)?;
            None
        } else if pending.asks_for(&request) {
            Some(pending)
        } else {
            return Err(Error::PendingLoginExists);
        }
    } else {
        None
    };
    let pending = match resumable {
        Some(pending) => {
            // Approved meanwhile: the code is no longer useful to show.
            let polled = poll(client, &pending)?;
            if polled.get("status").and_then(Value::as_str) == Some("approved") {
                return Ok(Report::with_text(
                    json!({"version":1,"status":"approved","next":"run `logmastctl login --wait` to keep it"}),
                    "This login was already approved. Run `logmastctl login --wait` to keep it."
                        .into(),
                ));
            }
            pending
        }
        None => {
            let pending = PendingLogin {
                version: 1,
                origin: client.origin.clone(),
                id: Uuid::now_v7(),
                device_code: secret(),
                token: secret(),
                workspace: request.workspace,
                project: request.project,
                permission: request.permission,
                days: request.days,
                scope: request.scope.clone(),
                expires_at: None,
            };
            save_pending(&path, &pending)?;
            pending
        }
    };
    let directory = pending
        .scope
        .as_deref()
        .and_then(Path::to_str)
        .map(reported_directory);
    let started = client.call(
        "/api/v1/device/authorizations",
        None,
        Some(json!({"id":pending.id,"device_code_hash":digest_hex(&pending.device_code),"token_hash":digest_hex(&pending.token),
            "workspace":pending.workspace,"project":pending.project,"scope":pending.permission.as_str(),"days":pending.days,
            "client":{"version":env!("CARGO_PKG_VERSION"),"hostname":hostname(),"directory":directory}})),
    )?;
    let text_field = |field: &str| started.get(field).and_then(Value::as_str);
    let user_code = text_field("user_code")
        .ok_or(Error::UnreadableResponse)?
        .to_owned();
    let verification = text_field("verification_uri")
        .ok_or(Error::UnreadableResponse)?
        .to_owned();
    let expires_at: chrono::DateTime<chrono::Utc> = text_field("expires_at")
        .and_then(|text| text.parse().ok())
        .ok_or(Error::UnreadableResponse)?;
    save_pending(
        &path,
        &PendingLogin {
            expires_at: Some(expires_at),
            ..pending
        },
    )?;
    let shown = match (user_code.get(..4), user_code.get(4..)) {
        (Some(head), Some(tail)) => format!("{head}-{tail}"),
        _ => user_code,
    };
    Ok(Report::with_text(
        json!({"version":1,"status":"pending","verification_uri":verification,"user_code":shown,"expires_at":expires_at,
            "next":"after approval, run `logmastctl login --wait`"}),
        format!(
            "Open {verification} and enter the code {shown}.\nOnly approve it if you started this login. It expires in ten minutes."
        ),
    ))
}

/// Polls until the person decides or the request expires. Returns the request with the
/// approved grant, so keeping it never rereads a file another login may have replaced.
pub fn wait_for_decision(client: &Client, state: &Path) -> Result<(PendingLogin, Value), Error> {
    let path = pending_path(state, &client.origin)?;
    if !exists(&path)? {
        return Err(Error::NoPendingLogin);
    }
    let pending = read_pending(&path, &client.origin)?;
    let deadline = pending.expires_at.ok_or(Error::NoPendingLogin)?;
    let mut interval = Duration::from_secs(5);
    loop {
        let polled = poll(client, &pending)?;
        if let Some(seconds) = polled.get("interval").and_then(Value::as_u64) {
            interval = Duration::from_secs(seconds.clamp(1, 60));
        }
        match polled.get("status").and_then(Value::as_str) {
            Some("approved") => return Ok((pending, polled)),
            Some("denied") => {
                forget_pending(&path, &client.origin, &pending)?;
                return Err(Error::LoginDenied);
            }
            Some("expired") => {
                forget_pending(&path, &client.origin, &pending)?;
                return Err(Error::LoginExpired);
            }
            Some("pending" | "slow_down") => {}
            _ => return Err(Error::UnreadableResponse),
        }
        if chrono::Utc::now() >= deadline {
            forget_pending(&path, &client.origin, &pending)?;
            return Err(Error::LoginExpired);
        }
        std::thread::sleep(interval);
    }
}

/// Discards an approved login nobody accepted: its grant is revoked.
pub fn discard(client: &Client, state: &Path, pending: &PendingLogin) -> Result<(), Error> {
    retire_pending(client, &pending_path(state, &client.origin)?, pending)
}

/// Keeps an approved login. A grant for another workspace or project than was asked for is
/// revoked and never used. A login already kept for the same workspace, project and scope is
/// replaced, its grant revoked first, so repeated logins never pile up grants.
pub fn keep(
    client: &Client,
    state: &Path,
    pending: PendingLogin,
    decided: &Value,
) -> Result<Report, Error> {
    let path = pending_path(state, &client.origin)?;
    let identity = |field: &str| -> Option<Uuid> {
        decided
            .get(field)
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
    };
    let workspace = identity("workspace_id").ok_or(Error::UnreadableResponse)?;
    let project = identity("project_id");
    if pending.workspace.is_some_and(|asked| asked != workspace)
        || pending.project.is_some_and(|asked| Some(asked) != project)
    {
        retire_pending(client, &path, &pending)?;
        return Err(Error::LoginMismatch);
    }
    let target = login_path(
        state,
        &client.origin,
        workspace,
        project,
        pending.scope.as_deref(),
    )?;
    let replaced = exists(&target)?;
    if replaced {
        // An unreadable old file is removed all the same; its grant then lapses at expiry.
        if let Ok(previous) = serde_json::from_str::<LoginFile>(&read_private(&target)?) {
            revoke_token(client, &previous.token)?;
        }
        fs::remove_file(&target).map_err(Error::State)?;
    }
    let text = |field: &str| {
        decided
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let workspace_name = text("workspace_name").unwrap_or_default();
    let project_name = text("project_name");
    let expires_at = text("expires_at").unwrap_or_default();
    write_private(
        &target,
        &json!({"version":2,"origin":client.origin,"token":pending.token,"workspace_id":workspace,"workspace_name":workspace_name,
            "project_id":project,"project_name":project_name,"scope":pending.scope,"expires_at":expires_at}),
    )?;
    forget_pending(&path, &client.origin, &pending)?;
    let reach = project_name.as_ref().map_or_else(
        || "the whole workspace".to_owned(),
        |name| format!("project {name}"),
    );
    let used_in = pending.scope.as_ref().map_or_else(
        || "anywhere on this machine".to_owned(),
        |scope| format!("in {}", scope.display()),
    );
    Ok(Report::with_text(
        json!({"version":1,"status":"approved","workspace_id":workspace,"workspace_name":workspace_name,"project_id":project,
            "project_name":project_name,"scopes":decided.get("scopes"),"expires_at":expires_at,"scope":pending.scope,
            "replaced":replaced,"secrets_printed":false}),
        format!(
            "Logged in to {workspace_name} ({reach}), used {used_in}, until {expires_at}.{}",
            if replaced {
                " The previous login here was revoked."
            } else {
                ""
            }
        ),
    ))
}

fn revoke_token(client: &Client, token: &str) -> Result<(), Error> {
    match client.call("/api/v1/auth/token/revoke", Some(token), Some(json!({}))) {
        // Never approved, already revoked or expired: nothing is left to end.
        Ok(_) | Err(Error::Http(401)) => Ok(()),
        Err(error) => Err(error),
    }
}

fn read_logins(state: &Path, origin: &str) -> Result<Vec<FoundLogin>, Error> {
    let directory = logins_directory(state, origin)?;
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(Error::State(error)),
    };
    let mut logins = Vec::new();
    for entry in entries {
        let path = entry.map_err(Error::State)?.path();
        let is_login = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".json") && name != "pending.json");
        if !is_login {
            continue;
        }
        let login: LoginFile =
            serde_json::from_str(&read_private(&path)?).map_err(|_| Error::InvalidState)?;
        if login.version == 2 && login.origin == origin {
            logins.push(FoundLogin { path, login });
        }
    }
    Ok(logins)
}

/// The login for a command run in `directory`. Among logins whose scope contains it, those for
/// the target workspace win, then the target's project (or, with no project named, the
/// workspace-wide login), then the nearest scope. Several left are ambiguous.
pub fn resolve(
    state: &Path,
    origin: &str,
    directory: &Path,
    target: Option<Target>,
) -> Result<Option<FoundLogin>, Error> {
    let mut candidates: Vec<FoundLogin> = read_logins(state, origin)?
        .into_iter()
        .filter(|found| {
            found
                .login
                .scope
                .as_ref()
                .is_none_or(|scope| directory.starts_with(scope))
        })
        .collect();
    if let Some(target) = target {
        candidates.retain(|found| found.login.workspace_id == target.workspace);
        // The named project's login, else a workspace-wide one, which reaches every project.
        for preferred in [target.project, None] {
            if candidates
                .iter()
                .any(|found| found.login.project_id == preferred)
            {
                candidates.retain(|found| found.login.project_id == preferred);
                break;
            }
        }
    }
    let depth = |found: &FoundLogin| {
        found
            .login
            .scope
            .as_ref()
            .map_or(0, |scope| scope.components().count())
    };
    let nearest = candidates.iter().map(depth).max().unwrap_or(0);
    candidates.retain(|found| depth(found) == nearest);
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(candidates.pop()),
        _ => Err(Error::AmbiguousLogin),
    }
}

/// Whether this machine holds any login for the origin, so bindings are read only when needed.
pub fn any(state: &Path, origin: &str) -> Result<bool, Error> {
    Ok(!read_logins(state, origin)?.is_empty())
}

/// Ends a login: revoked at Logmast first, then its file removed.
pub fn logout(client: &Client, found: FoundLogin) -> Result<Report, Error> {
    revoke_token(client, &found.login.token)?;
    fs::remove_file(&found.path).map_err(Error::State)?;
    Ok(Report::with_text(
        json!({"version":1,"status":"logged_out","workspace_id":found.login.workspace_id,"project_id":found.login.project_id}),
        format!(
            "Logged out of {}; its access is revoked.",
            found.login.workspace_name
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_directories_keep_their_end_and_names_stay_distinct() -> Result<(), Error> {
        let long = format!("/{}/ledger", "a".repeat(300));
        let shown = reported_directory(&long);
        assert_eq!(shown.chars().count(), 200);
        assert!(shown.ends_with("/ledger"));
        assert_eq!(reported_directory("/src/\u{202E}gpj\u{200B}x"), "/src/gpjx");
        let state = PathBuf::from("/state/logmast/session.json");
        let workspace = Uuid::now_v7();
        let origin = "https://app.logmast.com";
        let machine = login_path(&state, origin, workspace, None, None)?;
        let scoped = login_path(
            &state,
            origin,
            workspace,
            None,
            Some(Path::new("/src/ledger")),
        )?;
        let other = login_path(
            &state,
            origin,
            workspace,
            None,
            Some(Path::new("/src/billing")),
        )?;
        assert!(machine != scoped && scoped != other);
        assert!(machine.starts_with("/state/logmast/logins/app.logmast.com"));
        Ok(())
    }

    #[test]
    fn hostnames_are_reduced_to_what_the_server_accepts() {
        assert_eq!(reported_hostname(" dev laptop\n<b>"), "devlaptopb");
        assert_eq!(reported_hostname(&"x".repeat(80)).len(), 64);
    }
}
