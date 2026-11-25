//! Services this machine connects: creating one, rotating its ingest credential,
//! exporting that credential to the application's secret store, and verifying
//! delivery with it. Ingest secrets are saved privately beside the CLI state and
//! are never printed, except by `--reveal` to a person at a terminal.
use crate::{
    Client, DeliveryTarget, Error, open_state, output::OutputMode, output::Report,
    persisted_verification, sentry_dsn,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{IsTerminal, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

// Intentionally no Debug or Serialize: it holds a secret. Persistence spells out its fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCredential {
    version: u32,
    origin: String,
    pub workspace_id: Uuid,
    pub service_id: Uuid,
    ingest_secret: String,
}

impl ServiceCredential {
    pub fn new(
        origin: String,
        workspace_id: Uuid,
        service_id: Uuid,
        ingest_secret: String,
    ) -> Self {
        Self {
            version: 1,
            origin,
            workspace_id,
            service_id,
            ingest_secret,
        }
    }
    pub fn ingest_secret(&self) -> &str {
        &self.ingest_secret
    }
}

/// Where the outputs of a create, rotate or export go. Every one is optional.
pub struct CredentialOutputs {
    pub env_file: Option<PathBuf>,
    pub dsn_file: Option<PathBuf>,
}

impl CredentialOutputs {
    fn paths(&self) -> Vec<&PathBuf> {
        [&self.env_file, &self.dsn_file]
            .into_iter()
            .flatten()
            .collect()
    }
}

fn services_directory(state: &Path) -> Result<PathBuf, Error> {
    let root = state
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(Error::InvalidState)?;
    Ok(root.join("services"))
}

fn credential_path(state: &Path, service: Uuid) -> Result<PathBuf, Error> {
    Ok(services_directory(state)?.join(format!("{service}.json")))
}

pub fn load_credential(
    state: &Path,
    origin: &str,
    service: Uuid,
) -> Result<Option<ServiceCredential>, Error> {
    let path = credential_path(state, service)?;
    if !path.try_exists().map_err(Error::State)? {
        return Ok(None);
    }
    let mut text = String::new();
    open_state(&path, false)?
        .read_to_string(&mut text)
        .map_err(Error::State)?;
    let credential: ServiceCredential =
        serde_json::from_str(&text).map_err(|_| Error::InvalidState)?;
    if credential.version != 1 || credential.origin != origin || credential.service_id != service {
        return Err(Error::InvalidState);
    }
    Ok(Some(credential))
}

/// Saves (or, after a rotation, replaces) a service's credential: a new private file
/// renamed over the old one, so a crash leaves either the old or the new secret.
pub fn save_credential(state: &Path, credential: &ServiceCredential) -> Result<(), Error> {
    let path = credential_path(state, credential.service_id)?;
    let temporary = path.with_extension(format!("{}.tmp", Uuid::now_v7()));
    let mut file = open_state(&temporary, true)?;
    let persisted = json!({"version":1,"origin":credential.origin,"workspace_id":credential.workspace_id,"service_id":credential.service_id,"ingest_secret":credential.ingest_secret});
    file.write_all(persisted.to_string().as_bytes())
        .map_err(Error::State)?;
    file.sync_all().map_err(Error::State)?;
    fs::rename(&temporary, &path).map_err(Error::State)?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(Error::State)?;
    }
    Ok(())
}

fn environment_block(origin: &str, credential: &ServiceCredential) -> String {
    format!(
        "LOGMAST_ENDPOINT={origin}/api/v1/ingest/batches\nLOGMAST_SERVICE_ID={}\nLOGMAST_TOKEN={}\nLOGMAST_ENVIRONMENT=production\n",
        credential.service_id, credential.ingest_secret
    )
}

fn output_parent(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Whether a secret file can be created at `path`, checked before anything changes on the
/// server. The directory may be a repository shared with a group, but not writable by
/// everyone; the file must not exist yet.
fn check_output_target(path: &Path) -> Result<(), Error> {
    let parent = output_parent(path);
    let metadata = fs::metadata(&parent).map_err(Error::State)?;
    if !metadata.is_dir() || metadata.mode() & 0o002 != 0 {
        return Err(Error::UnsafeOutputDirectory(parent));
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(Error::OutputExists(path.to_path_buf()));
    }
    Ok(())
}

pub fn check_outputs(outputs: &CredentialOutputs) -> Result<(), Error> {
    for path in outputs.paths() {
        check_output_target(path)?;
    }
    Ok(())
}

/// A new file only the user can read; an existing file or link is never overwritten or followed.
fn write_secret_file(path: &Path, contents: &str) -> Result<(), Error> {
    check_output_target(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => Error::OutputExists(path.to_path_buf()),
            _ => Error::State(error),
        })?;
    file.write_all(contents.as_bytes()).map_err(Error::State)?;
    file.sync_all().map_err(Error::State)
}

fn write_outputs(
    origin: &str,
    credential: &ServiceCredential,
    outputs: &CredentialOutputs,
) -> Result<(), Error> {
    if let Some(path) = &outputs.env_file {
        write_secret_file(path, &environment_block(origin, credential))?;
    }
    if let Some(path) = &outputs.dsn_file {
        write_secret_file(
            path,
            &format!(
                "SENTRY_DSN={}\n",
                sentry_dsn(origin, &credential.ingest_secret)?
            ),
        )?;
    }
    Ok(())
}

fn written(outputs: &CredentialOutputs) -> String {
    let files: Vec<String> = outputs
        .paths()
        .into_iter()
        .map(|path| path.display().to_string())
        .collect();
    if files.is_empty() {
        String::new()
    } else {
        format!(
            " Written to {} (mode 600); keep it out of version control.",
            files.join(" and ")
        )
    }
}

#[derive(Deserialize)]
struct IssuedCredential {
    service_id: Uuid,
    ingest_token: String,
}

/// What became of the outputs after the server's change, which has already happened.
enum OutputsOutcome {
    Written,
    Failed(String),
}

/// Saves an issued credential first: the server has already created it, and this file is
/// the only copy. Outputs come after, and their failure never hides the change.
fn keep_issued(
    state: &Path,
    client: &Client,
    workspace: Uuid,
    response: Value,
    outputs: &CredentialOutputs,
) -> Result<(ServiceCredential, OutputsOutcome), Error> {
    let issued: IssuedCredential =
        serde_json::from_value(response).map_err(|_| Error::UnreadableResponse)?;
    let credential = ServiceCredential::new(
        client.origin.clone(),
        workspace,
        issued.service_id,
        issued.ingest_token,
    );
    save_credential(state, &credential).map_err(|error| Error::CredentialNotSaved {
        service: credential.service_id,
        cause: Box::new(error),
    })?;
    let outcome = match write_outputs(&client.origin, &credential, outputs) {
        Ok(()) => OutputsOutcome::Written,
        Err(error) => OutputsOutcome::Failed(error.to_string()),
    };
    Ok((credential, outcome))
}

fn outputs_report(
    service: Uuid,
    outcome: &OutputsOutcome,
    outputs: &CredentialOutputs,
) -> (Value, String, String) {
    match outcome {
        OutputsOutcome::Written => (
            json!(true),
            written(outputs),
            format!("logmastctl verify --service {service}"),
        ),
        OutputsOutcome::Failed(reason) => (
            json!(false),
            format!(" The credential is saved here, but writing your files failed ({reason})."),
            format!("logmastctl credentials export --service {service} --env-file NEW_PATH"),
        ),
    }
}

/// Mutations are not idempotent: after an uncertain outcome the next step must say how to
/// reconcile, not invite a blind repeat.
fn uncertain(error: Error, reconcile: Error) -> Error {
    match error {
        Error::Transport(_) => reconcile,
        Error::Http(status) if status >= 500 => reconcile,
        other => other,
    }
}

pub fn create(
    client: &Client,
    token: &str,
    state: &Path,
    workspace: Uuid,
    project: Uuid,
    name: &str,
    outputs: &CredentialOutputs,
) -> Result<Report, Error> {
    check_outputs(outputs)?;
    let response = client
        .call(
            &format!("/api/v1/workspaces/{workspace}/control"),
            Some(token),
            Some(json!({"action":"create_service","project_id":project,"name":name})),
        )
        .map_err(|error| {
            uncertain(
                error,
                Error::UncertainCreate {
                    name: name.to_owned(),
                },
            )
        })?;
    let (credential, outcome) = keep_issued(state, client, workspace, response, outputs)?;
    let service = credential.service_id;
    let (outputs_written, files, next) = outputs_report(service, &outcome, outputs);
    Ok(Report::with_text(
        json!({"version":1,"workspace_id":workspace,"project_id":project,"service_id":service,"name":name,"credential_saved":true,"outputs_written":outputs_written,"env_file":outputs.env_file,"dsn_file":outputs.dsn_file,"secrets_printed":false,"next":next}),
        format!(
            "Created service {name} ({service}). Its ingest credential is saved privately on this machine.{files}\nnext: {next}"
        ),
    ))
}

pub fn rotate(
    client: &Client,
    token: &str,
    state: &Path,
    workspace: Uuid,
    service: Uuid,
    outputs: &CredentialOutputs,
) -> Result<Report, Error> {
    check_outputs(outputs)?;
    let response = client
        .call(
            &format!("/api/v1/workspaces/{workspace}/control"),
            Some(token),
            Some(json!({"action":"rotate_credential","service_id":service})),
        )
        .map_err(|error| uncertain(error, Error::UncertainRotate { service }))?;
    let (_, outcome) = keep_issued(state, client, workspace, response, outputs)?;
    let (outputs_written, files, next) = outputs_report(service, &outcome, outputs);
    Ok(Report::with_text(
        json!({"version":1,"workspace_id":workspace,"service_id":service,"credential_saved":true,"previous_credentials":"revoked","outputs_written":outputs_written,"env_file":outputs.env_file,"dsn_file":outputs.dsn_file,"secrets_printed":false,"next":next}),
        format!(
            "Rotated the credential of service {service}. Earlier credentials stopped working; update every producer.{files}\nnext: {next}"
        ),
    ))
}

/// Exports a saved credential to files, or shows it to a person at a terminal.
pub fn export(
    origin: &str,
    credential: &ServiceCredential,
    outputs: &CredentialOutputs,
    reveal: bool,
    mode: OutputMode,
) -> Result<Report, Error> {
    if reveal {
        if mode != OutputMode::Human || !std::io::stdout().is_terminal() {
            return Err(Error::RevealNeedsTerminal);
        }
        // Printed only to a terminal, where a person reads it; never in JSON.
        return Ok(Report::with_text(
            json!({"version":1,"service_id":credential.service_id,"secrets_printed":true}),
            environment_block(origin, credential),
        ));
    }
    if outputs.paths().is_empty() {
        return Err(Error::NoExportTarget);
    }
    check_outputs(outputs)?;
    write_outputs(origin, credential, outputs)?;
    Ok(Report::with_text(
        json!({"version":1,"service_id":credential.service_id,"env_file":outputs.env_file,"dsn_file":outputs.dsn_file,"secrets_printed":false}),
        format!(
            "Exported the credential of service {}.{}",
            credential.service_id,
            written(outputs)
        ),
    ))
}

/// Verifies delivery for a service whose credential this machine holds, reading the
/// evidence back with the management credential. Runs resume and replay like enrollment's.
pub fn verify(
    client: &Client,
    token: &str,
    state: &Path,
    credential: &ServiceCredential,
    requested: Option<Uuid>,
) -> Result<Value, Error> {
    let base = services_directory(state)?.join(format!("{}.json", credential.service_id));
    let target = DeliveryTarget {
        workspace: credential.workspace_id,
        service: credential.service_id,
        ingest_secret: &credential.ingest_secret,
    };
    persisted_verification(
        &base,
        &client.origin,
        credential.service_id,
        requested,
        |run| client.verify_delivery(&target, run, token),
    )
}

/// The credential this machine holds for the service: one it created, rotated or enrolled.
/// Only local files are read; nothing is sent.
pub fn credential_for(
    client: &Client,
    state: &Path,
    service: Uuid,
) -> Result<ServiceCredential, Error> {
    load_credential(state, &client.origin, service)?.ok_or(Error::NoSavedCredential(service))
}
