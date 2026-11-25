//! Application-owned check results: heartbeats, job completions and
//! verifications sent to `/api/v1/ingest/check-ins`.
//!
//! Unlike error reports, a check-in is sent directly rather than queued. The
//! caller decides when the signal is true, usually at the end of a job, and
//! learns whether Logmast accepted it. Each check-in is built once and retried
//! byte-for-byte, so Logmast deduplicates a retry of a committed write instead
//! of rejecting changed content. Call this away from request handling; a send
//! takes at most [`SEND_BUDGET`].

use chrono::{DateTime, Utc};
use logmast_wire::{CheckAcceptance, CheckIn, CheckOutcome, MAX_CHECK_IN_BYTES};
use std::time::Duration;
use uuid::Uuid;

use crate::{Config, read_response};

/// Upper bound on one [`CheckIns::send`], retries included.
pub const SEND_BUDGET: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_ATTEMPTS: u32 = 4;
const PATH: &str = "/api/v1/ingest/check-ins";

#[derive(Debug, thiserror::Error)]
pub enum CheckInError {
    #[error("invalid Logmast check-in configuration")]
    Configuration,
    #[error("could not construct the check-in client")]
    Client(#[from] reqwest::Error),
    #[error("check-in exceeds {MAX_CHECK_IN_BYTES} bytes")]
    TooLarge,
    /// A permanent rejection. `code` is Logmast's stable error code when the
    /// response carried one. Retrying the same check-in cannot succeed.
    #[error("Logmast rejected the check-in (HTTP {status}, {code})")]
    Rejected { status: u16, code: String },
    /// Retries were exhausted on transport errors, throttling, server errors
    /// or invalid acknowledgments. The check-in may or may not have been
    /// stored; sending the identical check-in again later is safe.
    #[error("Logmast did not acknowledge the check-in after {attempts} attempt(s)")]
    Unacknowledged { attempts: u32 },
}

/// One check result, built once and sent unchanged on every retry.
#[derive(Clone, Debug)]
pub struct CheckInReport {
    wire: CheckIn,
}

impl CheckInReport {
    /// A result for `check_id` observed now. `run_id` must be stable for the
    /// run being reported: derive it with [`stable_run_id`] from the
    /// application's own durable run key, or persist a random one before
    /// sending.
    pub fn new(check_id: Uuid, run_id: Uuid, outcome: CheckOutcome) -> Self {
        Self::observed_at(check_id, run_id, outcome, Utc::now())
    }

    pub fn observed_at(
        check_id: Uuid,
        run_id: Uuid,
        outcome: CheckOutcome,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            wire: CheckIn {
                check_id,
                run_id,
                observed_at,
                outcome,
                release: None,
                duration_ms: None,
                correlation_id: None,
                occurrence_id: None,
            },
        }
    }

    /// How long the reported run took, capped at Logmast's seven-day maximum.
    pub fn duration(mut self, duration: Duration) -> Self {
        let millis = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
        self.wire.duration_ms = Some(millis.min(604_800_000));
        self
    }

    /// The application's own identifier for the run, at most 128 characters.
    pub fn correlation_id(mut self, correlation_id: &str) -> Self {
        self.wire.correlation_id = Some(correlation_id.chars().take(128).collect());
        self
    }

    /// The error occurrence that explains a failed result, if one was reported.
    pub fn occurrence(mut self, occurrence_id: Uuid) -> Self {
        self.wire.occurrence_id = Some(occurrence_id);
        self
    }

    pub fn as_wire(&self) -> &CheckIn {
        &self.wire
    }
}

/// A deterministic, non-nil run ID for `check_id` and an application key,
/// such as a database run ID. The same inputs always give the same ID, so a
/// process that retries after a restart reuses it instead of creating a new
/// run (Logmast's contract: "persist immutable content and non-nil IDs
/// before sending").
pub fn stable_run_id(check_id: Uuid, key: &str) -> Uuid {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"logmast check-in run v1\0");
    hasher.update(check_id.as_bytes());
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    for (byte, digest_byte) in bytes.iter_mut().zip(digest.iter()) {
        *byte = *digest_byte;
    }
    Uuid::new_v8(bytes)
}

/// Sends check-ins for the service whose ingest credential is in `Config`.
#[derive(Clone)]
pub struct CheckIns {
    client: reqwest::Client,
    url: reqwest::Url,
    token: String,
    release: Option<String>,
}

impl CheckIns {
    /// The check-in URL is derived from the configured ingest endpoint, on the
    /// same origin, so no second endpoint has to be configured.
    pub fn new(config: &Config) -> Result<Self, CheckInError> {
        let url = reqwest::Url::parse(&config.endpoint)
            .and_then(|endpoint| endpoint.join(PATH))
            .map_err(|_| CheckInError::Configuration)?;
        let client = reqwest::Client::builder()
            .timeout(ATTEMPT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            url,
            token: config.token.clone(),
            release: config.release.clone(),
        })
    }

    /// Send `report`, retrying transient failures within [`SEND_BUDGET`].
    ///
    /// `Ok` carries Logmast's receipt. `applied == false` means the result was
    /// stored but did not advance the check's state (a paused check, or a stale
    /// or reordered report); it never establishes current liveness.
    pub async fn send(&self, report: &CheckInReport) -> Result<CheckAcceptance, CheckInError> {
        let mut wire = report.wire.clone();
        if wire.release.is_none() {
            wire.release.clone_from(&self.release);
        }
        let body = serde_json::to_vec(&wire).map_err(|_| CheckInError::Configuration)?;
        if body.len() > MAX_CHECK_IN_BYTES {
            return Err(CheckInError::TooLarge);
        }
        let deadline = tokio::time::Instant::now() + SEND_BUDGET;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let response = self
                .client
                .post(self.url.clone())
                .bearer_auth(&self.token)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.clone())
                .send()
                .await;
            let mut retry_after = None;
            // Transport errors stay local and are never exported: the
            // response might carry provider detail.
            if let Ok(response) = response {
                let status = response.status();
                retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|text| text.parse::<u64>().ok())
                    .map(|seconds| Duration::from_secs(seconds.min(10)));
                if status.is_success() {
                    if let Some(acceptance) = read_response(response)
                        .await
                        .and_then(|body| serde_json::from_slice::<CheckAcceptance>(&body).ok())
                        .filter(|acceptance| !acceptance.receipt_id.is_nil())
                    {
                        return Ok(acceptance);
                    }
                    // An uncertain acknowledgment can follow a committed
                    // write; the identical body deduplicates on retry.
                } else if status.is_client_error() && !matches!(status.as_u16(), 408 | 429) {
                    let code = read_response(response)
                        .await
                        .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
                        .and_then(|problem| {
                            problem
                                .get("code")
                                .and_then(serde_json::Value::as_str)
                                .map(|code| code.chars().take(64).collect())
                        })
                        .unwrap_or_else(|| "unknown".to_string());
                    return Err(CheckInError::Rejected {
                        status: status.as_u16(),
                        code,
                    });
                }
            }
            let backoff = retry_after
                .unwrap_or_else(|| Duration::from_millis(500 * 2u64.pow(attempt.min(5))));
            if attempt >= MAX_ATTEMPTS || tokio::time::Instant::now() + backoff >= deadline {
                return Err(CheckInError::Unacknowledged { attempts: attempt });
            }
            tokio::time::sleep(backoff).await;
        }
    }
}
