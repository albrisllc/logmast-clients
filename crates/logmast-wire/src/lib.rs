//! Version one JSON ingestion contract shared by the server and Rust producer.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

pub const MAX_BATCH_EVENTS: usize = 100;
pub const MAX_REQUEST_BYTES: usize = 1_048_576;
pub const MAX_EVENT_BYTES: usize = 65_536;
pub const RETENTION_DAYS: i64 = 14;
pub const MAX_CHECK_IN_BYTES: usize = 8192;
pub const DEFAULT_CHECK_LIMIT: i32 = 20;
pub const DEFAULT_CHECK_IN_LIMIT: i64 = 50000;
pub const MIN_CHECK_INTERVAL: i64 = 60;
pub const MAX_CHECK_INTERVAL: i64 = 604800;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    Heartbeat,
    Job,
    Verification,
}

impl CheckKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Heartbeat => "heartbeat",
            Self::Job => "job",
            Self::Verification => "verification",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckDefinition {
    pub id: Uuid,
    pub service_id: Uuid,
    pub name: String,
    pub environment: String,
    pub kind: CheckKind,
    pub interval_seconds: Option<i64>,
    pub grace_seconds: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Pass,
    Fail,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckIn {
    pub check_id: Uuid,
    pub run_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub outcome: CheckOutcome,
    pub release: Option<String>,
    pub duration_ms: Option<i64>,
    pub correlation_id: Option<String>,
    pub occurrence_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckAcceptance {
    pub receipt_id: Uuid,
    pub duplicate: bool,
    pub applied: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckStatus {
    pub definition: CheckDefinition,
    pub revision: i64,
    pub state: String,
    pub due_at: Option<DateTime<Utc>>,
    pub last_received_at: Option<DateTime<Utc>>,
    pub last_pass_at: Option<DateTime<Utc>>,
    pub last_result: Option<CheckIn>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Debug,
    Info,
    Warning,
    Error,
    Fatal,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Rejected,
    Retrying,
    Recovered,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub occurrence_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub environment: String,
    pub severity: Severity,
    pub message: String,
    pub code: Option<String>,
    pub cause_discriminator: Option<String>,
    pub fingerprint: Option<String>,
    pub outcome: Option<Outcome>,
    #[serde(default)]
    pub exception_chain: Vec<Exception>,
    pub stack: Option<String>,
    pub operation: Option<String>,
    #[serde(default)]
    pub correlation_ids: Vec<String>,
    pub release: Option<String>,
    #[serde(default)]
    pub breadcrumbs: Vec<Value>,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
}

impl Event {
    pub fn qualifies_for_alert(&self) -> bool {
        matches!(self.severity, Severity::Error | Severity::Fatal)
            && !matches!(
                self.outcome,
                Some(Outcome::Rejected | Outcome::Retrying | Outcome::Recovered)
            )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub batch_id: Uuid,
    pub service_id: Uuid,
    pub events: Vec<Event>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acceptance {
    pub receipt_id: Uuid,
    pub new_events: usize,
    pub duplicates: usize,
    /// How many new events kept their payload; the rest were counted only.
    /// Absent from servers older than usage billing, where all were stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_events: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldError {
    pub index: Option<usize>,
    pub field: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
    pub errors: Vec<FieldError>,
}
