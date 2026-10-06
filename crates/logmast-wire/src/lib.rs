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
