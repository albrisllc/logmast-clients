//! Bounded, in-memory tracing export. Configure once in each executable.
//! Abrupt termination can lose queued reports. Exporter diagnostics stay local.

/// Own the report for an unexpected Tokio task termination. Await the handle
/// exactly here; callers must not report the returned JoinError again. Planned
/// shutdown aborts should be awaited directly, outside this failure boundary.
/// Panic-hook diagnostics remain local and the panic payload is never exported.
pub async fn supervise_task<T>(
    operation: &str,
    task: tokio::task::JoinHandle<T>,
) -> Result<T, tokio::task::JoinError> {
    match task.await {
        Ok(output) => Ok(output),
        Err(error) => {
            let (cause, message) = if error.is_panic() {
                ("task_panic", "supervised task panicked")
            } else {
                (
                    "task_cancelled",
                    "supervised task was unexpectedly cancelled",
                )
            };
            report_safe_failure(
                "Supervised task failed",
                "RUNTIME.TASK.FAILED",
                operation,
                cause,
                message,
                None,
            );
            Err(error)
        }
    }
}

/// Report a selected safe cause without traversing raw provider diagnostics.
pub fn report_safe_failure(
    message: &str,
    code: &str,
    operation: &str,
    cause_discriminator: &str,
    safe_cause: &str,
    correlation_id: Option<&str>,
) {
    let chain = vec![
        logmast_wire::Exception {
            kind: "operation".into(),
            message: message.into(),
        },
        logmast_wire::Exception {
            kind: cause_discriminator.into(),
            message: safe_cause.into(),
        },
    ];
    let Ok(exception_chain) = serde_json::to_string(&chain) else {
        return;
    };
    tracing::error!(target:"logmast::report",code,operation,cause_discriminator,exception_chain,correlation_id=correlation_id.unwrap_or(""),outcome="failed",message);
}
use chrono::Utc;
use logmast_wire::{Batch, ErrorResponse, Event, Exception, Outcome, Severity};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinHandle,
};
use tracing::{
    Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};
use uuid::Uuid;

const QUEUE_EVENTS: usize = 1024;
const QUEUE_BYTES: usize = 16 * 1024 * 1024;
const FLUSH_BYTES: usize = 512 * 1024;
const RETRY_LIFETIME: Duration = Duration::from_secs(15 * 60);

pub struct Config {
    pub endpoint: String,
    pub token: String,
    pub service_id: Uuid,
    pub environment: String,
    pub release: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReportingError {
    #[error("invalid or incomplete Logmast environment configuration")]
    Configuration,
    #[error("could not construct HTTP exporter")]
    Client(#[from] reqwest::Error),
    #[error("reporting task failed")]
    Task(#[from] tokio::task::JoinError),
}

impl Config {
    pub fn from_env() -> Result<Option<Self>, ReportingError> {
        let Ok(endpoint) = std::env::var("LOGMAST_ENDPOINT") else {
            return Ok(None);
        };
        let token = std::env::var("LOGMAST_TOKEN").map_err(|_| ReportingError::Configuration)?;
        let service_id = std::env::var("LOGMAST_SERVICE_ID")
            .map_err(|_| ReportingError::Configuration)?
            .parse()
            .map_err(|_| ReportingError::Configuration)?;
        let environment =
            std::env::var("LOGMAST_ENVIRONMENT").map_err(|_| ReportingError::Configuration)?;
        if token.is_empty() || environment.is_empty() || environment.len() > 80 {
            return Err(ReportingError::Configuration);
        }
        let url = reqwest::Url::parse(&endpoint).map_err(|_| ReportingError::Configuration)?;
        if url.scheme() != "https"
            && !(url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost")))
        {
            return Err(ReportingError::Configuration);
        }
        Ok(Some(Self {
            endpoint,
            token,
            service_id,
            environment,
            release: std::env::var("LOGMAST_RELEASE").ok(),
        }))
    }
}

#[derive(Debug)]
pub struct Counters {
    pub enqueued: AtomicU64,
    pub delivered: AtomicU64,
    pub dropped_overflow: AtomicU64,
    pub dropped_invalid: AtomicU64,
    pub dropped_expired: AtomicU64,
    pub dropped_shutdown: AtomicU64,
}

impl Counters {
    pub fn snapshot(&self) -> BTreeMap<String, u64> {
        [
            ("enqueued", &self.enqueued),
            ("delivered", &self.delivered),
            ("dropped_overflow", &self.dropped_overflow),
            ("dropped_invalid", &self.dropped_invalid),
            ("dropped_expired", &self.dropped_expired),
            ("dropped_shutdown", &self.dropped_shutdown),
        ]
        .into_iter()
        .map(|(name, counter)| (name.into(), counter.load(Ordering::Relaxed)))
        .collect()
    }
}

struct QueuedEvent {
    event: Event,
    enqueued_at: Instant,
    bytes: usize,
    _byte_permit: OwnedSemaphorePermit,
    _count_permit: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub struct ReportingLayer {
    sender: mpsc::Sender<QueuedEvent>,
    bytes: Arc<Semaphore>,
    count: Arc<Semaphore>,
    environment: String,
    release: Option<String>,
    pub counters: Arc<Counters>,
}

pub struct ReportingGuard {
    task: Option<JoinHandle<()>>,
    shutdown: watch::Sender<bool>,
    count: Arc<Semaphore>,
    pub counters: Arc<Counters>,
}

impl ReportingGuard {
    pub async fn shutdown(mut self) -> Result<BTreeMap<String, u64>, ReportingError> {
        let _ = self.shutdown.send(true);
        if let Some(mut task) = self.task.take() {
            if let Ok(result) = tokio::time::timeout(Duration::from_secs(10), &mut task).await {
                result?;
            } else {
                self.counters.dropped_shutdown.fetch_add(
                    (QUEUE_EVENTS - self.count.available_permits()) as u64,
                    Ordering::Relaxed,
                );
                task.abort();
                if let Err(error) = task.await
                    && !error.is_cancelled()
                {
                    return Err(error.into());
                }
            }
        }
        let counters = self.counters.snapshot();
        tracing::info!(target:"logmast_exporter",?counters,"Logmast exporter stopped");
        Ok(counters)
    }
}

impl Drop for ReportingGuard {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            self.counters.dropped_shutdown.fetch_add(
                (QUEUE_EVENTS - self.count.available_permits()) as u64,
                Ordering::Relaxed,
            );
            task.abort();
            tracing::warn!(target:"logmast_exporter","Logmast guard dropped without an awaited shutdown");
        }
    }
}

pub fn start(config: Config) -> Result<(ReportingLayer, ReportingGuard), ReportingError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let (sender, receiver) = mpsc::channel(QUEUE_EVENTS);
    let bytes = Arc::new(Semaphore::new(QUEUE_BYTES));
    let count = Arc::new(Semaphore::new(QUEUE_EVENTS));
    let counters = Arc::new(Counters {
        enqueued: AtomicU64::new(0),
        delivered: AtomicU64::new(0),
        dropped_overflow: AtomicU64::new(0),
        dropped_invalid: AtomicU64::new(0),
        dropped_expired: AtomicU64::new(0),
        dropped_shutdown: AtomicU64::new(0),
    });
    let layer = ReportingLayer {
        sender,
        bytes,
        count: count.clone(),
        environment: config.environment.clone(),
        release: config.release.clone(),
        counters: counters.clone(),
    };
    let (shutdown_sender, shutdown) = watch::channel(false);
    let task_counters = counters.clone();
    let task = tokio::spawn(async move {
        export(config, client, receiver, shutdown, task_counters).await;
    });
    Ok((
        layer,
        ReportingGuard {
            task: Some(task),
            shutdown: shutdown_sender,
            count,
            counters,
        },
    ))
}

#[derive(Clone, Debug)]
struct Fields {
    fields: BTreeMap<String, Value>,
}
impl Fields {
    /// A key already present may be replaced; the cap bounds distinct keys.
    fn accepts(&self, name: &str) -> bool {
        self.fields.len() < 32 || self.fields.contains_key(name)
    }
}
impl Visit for Fields {
    fn record_str(&mut self, field: &Field, text: &str) {
        if self.accepts(field.name()) {
            self.fields.insert(
                field.name().into(),
                Value::String(text.chars().take(32768).collect()),
            );
        }
    }
    fn record_debug(&mut self, field: &Field, input: &dyn std::fmt::Debug) {
        self.record_str(field, &format!("{input:?}"));
    }
    fn record_i64(&mut self, field: &Field, input: i64) {
        if self.accepts(field.name()) {
            self.fields.insert(field.name().into(), input.into());
        }
    }
    fn record_u64(&mut self, field: &Field, input: u64) {
        if self.accepts(field.name()) {
            self.fields.insert(field.name().into(), input.into());
        }
    }
    fn record_bool(&mut self, field: &Field, input: bool) {
        if self.accepts(field.name()) {
            self.fields.insert(field.name().into(), input.into());
        }
    }
}

fn take_text(fields: &mut BTreeMap<String, Value>, name: &str) -> Option<String> {
    match fields.remove(name) {
        Some(Value::String(text)) if !text.is_empty() => Some(text),
        _ => None,
    }
}

// OWNED-RUST-EXCEPTION: external-signature: LookupSpan requires its registry lifetime;
// no borrowed application data crosses this tracing adapter.
impl<Registry> Layer<Registry> for ReportingLayer
where
    Registry: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, context: Context<'_, Registry>) {
        let mut fields = Fields {
            fields: BTreeMap::new(),
        };
        attributes.record(&mut fields);
        if let Some(span) = context.span(id) {
            span.extensions_mut().insert(fields);
        }
    }
    fn on_record(&self, id: &Id, record: &Record<'_>, context: Context<'_, Registry>) {
        if let Some(span) = context.span(id)
            && let Some(fields) = span.extensions_mut().get_mut::<Fields>()
        {
            record.record(fields);
        }
    }
    fn on_event(&self, event: &tracing::Event<'_>, context: Context<'_, Registry>) {
        // Explicit target is the executable's opt-in reporting policy. Ordinary
        // logs, panic hooks and exporter errors never recursively enter export.
        if event.metadata().target() != "logmast::report" {
            return;
        }
        // The event's own fields decide classification; enclosing spans only
        // add context, innermost first, and never displace an event field.
        let mut collected = Fields {
            fields: BTreeMap::new(),
        };
        event.record(&mut collected);
        if let Some(scope) = context.event_scope(event) {
            for span in scope {
                if let Some(fields) = span.extensions().get::<Fields>() {
                    for (key, input) in &fields.fields {
                        if collected.fields.len() < 32 && !collected.fields.contains_key(key) {
                            collected.fields.insert(key.clone(), input.clone());
                        }
                    }
                }
            }
        }
        let mut fields = collected.fields;
        let message =
            take_text(&mut fields, "message").unwrap_or_else(|| event.metadata().name().to_owned());
        let severity = match *event.metadata().level() {
            tracing::Level::ERROR => Severity::Error,
            tracing::Level::WARN => Severity::Warning,
            tracing::Level::INFO => Severity::Info,
            tracing::Level::DEBUG | tracing::Level::TRACE => Severity::Debug,
        };
        let outcome = match take_text(&mut fields, "outcome").as_deref() {
            Some("rejected") => Some(Outcome::Rejected),
            Some("retrying") => Some(Outcome::Retrying),
            Some("recovered") => Some(Outcome::Recovered),
            Some("failed") => Some(Outcome::Failed),
            _ => None,
        };
        let exception_chain = take_text(&mut fields, "exception_chain")
            .and_then(|chain| serde_json::from_str::<Vec<Exception>>(&chain).ok())
            .unwrap_or_default();
        let correlation_ids = take_text(&mut fields, "correlation_id")
            .into_iter()
            .collect();
        let report = Event {
            occurrence_id: Uuid::now_v7(),
            timestamp: Utc::now(),
            environment: self.environment.clone(),
            severity,
            message,
            code: take_text(&mut fields, "code"),
            cause_discriminator: take_text(&mut fields, "cause_discriminator"),
            fingerprint: take_text(&mut fields, "fingerprint"),
            outcome,
            exception_chain,
            stack: take_text(&mut fields, "stack"),
            operation: take_text(&mut fields, "operation"),
            correlation_ids,
            release: self.release.clone(),
            breadcrumbs: Vec::new(),
            attributes: fields,
        };
        self.enqueue(report);
    }
}

impl ReportingLayer {
    pub fn enqueue(&self, event: Event) {
        let Ok(encoded) = serde_json::to_vec(&event) else {
            self.counters
                .dropped_invalid
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        if encoded.len() > logmast_wire::MAX_EVENT_BYTES {
            self.counters
                .dropped_invalid
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(byte_permit) = self
            .bytes
            .clone()
            .try_acquire_many_owned(encoded.len() as u32)
        else {
            self.counters
                .dropped_overflow
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Ok(count_permit) = self.count.clone().try_acquire_owned() else {
            self.counters
                .dropped_overflow
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let queued = QueuedEvent {
            event,
            enqueued_at: Instant::now(),
            bytes: encoded.len(),
            _byte_permit: byte_permit,
            _count_permit: count_permit,
        };
        if self.sender.try_send(queued).is_err() {
            self.counters
                .dropped_overflow
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.enqueued.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn export(
    config: Config,
    client: reqwest::Client,
    mut receiver: mpsc::Receiver<QueuedEvent>,
    mut shutdown: watch::Receiver<bool>,
    counters: Arc<Counters>,
) {
    let mut carry = None;
    loop {
        if *shutdown.borrow() {
            receiver.close();
        }
        let first = if let Some(event) = carry.take() {
            Some(event)
        } else {
            tokio::select! {event=receiver.recv()=>event,_=shutdown.changed()=>{receiver.close();receiver.recv().await}}
        };
        let Some(first) = first else {
            return;
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut bytes = first.bytes + 256;
        let mut pending = vec![first];
        while pending.len() < 100 {
            let next = if *shutdown.borrow() {
                receiver.try_recv().ok()
            } else {
                tokio::select! {event=receiver.recv()=>event,_=tokio::time::sleep_until(deadline)=>None,_=shutdown.changed()=>{receiver.close();receiver.try_recv().ok()}}
            };
            let Some(next) = next else {
                break;
            };
            if bytes + next.bytes + 1 > FLUSH_BYTES {
                carry = Some(next);
                break;
            }
            bytes += next.bytes + 1;
            pending.push(next);
        }
        deliver(&config, &client, pending, &counters).await;
    }
}

async fn deliver(
    config: &Config,
    client: &reqwest::Client,
    pending: Vec<QueuedEvent>,
    counters: &Counters,
) {
    let mut batches = vec![pending];
    while let Some(mut pending) = batches.pop() {
        let previous = pending.len();
        pending.retain(|event| event.enqueued_at.elapsed() < RETRY_LIFETIME);
        counters
            .dropped_expired
            .fetch_add((previous - pending.len()) as u64, Ordering::Relaxed);
        if pending.is_empty() {
            continue;
        }
        // Bounded copy: at most 100 events / 512 KiB for serialization. Queue
        // permits remain held while HTTP and every transport retry are in flight.
        let batch = Batch {
            batch_id: Uuid::now_v7(),
            service_id: config.service_id,
            events: pending.iter().map(|queued| queued.event.clone()).collect(),
        };
        let Ok(body) = serde_json::to_vec(&batch) else {
            counters
                .dropped_invalid
                .fetch_add(pending.len() as u64, Ordering::Relaxed);
            continue;
        };
        let mut attempt = 0u32;
        loop {
            if pending
                .iter()
                .any(|event| event.enqueued_at.elapsed() >= RETRY_LIFETIME)
            {
                counters
                    .dropped_expired
                    .fetch_add(pending.len() as u64, Ordering::Relaxed);
                break;
            }
            let response = client
                .post(&config.endpoint)
                .bearer_auth(&config.token)
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .await;
            let mut retry_after = None;
            if let Ok(response) = response {
                let status = response.status();
                if status.is_success() {
                    counters
                        .delivered
                        .fetch_add(pending.len() as u64, Ordering::Relaxed);
                    break;
                }
                retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|header| header.to_str().ok())
                    .and_then(|text| text.parse::<u64>().ok())
                    .map(|seconds| seconds.min(60));
                if matches!(status.as_u16(), 409 | 413 | 422) {
                    if status.as_u16() == 422
                        && let Ok(errors) = response.json::<ErrorResponse>().await
                    {
                        let invalid: std::collections::BTreeSet<usize> = errors
                            .errors
                            .iter()
                            .filter_map(|error| error.index)
                            .collect();
                        if !invalid.is_empty() {
                            let retained: Vec<_> = pending
                                .into_iter()
                                .enumerate()
                                .filter_map(|(index, event)| {
                                    if invalid.contains(&index) {
                                        counters.dropped_invalid.fetch_add(1, Ordering::Relaxed);
                                        None
                                    } else {
                                        Some(event)
                                    }
                                })
                                .collect();
                            if !retained.is_empty() {
                                batches.push(retained);
                            }
                            break;
                        }
                    }
                    if pending.len() > 1 {
                        let remainder = pending.split_off(pending.len() / 2);
                        batches.push(remainder);
                        batches.push(pending);
                    } else {
                        counters.dropped_invalid.fetch_add(1, Ordering::Relaxed);
                    }
                    break;
                }
                if status.is_client_error() && status.as_u16() != 429 {
                    counters
                        .dropped_invalid
                        .fetch_add(pending.len() as u64, Ordering::Relaxed);
                    tracing::warn!(target:"logmast_exporter",status=status.as_u16(),dropped=pending.len(),"Logmast rejected a batch permanently; check credentials and service configuration");
                    break;
                }
            }
            attempt = attempt.saturating_add(1);
            let ceiling = (1u64 << attempt.min(6)).min(60) * 1000;
            let jitter = rand::random::<u64>() % ceiling;
            tokio::time::sleep(Duration::from_millis(
                retry_after
                    .map(|seconds| seconds * 1000)
                    .unwrap_or(jitter.max(100)),
            ))
            .await;
        }
    }
}

/// Emit a terminal failure once. Every Display/source in `error` must already
/// be safe for remote persistence; wrap database/provider errors with safe
/// typed causes at the owning executable boundary. This does not capture a
/// failure-site backtrace. Include a captured stack explicitly when available.
pub fn report_error(
    error: &(dyn std::error::Error + 'static),
    code: Option<&str>,
    cause_discriminator: Option<&str>,
    operation: &str,
    correlation_id: Option<&str>,
) {
    let mut chain = Vec::new();
    let mut current = Some(error);
    while let Some(cause) = current {
        if chain.len() >= 16 {
            break;
        }
        chain.push(Exception {
            kind: if chain.is_empty() {
                "operation".into()
            } else {
                "cause".into()
            },
            message: cause.to_string().chars().take(1024).collect(),
        });
        current = cause.source();
    }
    let Ok(exception_chain) = serde_json::to_string(&chain) else {
        return;
    };
    tracing::error!(target:"logmast::report",code=code.unwrap_or(""),cause_discriminator=cause_discriminator.unwrap_or(""),operation,correlation_id=correlation_id.unwrap_or(""),outcome="failed",exception_chain,message=%error);
}
