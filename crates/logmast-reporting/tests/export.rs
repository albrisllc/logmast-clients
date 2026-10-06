#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use logmast_reporting::{Config, start};
use logmast_wire::{Batch, Event, Severity};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

fn event(message: &str) -> Event {
    Event {
        occurrence_id: uuid::Uuid::now_v7(),
        timestamp: chrono::Utc::now(),
        environment: "test".into(),
        severity: Severity::Error,
        message: message.into(),
        code: None,
        cause_discriminator: None,
        fingerprint: None,
        outcome: None,
        exception_chain: Vec::new(),
        stack: None,
        operation: None,
        correlation_ids: Vec::new(),
        release: None,
        breadcrumbs: Vec::new(),
        attributes: BTreeMap::new(),
    }
}

async fn reject_one(
    State(batches): State<Arc<Mutex<Vec<Batch>>>>,
    Json(batch): Json<Batch>,
) -> (StatusCode, Json<serde_json::Value>) {
    let invalid = batch
        .events
        .iter()
        .position(|event| event.message == "invalid");
    batches.lock().await.push(batch);
    if let Some(index) = invalid {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({"code":"INVALID_BATCH","message":"invalid","errors":[{"index":index,"field":"message","message":"fixture"}]}),
            ),
        );
    }
    (StatusCode::OK, Json(serde_json::json!({"ok":true})))
}

#[tokio::test]
async fn supervised_panic_reports_once_without_exporting_panic_payload() {
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::prelude::*;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let batches = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
        .route("/ingest", post(reject_one))
        .with_state(batches.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let (layer, guard) = start(Config {
        endpoint: format!("http://{address}/ingest"),
        token: "fixture".into(),
        service_id: uuid::Uuid::now_v7(),
        environment: "test".into(),
        release: None,
    })
    .unwrap();
    let subscriber = tracing_subscriber::registry().with(layer);
    async {
        let task = tokio::spawn(async { panic!("local-only panic payload") });
        assert!(
            logmast_reporting::supervise_task("contract.background", task)
                .await
                .is_err()
        );
    }
    .with_subscriber(subscriber)
    .await;
    let counters = guard.shutdown().await.unwrap();
    assert_eq!(counters["delivered"], 1);
    let batches = batches.lock().await;
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].events.len(), 1);
    assert!(
        !serde_json::to_string(&batches[0])
            .unwrap()
            .contains("local-only panic payload")
    );
    assert_eq!(
        batches[0].events[0].cause_discriminator.as_deref(),
        Some("task_panic")
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn permanent_reject_is_isolated_without_changing_valid_identity() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let batches = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
        .route("/ingest", post(reject_one))
        .with_state(batches.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let (layer, guard) = start(Config {
        endpoint: format!("http://{address}/ingest"),
        token: "fixture".into(),
        service_id: uuid::Uuid::now_v7(),
        environment: "test".into(),
        release: None,
    })
    .unwrap();
    let valid = event("valid");
    let original_id = valid.occurrence_id;
    layer.enqueue(event("invalid"));
    layer.enqueue(valid);
    let counters = guard.shutdown().await.unwrap();
    assert_eq!(counters["delivered"], 1);
    assert_eq!(counters["dropped_invalid"], 1);
    let batches = batches.lock().await;
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[1].events[0].occurrence_id, original_id);
    assert_ne!(batches[0].batch_id, batches[1].batch_id);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn queue_count_bytes_and_shutdown_are_bounded() {
    let (layer, guard) = start(Config {
        endpoint: "http://127.0.0.1:9/ingest".into(),
        token: "fixture".into(),
        service_id: uuid::Uuid::now_v7(),
        environment: "test".into(),
        release: None,
    })
    .unwrap();
    for _ in 0..1200 {
        layer.enqueue(event("small"));
    }
    assert_eq!(layer.counters.snapshot()["enqueued"], 1024);
    assert_eq!(layer.counters.snapshot()["dropped_overflow"], 176);
    let started = std::time::Instant::now();
    let counters = guard.shutdown().await.unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(11));
    assert_eq!(counters["dropped_shutdown"], 1024);
    let (layer, guard) = start(Config {
        endpoint: "http://127.0.0.1:9/ingest".into(),
        token: "fixture".into(),
        service_id: uuid::Uuid::now_v7(),
        environment: "test".into(),
        release: None,
    })
    .unwrap();
    for _ in 0..400 {
        layer.enqueue(event(&"x".repeat(60_000)));
    }
    let snapshot = layer.counters.snapshot();
    assert!(snapshot["enqueued"] < 300);
    assert!(snapshot["dropped_overflow"] > 100);
    drop(guard);
}

#[tokio::test]
async fn transient_failure_retries_identical_batch_and_occurrences() {
    async fn transient(
        State(batches): State<Arc<Mutex<Vec<Batch>>>>,
        Json(batch): Json<Batch>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let mut batches = batches.lock().await;
        batches.push(batch);
        (
            if batches.len() == 1 {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            },
            Json(serde_json::json!({})),
        )
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let batches = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
        .route("/ingest", post(transient))
        .with_state(batches.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let (layer, guard) = start(Config {
        endpoint: format!("http://{address}/ingest"),
        token: "fixture".into(),
        service_id: uuid::Uuid::now_v7(),
        environment: "test".into(),
        release: None,
    })
    .unwrap();
    layer.enqueue(event("retry"));
    let counters = guard.shutdown().await.unwrap();
    assert_eq!(counters["delivered"], 1);
    let batches = batches.lock().await;
    assert_eq!(
        serde_json::to_vec(&batches[0]).unwrap(),
        serde_json::to_vec(&batches[1]).unwrap()
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn event_fields_outrank_enclosing_span_context() {
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::prelude::*;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let batches = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
        .route("/ingest", post(reject_one))
        .with_state(batches.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let (layer, guard) = start(Config {
        endpoint: format!("http://{address}/ingest"),
        token: "fixture".into(),
        service_id: uuid::Uuid::now_v7(),
        environment: "test".into(),
        release: None,
    })
    .unwrap();
    let subscriber = tracing_subscriber::registry().with(layer);
    async {
        // Thirty-two span fields fill the attribute budget before the event
        // records its own classification.
        let context = tracing::info_span!(
            "context",
            f00 = 0, f01 = 1, f02 = 2, f03 = 3, f04 = 4, f05 = 5, f06 = 6, f07 = 7,
            f08 = 8, f09 = 9, f10 = 10, f11 = 11, f12 = 12, f13 = 13, f14 = 14, f15 = 15,
            f16 = 16, f17 = 17, f18 = 18, f19 = 19, f20 = 20, f21 = 21, f22 = 22, f23 = 23,
            f24 = 24, f25 = 25, f26 = 26, f27 = 27, f28 = 28, f29 = 29, f30 = 30, code = "span"
        );
        context.in_scope(|| {
            tracing::error!(target:"logmast::report",code="SAMPLE.RETRY.RECOVERED",outcome="recovered",operation="sample.retry","recovered after retry");
        });
    }
    .with_subscriber(subscriber)
    .await;
    let counters = guard.shutdown().await.unwrap();
    assert_eq!(counters["delivered"], 1);
    let batches = batches.lock().await;
    let exported = &batches[0].events[0];
    assert_eq!(exported.outcome, Some(logmast_wire::Outcome::Recovered));
    assert_eq!(exported.code.as_deref(), Some("SAMPLE.RETRY.RECOVERED"));
    assert_eq!(exported.operation.as_deref(), Some("sample.retry"));
    assert!(!exported.qualifies_for_alert());
    assert!(exported.attributes.len() <= 32);
    assert_eq!(exported.attributes.get("f00"), Some(&serde_json::json!(0)));
    server.abort();
    let _ = server.await;
}
