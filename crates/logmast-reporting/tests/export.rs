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

fn acceptance(batch: &Batch) -> serde_json::Value {
    serde_json::json!({
        "receipt_id": uuid::Uuid::now_v7(),
        "new_events": batch.events.len(),
        "duplicates": 0,
    })
}

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

#[tokio::test]
async fn advertised_gzip_batches_and_preserves_wire_bytes_across_retry() {
    compression_fixture(false).await;
}

#[tokio::test]
async fn unsupported_gzip_falls_back_without_changing_logical_identity() {
    compression_fixture(true).await;
}

async fn compression_fixture(fallback: bool) {
    use axum::{body::Bytes, http::HeaderMap, routing::get};
    use std::io::Read;
    type Attempts = Arc<Mutex<Vec<(String, Vec<u8>, Batch)>>>;
    #[derive(Clone)]
    struct Capture {
        fallback: bool,
        calls: Attempts,
    }
    async fn collect(
        State(capture): State<Capture>,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let encoding = headers
            .get("content-encoding")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let mut decoded = Vec::new();
        if encoding == "gzip" {
            flate2::read::GzDecoder::new(body.as_ref())
                .read_to_end(&mut decoded)
                .unwrap();
        } else {
            decoded = body.to_vec();
        }
        let batch: Batch = serde_json::from_slice(&decoded).unwrap();
        let accepted = acceptance(&batch);
        let mut calls = capture.calls.lock().await;
        calls.push((encoding, body.to_vec(), batch));
        let status = if calls.len() == 1 {
            if capture.fallback {
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        } else {
            StatusCode::OK
        };
        (status, Json(accepted))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let catalog_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reads = catalog_reads.clone();
    let router = Router::new()
        .route("/ingest", post(collect))
        .route(
            "/api/v1/catalog",
            get(move |headers: HeaderMap| {
                assert!(!headers.contains_key("authorization"));
                reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async {
                    Json(serde_json::json!({"ingestion":{"content_encodings":["identity","gzip"]}}))
                }
            }),
        )
        .with_state(Capture {
            fallback,
            calls: calls.clone(),
        });
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let (layer, guard) = start(Config {
        endpoint: format!("http://{address}/ingest"),
        token: "fixture".into(),
        service_id: uuid::Uuid::now_v7(),
        environment: "test".into(),
        release: None,
    })
    .unwrap();
    let reports: Vec<_> = (0..10)
        .map(|_| event(&"repeated safe diagnostic ".repeat(120)))
        .collect();
    let ids: Vec<_> = reports.iter().map(|report| report.occurrence_id).collect();
    for report in reports {
        layer.enqueue(report);
    }
    assert_eq!(guard.shutdown().await.unwrap()["delivered"], 10);
    let calls = calls.lock().await;
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, "gzip");
    assert_eq!(
        calls[0]
            .2
            .events
            .iter()
            .map(|event| event.occurrence_id)
            .collect::<Vec<_>>(),
        ids
    );
    assert!(calls[0].1.len() < serde_json::to_vec(&calls[0].2).unwrap().len() / 2);
    assert_eq!(
        serde_json::to_vec(&calls[0].2).unwrap(),
        serde_json::to_vec(&calls[1].2).unwrap()
    );
    if fallback {
        assert_eq!(calls[1].0, "identity");
    } else {
        assert_eq!(calls[0].1, calls[1].1);
    }
    assert_eq!(catalog_reads.load(std::sync::atomic::Ordering::Relaxed), 1);
    server.abort();
    let _ = server.await;
}

async fn reject_one(
    State(batches): State<Arc<Mutex<Vec<Batch>>>>,
    Json(batch): Json<Batch>,
) -> (StatusCode, Json<serde_json::Value>) {
    let invalid = batch
        .events
        .iter()
        .position(|event| event.message == "invalid");
    let accepted = acceptance(&batch);
    batches.lock().await.push(batch);
    if let Some(index) = invalid {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({"code":"INVALID_BATCH","message":"invalid","errors":[{"index":index,"field":"message","message":"fixture"}]}),
            ),
        );
    }
    (StatusCode::OK, Json(accepted))
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
        let accepted = acceptance(&batch);
        batches.push(batch);
        (
            if batches.len() == 1 {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            },
            Json(accepted),
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

struct ResponseFixture {
    status: StatusCode,
    body: String,
    stall_after_body: bool,
    batches: Mutex<Vec<Batch>>,
}

async fn fixture_response(
    State(fixture): State<Arc<ResponseFixture>>,
    Json(batch): Json<Batch>,
) -> axum::response::Response {
    use axum::{body::Body, response::IntoResponse};
    use futures_util::StreamExt;
    let accepted = acceptance(&batch);
    let mut batches = fixture.batches.lock().await;
    batches.push(batch);
    if batches.len() > 1 {
        return Json(accepted).into_response();
    }
    let body = if fixture.stall_after_body {
        // No Content-Length and no EOF: the exporter must stop reading at its
        // byte limit, without waiting for the eight-second request timeout.
        let chunks = futures_util::stream::iter([Ok::<_, std::io::Error>(fixture.body.clone())]);
        Body::from_stream(chunks.chain(futures_util::stream::pending()))
    } else {
        Body::from(fixture.body.clone())
    };
    (fixture.status, body).into_response()
}

async fn run_response_fixture(
    status: StatusCode,
    body: String,
    stall_after_body: bool,
) -> Vec<Batch> {
    let fixture = Arc::new(ResponseFixture {
        status,
        body,
        stall_after_body,
        batches: Mutex::new(Vec::new()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route("/ingest", post(fixture_response))
        .with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let (layer, guard) = start(Config {
        endpoint: format!("http://{address}/ingest"),
        token: "private-fixture-token".into(),
        service_id: uuid::Uuid::now_v7(),
        environment: "test".into(),
        release: None,
    })
    .unwrap();
    layer.enqueue(event("first"));
    layer.enqueue(event("second"));
    let counters = tokio::time::timeout(std::time::Duration::from_secs(4), guard.shutdown())
        .await
        .expect("bounded response reader did not finish promptly")
        .unwrap();
    assert_eq!(counters["delivered"], 2);
    assert_eq!(counters["dropped_invalid"], 0);
    assert_eq!(counters["dropped_shutdown"], 0);
    server.abort();
    let _ = server.await;
    fixture.batches.lock().await.clone()
}

#[tokio::test]
async fn valid_receipts_accept_new_duplicate_and_mixed_counts() {
    for (new_events, duplicates) in [(2, 0), (0, 2), (1, 1)] {
        let body = serde_json::json!({
            "receipt_id": uuid::Uuid::now_v7(),
            "new_events": new_events,
            "duplicates": duplicates,
        });
        let batches = run_response_fixture(StatusCode::OK, body.to_string(), false).await;
        assert_eq!(batches.len(), 1);
    }
}

#[tokio::test]
async fn invalid_acceptance_retries_identical_batch_and_occurrences() {
    let receipt_id = uuid::Uuid::now_v7();
    let invalid_bodies = [
        String::new(),
        String::from("<html>proxy success</html>"),
        String::from("{}"),
        serde_json::json!({"receipt_id": uuid::Uuid::nil(), "new_events": 2, "duplicates": 0})
            .to_string(),
        serde_json::json!({"receipt_id": "invalid", "new_events": 2, "duplicates": 0}).to_string(),
        serde_json::json!({"receipt_id": receipt_id, "new_events": 2}).to_string(),
        serde_json::json!({"receipt_id": receipt_id, "new_events": 1, "duplicates": 0}).to_string(),
        serde_json::json!({"receipt_id": receipt_id, "new_events": 2, "duplicates": 1}).to_string(),
        serde_json::json!({"receipt_id": receipt_id, "new_events": -1, "duplicates": 3})
            .to_string(),
        serde_json::json!({"receipt_id": receipt_id, "new_events": usize::MAX, "duplicates": 3})
            .to_string(),
    ];
    for body in invalid_bodies {
        let batches = run_response_fixture(StatusCode::OK, body.clone(), false).await;
        assert_eq!(
            batches.len(),
            2,
            "invalid acknowledgment was accepted: {body}"
        );
        assert_eq!(
            serde_json::to_vec(&batches[0]).unwrap(),
            serde_json::to_vec(&batches[1]).unwrap(),
        );
    }
}

#[tokio::test]
async fn response_reads_are_bounded_with_and_without_content_length() {
    let accepted = serde_json::json!({
        "receipt_id": uuid::Uuid::now_v7(), "new_events": 2, "duplicates": 0,
    })
    .to_string();
    let at_limit = format!("{accepted}{}", " ".repeat(16 * 1024 - accepted.len()));
    assert_eq!(
        run_response_fixture(StatusCode::OK, at_limit.clone(), false)
            .await
            .len(),
        1,
    );
    for stall in [false, true] {
        let batches = run_response_fixture(StatusCode::OK, format!("{at_limit} "), stall).await;
        assert_eq!(batches.len(), 2);
        assert_eq!(
            serde_json::to_vec(&batches[0]).unwrap(),
            serde_json::to_vec(&batches[1]).unwrap(),
        );
    }
    let batches = run_response_fixture(
        StatusCode::UNPROCESSABLE_ENTITY,
        " ".repeat(16 * 1024 + 1),
        true,
    )
    .await;
    // Unreadable validation details use the existing split policy.
    assert_eq!(batches.len(), 3);
    assert_ne!(batches[0].batch_id, batches[1].batch_id);
    assert_eq!(
        batches[0].events[0].occurrence_id,
        batches[1].events[0].occurrence_id
    );
    assert_eq!(
        batches[0].events[1].occurrence_id,
        batches[2].events[0].occurrence_id
    );
}
