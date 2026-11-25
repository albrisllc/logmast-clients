#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use logmast_reporting::{
    CheckInError, CheckInReport, CheckIns, CheckOutcome, Config, stable_run_id,
};
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::sync::Mutex;

/// One scripted reply per request; the last one repeats.
#[derive(Clone)]
enum Reply {
    Accept,
    NilReceipt,
    Status(u16, &'static str),
    Unavailable,
}

/// Each request's Authorization header and body, in arrival order.
type Seen = Arc<Mutex<Vec<(Option<String>, Vec<u8>)>>>;

#[derive(Clone)]
struct Fixture {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    seen: Seen,
}

async fn receive(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    fixture
        .seen
        .lock()
        .await
        .push((authorization, body.to_vec()));
    let reply = {
        let mut replies = fixture.replies.lock().await;
        if replies.len() > 1 {
            replies.pop_front().unwrap()
        } else {
            replies.front().cloned().unwrap()
        }
    };
    match reply {
        Reply::Accept => axum::Json(serde_json::json!({
            "receipt_id": uuid::Uuid::now_v7(), "duplicate": false, "applied": true
        }))
        .into_response(),
        Reply::NilReceipt => axum::Json(serde_json::json!({
            "receipt_id": uuid::Uuid::nil(), "duplicate": false, "applied": true
        }))
        .into_response(),
        Reply::Status(status, code) => (
            StatusCode::from_u16(status).unwrap(),
            axum::Json(serde_json::json!({"code": code, "message": "fixture", "errors": []})),
        )
            .into_response(),
        Reply::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("retry-after", "0")],
            "unavailable",
        )
            .into_response(),
    }
}

async fn serve(replies: Vec<Reply>) -> (CheckIns, Fixture) {
    let fixture = Fixture {
        replies: Arc::new(Mutex::new(replies.into())),
        seen: Arc::new(Mutex::new(Vec::new())),
    };
    let router = Router::new()
        .route("/api/v1/ingest/check-ins", post(receive))
        .with_state(fixture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let check_ins = CheckIns::new(&Config {
        // The ingest endpoint as configured; check-ins share its origin.
        endpoint: format!("http://{address}/api/v1/ingest/batches"),
        token: "fixture-token".into(),
        service_id: uuid::Uuid::now_v7(),
        environment: "test".into(),
        release: Some("release-7".into()),
    })
    .unwrap();
    (check_ins, fixture)
}

fn report() -> CheckInReport {
    let check = uuid::Uuid::now_v7();
    CheckInReport::new(check, stable_run_id(check, "run-42"), CheckOutcome::Pass)
        .duration(Duration::from_millis(1500))
        .correlation_id("run-42")
}

#[tokio::test]
async fn an_accepted_check_in_returns_its_receipt_with_the_configured_release() {
    let (check_ins, fixture) = serve(vec![Reply::Accept]).await;
    let report = report();
    let acceptance = check_ins.send(&report).await.unwrap();
    assert!(!acceptance.receipt_id.is_nil() && acceptance.applied);

    let seen = fixture.seen.lock().await;
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0.as_deref(), Some("Bearer fixture-token"));
    let sent: serde_json::Value = serde_json::from_slice(&seen[0].1).unwrap();
    assert_eq!(sent["release"], "release-7");
    assert_eq!(sent["outcome"], "pass");
    assert_eq!(sent["duration_ms"], 1500);
    assert_eq!(sent["correlation_id"], "run-42");
    assert_eq!(sent["run_id"], report.as_wire().run_id.to_string());
}

#[tokio::test]
async fn transient_failures_and_invalid_receipts_retry_the_identical_body() {
    let (check_ins, fixture) =
        serve(vec![Reply::Unavailable, Reply::NilReceipt, Reply::Accept]).await;
    check_ins.send(&report()).await.unwrap();
    let seen = fixture.seen.lock().await;
    assert_eq!(seen.len(), 3);
    assert!(
        seen.windows(2).all(|pair| pair[0].1 == pair[1].1),
        "every retry must resend the same bytes so Logmast deduplicates it"
    );
}

#[tokio::test]
async fn a_permanent_rejection_is_not_retried_and_carries_the_stable_code() {
    let (check_ins, fixture) = serve(vec![Reply::Status(409, "CHECK_IN_CONFLICT")]).await;
    match check_ins.send(&report()).await {
        Err(CheckInError::Rejected { status, code }) => {
            assert_eq!(status, 409);
            assert_eq!(code, "CHECK_IN_CONFLICT");
        }
        other => panic!("expected a permanent rejection, got {other:?}"),
    }
    assert_eq!(fixture.seen.lock().await.len(), 1);
}

#[tokio::test]
async fn throttling_is_retried_but_bounded() {
    let (check_ins, fixture) = serve(vec![Reply::Unavailable]).await;
    let started = tokio::time::Instant::now();
    match check_ins.send(&report()).await {
        Err(CheckInError::Unacknowledged { attempts }) => assert_eq!(attempts, 4),
        other => panic!("expected exhausted retries, got {other:?}"),
    }
    assert_eq!(fixture.seen.lock().await.len(), 4);
    assert!(started.elapsed() < logmast_reporting::CHECK_IN_SEND_BUDGET);
}

#[test]
fn stable_run_ids_are_deterministic_per_check_and_key() {
    let check = uuid::Uuid::now_v7();
    let other_check = uuid::Uuid::now_v7();
    let id = stable_run_id(check, "run-42");
    assert_eq!(id, stable_run_id(check, "run-42"));
    assert_ne!(id, stable_run_id(check, "run-43"));
    assert_ne!(id, stable_run_id(other_check, "run-42"));
    assert!(!id.is_nil());
    assert_eq!(id.get_version_num(), 8);
}
