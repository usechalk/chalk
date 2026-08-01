//! Writer tests.
//!
//! One property carries this module: a chunk's verdict must reach **every**
//! device in that chunk, unchanged. Fifty devices share one answer from Google,
//! and narrowing or widening that answer on the way out is how an operator ends
//! up told a device did not move when it may have.

use super::*;

use chalk_core::models::device_action::DeprovisionReason;
use chalk_google_sync::backoff::{RateLimiter, RetryPolicy};
use chalk_google_sync::chromeos::{ChunkOutcome, ChunkResult};
use chalk_google_sync::token::StaticTokenProvider;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ids(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("g-{i:03}")).collect()
}

async fn writer_against(server: &MockServer) -> ChromeOsWriter {
    let client = ChromeOsClient::new(
        Arc::new(StaticTokenProvider::new("test-token")),
        "my_customer",
    )
    .with_base_url(&server.uri())
    .with_retry_policy(RetryPolicy::test_fast())
    .with_rate_limiter(RateLimiter::unlimited());
    ChromeOsWriter::new(Arc::new(client))
}

/// The mapping itself, without a server: one chunk verdict, every device.
#[test]
fn a_chunk_verdict_reaches_every_device_it_covered() {
    let outcome = BatchOutcome {
        chunks: vec![
            ChunkOutcome {
                device_ids: vec!["a".into(), "b".into()],
                result: ChunkResult::Applied,
            },
            ChunkOutcome {
                device_ids: vec!["c".into(), "d".into()],
                result: ChunkResult::Indeterminate {
                    detail: "timed out".into(),
                },
            },
            ChunkOutcome {
                device_ids: vec!["e".into()],
                result: ChunkResult::Failed {
                    reason: "forbidden".into(),
                    message: "not authorized".into(),
                },
            },
        ],
    };

    let per = per_device(outcome);
    assert_eq!(per.len(), 5, "one answer per device, none dropped");

    assert_eq!(per[0].result, RemoteResult::Applied);
    assert_eq!(per[1].result, RemoteResult::Applied);
    assert!(matches!(per[2].result, RemoteResult::Indeterminate { .. }));
    assert!(matches!(per[3].result, RemoteResult::Indeterminate { .. }));

    // The reason and the message answer different questions and both survive:
    // "forbidden" says delegation is wrong, the message says what Google said.
    match &per[4].result {
        RemoteResult::Failed { message } => {
            assert!(message.contains("forbidden"), "{message}");
            assert!(message.contains("not authorized"), "{message}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(
        per.iter().map(|o| o.device_id.as_str()).collect::<Vec<_>>(),
        vec!["a", "b", "c", "d", "e"]
    );
}

/// An unknown outcome must never narrow to a failure on the way through. This
/// is the one-line mistake that turns "verify these fifty" into "these fifty
/// did not move".
#[test]
fn an_unknown_chunk_never_narrows_to_a_failure() {
    let per = per_device(BatchOutcome {
        chunks: vec![ChunkOutcome {
            device_ids: ids(50),
            result: ChunkResult::Indeterminate {
                detail: "chunk timed out".into(),
            },
        }],
    });
    assert_eq!(per.len(), 50);
    for o in &per {
        match &o.result {
            RemoteResult::Indeterminate { detail } => assert_eq!(detail, "chunk timed out"),
            other => panic!("{} was narrowed to {other:?}", o.device_id),
        }
    }
}

/// End to end through the real client: 120 devices, three chunks, and every
/// device comes back answered.
#[tokio::test]
async fn a_move_over_the_chunk_limit_answers_for_every_device() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    let outcomes = writer_against(&server)
        .await
        .move_to_ou("/Students/HS", &ids(120))
        .await;
    assert_eq!(outcomes.len(), 120);
    assert!(outcomes.iter().all(|o| o.result == RemoteResult::Applied));
}

/// A permission failure is definite, so every device in the chunk is failed
/// rather than left unknown — those items are safe to re-arm once delegation
/// is fixed.
#[tokio::test]
async fn a_forbidden_response_fails_every_device_definitely() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": {"code": 403, "errors": [{"reason": "forbidden", "message": "denied"}]}
        })))
        .mount(&server)
        .await;

    let outcomes = writer_against(&server)
        .await
        .change_status(
            ChangeStatusAction::Deprovision(DeprovisionReason::RetiringDevice),
            &ids(3),
        )
        .await;
    assert_eq!(outcomes.len(), 3);
    for o in &outcomes {
        match &o.result {
            RemoteResult::Failed { message } => assert!(message.contains("forbidden"), "{message}"),
            other => panic!("expected a definite failure, got {other:?}"),
        }
    }
}

/// Asking for nothing answers for nothing, and makes no request.
#[tokio::test]
async fn an_empty_request_answers_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let w = writer_against(&server).await;
    assert!(w.move_to_ou("/Students", &[]).await.is_empty());
    assert!(w
        .change_status(ChangeStatusAction::Disable, &[])
        .await
        .is_empty());
}
