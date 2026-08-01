//! Tests for the remote-write seam.
//!
//! Small surface, but the default matters: a deployment with no Google write
//! access must *say so* on every item rather than quietly leaving them
//! pending, because a change set that appears to have succeeded is worse than
//! one that plainly did not.

use super::*;

use crate::models::device_action::{ChangeStatusAction, DeprovisionReason};

fn ids() -> Vec<String> {
    vec!["g-1".to_string(), "g-2".to_string()]
}

/// Every device comes back failed, each carrying the reason. Not applied, and
/// not silently absent from the results — an item Google said nothing about is
/// treated as indeterminate by the commit path, and "not configured" is a
/// definite no, not an unknown.
#[tokio::test]
async fn the_unavailable_writer_refuses_every_device_with_a_reason() {
    let w = UnavailableWriter::new("Google write-back is not configured.");

    for outcomes in [
        w.move_to_ou("/Students", &ids()).await,
        w.change_status(ChangeStatusAction::Disable, &ids()).await,
        w.change_status(
            ChangeStatusAction::Deprovision(DeprovisionReason::RetiringDevice),
            &ids(),
        )
        .await,
    ] {
        assert_eq!(
            outcomes.len(),
            2,
            "one answer per device, never one per call"
        );
        for o in &outcomes {
            match &o.result {
                RemoteResult::Failed { message } => {
                    assert!(message.contains("not configured"), "{message}")
                }
                other => panic!("expected a definite refusal, got {other:?}"),
            }
        }
        assert_eq!(outcomes[0].device_id, "g-1");
        assert_eq!(outcomes[1].device_id, "g-2");
    }
}

/// An empty batch produces no answers rather than one for a device that was
/// never named.
#[tokio::test]
async fn refusing_nothing_answers_nothing() {
    let w = UnavailableWriter::new("nope");
    assert!(w.move_to_ou("/Students", &[]).await.is_empty());
    assert!(w
        .change_status(ChangeStatusAction::Reenable, &[])
        .await
        .is_empty());
}

/// `Failed` and `Indeterminate` are different answers and must never compare
/// equal — the whole point of the third state is that the UI can tell an
/// operator "may have applied" instead of "did not apply".
#[test]
fn a_refusal_and_an_unknown_outcome_are_not_the_same_answer() {
    let failed = RemoteResult::Failed {
        message: "forbidden".into(),
    };
    let unknown = RemoteResult::Indeterminate {
        detail: "timed out".into(),
    };
    assert_ne!(failed, unknown);
    assert_ne!(RemoteResult::Applied, unknown);
    assert_eq!(RemoteOutcome::applied("g-1").result, RemoteResult::Applied);
}
