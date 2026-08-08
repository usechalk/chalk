//! [`RemoteWriter`] over the ChromeOS Directory API.
//!
//! # What this layer is for
//!
//! It is the translation between two different shapes of truth. The client
//! answers per *chunk* — up to fifty devices share one verdict, because that is
//! how `moveDevicesToOu` and `batchChangeStatus` actually behave. The commit
//! path needs an answer per *device*, because that is what a change-set item
//! records and what an operator reads.
//!
//! Fanning a chunk's verdict out across its devices is the whole job, and the
//! only honest way to do it: if a chunk of fifty timed out, every one of those
//! fifty is individually unknown. Reporting any of them as failed would say
//! something the API never said.
//!
//! # Why this lives in `chalk-devices`
//!
//! `chalk-core` defines the trait and must not learn the Directory API exists —
//! that is what keeps it a leaf and lets the console commit change sets without
//! depending on a Google client.

use std::sync::Arc;

use async_trait::async_trait;
use chalk_core::models::device_action::ChangeStatusAction;
use chalk_core::remote_write::{RemoteOutcome, RemoteResult, RemoteWriter};
use chalk_google_sync::chromeos::{AnnotatedFields, BatchOutcome, ChromeOsClient, ChunkResult};

/// Applies change-set items through the Directory API.
pub struct ChromeOsWriter {
    client: Arc<ChromeOsClient>,
}

impl ChromeOsWriter {
    pub fn new(client: Arc<ChromeOsClient>) -> Self {
        Self { client }
    }
}

/// Fan a chunk-level verdict out to the devices it covered.
///
/// Order is not assumed: the outcome names its own devices, so a client that
/// reordered or split differently still maps correctly.
fn per_device(outcome: BatchOutcome) -> Vec<RemoteOutcome> {
    outcome
        .chunks
        .into_iter()
        .flat_map(|chunk| {
            let result = match &chunk.result {
                ChunkResult::Applied => RemoteResult::Applied,
                ChunkResult::Failed { reason, message } => RemoteResult::Failed {
                    // Both, because they answer different questions: the reason
                    // is what to fix (`forbidden` means delegation), and the
                    // message is what Google actually said.
                    message: format!("{reason}: {message}"),
                },
                ChunkResult::Indeterminate { detail } => RemoteResult::Indeterminate {
                    detail: detail.clone(),
                },
            };
            chunk
                .device_ids
                .into_iter()
                .map(move |device_id| RemoteOutcome {
                    device_id,
                    result: result.clone(),
                })
        })
        .collect()
}

#[async_trait]
impl RemoteWriter for ChromeOsWriter {
    async fn move_to_ou(&self, org_unit_path: &str, device_ids: &[String]) -> Vec<RemoteOutcome> {
        per_device(
            self.client
                .move_devices_to_ou(org_unit_path, device_ids)
                .await,
        )
    }

    async fn change_status(
        &self,
        action: ChangeStatusAction,
        device_ids: &[String],
    ) -> Vec<RemoteOutcome> {
        per_device(self.client.batch_change_status(action, device_ids).await)
    }

    async fn write_field(
        &self,
        field: &str,
        value: &str,
        device_ids: &[String],
    ) -> Vec<RemoteOutcome> {
        // Build (and validate) once; a value over Google's limit fails every
        // device here with the field name and the limit, before anything is
        // sent.
        let fields = match field {
            "annotated_user" => AnnotatedFields::new().with_annotated_user(value),
            "annotated_asset_id" => AnnotatedFields::new().with_annotated_asset_id(value),
            "annotated_location" => AnnotatedFields::new().with_annotated_location(value),
            "notes" => AnnotatedFields::new().with_notes(value),
            other => Err(chalk_core::error::ChalkError::GoogleSync(format!(
                "{other:?} is not a field Chalk writes to Google"
            ))),
        };
        let fields = match fields {
            Ok(f) => f,
            Err(e) => {
                return device_ids
                    .iter()
                    .map(|id| RemoteOutcome {
                        device_id: id.clone(),
                        result: RemoteResult::Failed {
                            message: e.to_string(),
                        },
                    })
                    .collect()
            }
        };
        // One PATCH per device, serially, mirroring run_chunks' discipline:
        // a failed device must not cancel the ones behind it.
        let mut out = Vec::with_capacity(device_ids.len());
        for id in device_ids {
            let result = match self.client.update_annotated_fields(id, &fields).await {
                Ok(()) => RemoteResult::Applied,
                Err(e) => RemoteResult::Failed {
                    message: e.to_string(),
                },
            };
            out.push(RemoteOutcome {
                device_id: id.clone(),
                result,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests;
