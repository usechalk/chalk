//! Chalk Devices — ChromeOS fleet ingestion and device→roster matching.
//!
//! The crate turns a Google Workspace ChromeOS estate into rows of `assets`
//! with real students attached, and nothing else. It is **read-only against
//! Google**: [`chalk_google_sync::chromeos::ChromeOsClient`] exposes no write
//! method, and nothing here constructs one. Every mutation this crate performs
//! is against Chalk's own tables.
//!
//! Two invariants shape the design:
//!
//! - **Google is authoritative for hardware, OS, OU and AUE. Chalk is
//!   authoritative for assignment, status and purchase/warranty/funding.** The
//!   sync therefore merges field by field and never replaces a row.
//! - **A human always wins.** `match_state='manual'` (and `'ignored'`) make a
//!   device's assignment untouchable by any rule, on every subsequent run.
//!
//! Repositories arrive as four standalone `Arc<dyn …>` traits rather than
//! `ChalkRepository`, so a device test needs a ~40-line fake roster instead of
//! the 800-line mock that exists to test user provisioning.

pub mod matching;
pub mod sync;
pub mod writer;

pub use matching::{match_device_to_user, normalize_asset_tag, MatchRule, RosterIndex, UserMatch};
pub use sync::{DeviceSyncEngine, DeviceSyncSummary};
