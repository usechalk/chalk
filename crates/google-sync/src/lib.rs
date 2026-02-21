//! Chalk Google Sync — Google Workspace user provisioning and OU management.
//!
//! This crate handles creating/suspending Google Workspace accounts,
//! managing Organizational Units, and delta-only sync via the Admin SDK.

pub mod auth;
pub mod client;
pub mod models;
pub mod ou;
pub mod sync;
pub mod username;
