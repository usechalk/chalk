//! Chalk AD Sync -- Active Directory user provisioning and OU management.
//!
//! This crate handles creating/disabling Active Directory accounts,
//! managing Organizational Units, and delta-only sync via LDAP.

pub mod client;
pub mod models;
pub mod ou;
pub mod password;
pub mod sync;
pub mod username;
