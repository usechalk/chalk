//! Chalk Core — SIS engine, OneRoster schema, data normalization, and database layer.

pub mod auth;
pub mod config;
pub mod connectors;
pub mod cookies;
pub mod crypto;
pub mod db;
pub mod error;
pub mod http;
pub mod migration;
pub mod models;
pub mod oneroster_csv;
pub mod passwords;
pub mod sync;
pub mod webhooks;
