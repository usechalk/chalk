//! Chalk Marketplace — Client-side marketplace integration for vendor connections.
//!
//! Planned for Phase 2. This crate will handle vendor discovery, data sharing
//! consent, and peer-to-peer roster data exchange.

/// Returns whether the marketplace feature is enabled.
pub fn is_enabled() -> bool {
    false
}

/// Placeholder: Sync webhook endpoints from the marketplace.
///
/// In a future version, this will fetch webhook endpoint configurations
/// from partner marketplace subscriptions and return them for registration.
pub async fn sync_webhook_endpoints() -> Vec<()> {
    // TODO: Phase 2 — fetch partner webhook subscriptions from marketplace API
    Vec::new()
}
