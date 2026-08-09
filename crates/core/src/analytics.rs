//! Product-analytics seam (hosted-only by construction).
//!
//! The console calls [`AnalyticsSink::capture`] from its auth middleware
//! when a sink is wired; `chalk serve` NEVER wires one, so a self-hosted
//! district's console cannot emit an event no matter how it is configured —
//! the privacy property is the absent impl, not a flag. Only the hosted
//! runtime (a separate, private codebase) supplies an implementation.
//!
//! Events are no-PII **by type**: the struct has fields for the route
//! template, method, actor *role*, and event name — there is nowhere to put
//! a student name, an email, a serial, or a raw URL (templates like
//! `/devices/:id` never contain the id).

/// One captured console interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyticsEvent {
    /// `"console_pageview"` or `"console_action"`.
    pub name: &'static str,
    /// The axum route TEMPLATE (`/devices/:id/checkout`), never the real
    /// path — ids and query strings are structurally absent.
    pub route: String,
    pub method: String,
    /// The actor's role string (`admin`/`technician`/`read_only`), never
    /// their identity.
    pub role: String,
}

/// Where events go. Implementations must be fire-and-forget: a slow or
/// down analytics endpoint may never slow a console request.
pub trait AnalyticsSink: Send + Sync {
    fn capture(&self, event: AnalyticsEvent);
}
