//! Magic-link email delivery abstraction.
//!
//! The admin console and IDP portal generate passwordless login links but must
//! not depend on any specific email provider. The binary that runs them (the
//! hosted runtime, or a self-hoster's CLI) injects a [`MagicLinkMailer`]; its
//! presence is what *enables* magic-link login. The hosted runtime provides a
//! Postmark-backed implementation; self-hosters can supply their own.

use async_trait::async_trait;

/// Sends one-time passwordless login links.
#[async_trait]
pub trait MagicLinkMailer: Send + Sync {
    /// Email a login link to `to_email`. Implementations should be best-effort;
    /// callers treat failures as non-fatal (the user is shown a neutral
    /// "check your email" response regardless, to avoid account enumeration).
    async fn send_login_link(&self, to_email: &str, link: &str) -> anyhow::Result<()>;
}

/// A no-op mailer that logs the link instead of sending it — useful for local
/// development when no email provider is configured.
pub struct LoggingMailer;

#[async_trait]
impl MagicLinkMailer for LoggingMailer {
    async fn send_login_link(&self, to_email: &str, link: &str) -> anyhow::Result<()> {
        tracing::info!(target: "chalk_core::mail", "DEV magic login link for {to_email}: {link}");
        Ok(())
    }
}
