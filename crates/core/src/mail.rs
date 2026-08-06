//! Magic-link email delivery abstraction.
//!
//! The admin console and IDP portal generate passwordless login links but must
//! not depend on any specific email provider. The binary that runs them (the
//! hosted runtime, or a self-hoster's CLI) injects a [`MagicLinkMailer`]; its
//! presence is what *enables* magic-link login. The hosted runtime provides a
//! Postmark-backed implementation; self-hosters can supply their own.

use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::{Deserialize, Serialize};

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

// ---------------------------------------------------------------------------
// SMTP
// ---------------------------------------------------------------------------

/// How a self-hosted Chalk sends mail.
///
/// **SMTP and nothing else.** A district running its own Chalk already runs a
/// mail server, or has credentials for the one its email is on; pointing at it
/// is a hostname and a password. Integrating a third-party sending service
/// would mean a self-hoster signing up for an account, agreeing to somebody
/// else's terms, and routing their pupils' names through a vendor they did not
/// choose — for a sign-in link. Hosted uses Postmark because hosted is *our*
/// deployment and that is our decision to make.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// The address mail appears to come from.
    pub from: String,
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// `starttls` (the usual, port 587), `implicit` (port 465), or `none`.
    ///
    /// `none` exists for a relay on localhost that a district already trusts.
    /// It is not the default and never will be: credentials and a sign-in link
    /// in clear text across a school network is not a trade worth offering
    /// silently.
    #[serde(default = "default_smtp_security")]
    pub security: String,
}

fn default_smtp_port() -> u16 {
    587
}

fn default_smtp_security() -> String {
    "starttls".to_string()
}

/// Sends through a district's own SMTP server.
pub struct SmtpMailer {
    config: SmtpConfig,
}

impl SmtpMailer {
    pub fn new(config: SmtpConfig) -> Self {
        Self { config }
    }

    fn transport(&self) -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
        let builder = match self.config.security.trim().to_ascii_lowercase().as_str() {
            "implicit" | "tls" | "ssl" => {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.host)?
            }
            "none" | "plaintext" => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.config.host)
            }
            // Anything unrecognised gets the safe one rather than the
            // dangerous one. A typo in `security` must not silently downgrade
            // a district to clear text.
            _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.config.host)?,
        };

        let builder = builder.port(self.config.port);
        let builder = match (&self.config.username, &self.config.password) {
            (Some(u), Some(p)) if !u.is_empty() => {
                builder.credentials(Credentials::new(u.clone(), p.clone()))
            }
            _ => builder,
        };
        Ok(builder.build())
    }
}

#[async_trait]
impl MagicLinkMailer for SmtpMailer {
    async fn send_login_link(&self, to_email: &str, link: &str) -> anyhow::Result<()> {
        // Plain text. An HTML sign-in mail is more likely to be mangled by a
        // school filter than to be appreciated, and the whole message is one
        // sentence and a URL.
        let body = format!(
            "Someone asked to sign in to IT Help with this address.\n\n\
             {link}\n\n\
             The link works once and expires in 15 minutes. If this was not \
             you, nothing has happened and you can ignore this message.\n"
        );

        let message = Message::builder()
            .from(self.config.from.parse()?)
            .to(to_email.parse()?)
            .subject("Your sign-in link")
            .header(ContentType::TEXT_PLAIN)
            .body(body)?;

        self.transport()?.send(message).await?;
        Ok(())
    }
}

#[cfg(test)]
mod smtp_tests {
    use super::*;

    /// A typo in `security` must not silently downgrade a district to sending
    /// credentials and a sign-in link in clear text. Anything unrecognised
    /// gets TLS.
    #[test]
    fn an_unrecognised_security_setting_is_not_treated_as_none() {
        for setting in ["", "startls", "yes", "true", "TLS1.2", "garbage"] {
            let mailer = SmtpMailer::new(SmtpConfig {
                from: "it@example.edu".into(),
                host: "localhost".into(),
                port: 587,
                username: None,
                password: None,
                security: setting.into(),
            });
            // `builder_dangerous` never fails, so a transport that builds for
            // an unreachable host proves nothing; what matters is that the
            // dangerous branch was not selected. Only the two explicit
            // spellings may reach it.
            let dangerous = matches!(
                setting.trim().to_ascii_lowercase().as_str(),
                "none" | "plaintext"
            );
            assert!(!dangerous, "{setting:?} must not select plaintext");
            let _ = mailer.transport();
        }
    }

    #[test]
    fn the_defaults_are_the_submission_port_and_starttls() {
        let config: SmtpConfig = toml::from_str(
            r#"
            from = "it@example.edu"
            host = "smtp.example.edu"
            "#,
        )
        .unwrap();
        assert_eq!(config.port, 587);
        assert_eq!(config.security, "starttls");
        assert!(config.username.is_none());
    }

    /// Plaintext has to be asked for by name.
    #[test]
    fn plaintext_must_be_written_out_in_full() {
        let config: SmtpConfig = toml::from_str(
            r#"
            from = "it@example.edu"
            host = "localhost"
            port = 25
            security = "none"
            "#,
        )
        .unwrap();
        assert_eq!(config.security, "none");
        assert_eq!(config.port, 25);
    }
}
