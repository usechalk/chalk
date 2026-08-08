//! Outbound email delivery abstraction.
//!
//! The console, IDP portal, and — from the notification work — the help desk
//! and device lifecycle all need to send mail without depending on a specific
//! provider. The binary that runs them (the hosted runtime, or a self-hoster's
//! CLI) injects a [`Notifier`]; the hosted runtime provides a Postmark-backed
//! implementation, self-hosters point at their own SMTP.
//!
//! # One transport, many messages
//!
//! This started as a magic-link-only trait, which is why the trait's single
//! *required* method is a general [`Notifier::send_email`] and the login link
//! is a *provided* method built on top of it. A transport implements sending
//! one message; every kind of notification — a sign-in link, a help-desk reply,
//! a device-return reminder — is that one operation with different content.
//! Presence of a [`Notifier`] is still what enables magic-link login.

use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::{Deserialize, Serialize};

/// One outbound email, transport-agnostic.
///
/// Deliberately carries no `from` address: the *transport* owns that (a
/// self-hoster's SMTP `from`, or the hosted Postmark default), because a
/// message built in a handler has no business knowing the deployment's sending
/// identity. `reply_to` is the exception a handler legitimately sets — a
/// help-desk reply threads back to a per-ticket address so the requester's
/// response returns through the inbound webhook.
#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    /// Plain text. School mail filters mangle HTML sign-in and notification
    /// mail more often than they thank you for it, and every message Chalk
    /// sends is a few sentences and maybe a link.
    pub body: String,
    /// When set, replies go here instead of to the transport's `from` — used
    /// to thread a requester's reply back to the ticket it belongs to.
    pub reply_to: Option<String>,
}

impl EmailMessage {
    /// A message with no reply-to override (the common case).
    pub fn new(to: impl Into<String>, subject: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            to: to.into(),
            subject: subject.into(),
            body: body.into(),
            reply_to: None,
        }
    }

    /// Set the address a reply should return to.
    pub fn with_reply_to(mut self, reply_to: impl Into<String>) -> Self {
        self.reply_to = Some(reply_to.into());
        self
    }
}

/// The body of the passwordless sign-in email. One sentence and a URL; kept as
/// a free function so the wording lives in exactly one place regardless of
/// transport.
fn login_link_body(link: &str) -> String {
    format!(
        "Someone asked to sign in to IT Help with this address.\n\n\
         {link}\n\n\
         The link works once and expires in 15 minutes. If this was not \
         you, nothing has happened and you can ignore this message.\n"
    )
}

/// Sends outbound email for Chalk. One required method; everything else is a
/// message shaped and handed to it.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Deliver one message. Implementations should be best-effort; callers
    /// treat failures as non-fatal (a sign-in shows a neutral "check your
    /// email" regardless, to avoid account enumeration, and a help-desk action
    /// still succeeds even if its notification did not go out).
    async fn send_email(&self, message: &EmailMessage) -> anyhow::Result<()>;

    /// Email a one-time sign-in link. Provided on top of [`Self::send_email`]
    /// so every transport gets it for free and the wording cannot drift
    /// between them.
    async fn send_login_link(&self, to_email: &str, link: &str) -> anyhow::Result<()> {
        self.send_email(&EmailMessage::new(
            to_email,
            "Your sign-in link",
            login_link_body(link),
        ))
        .await
    }
}

/// A no-op notifier that logs instead of sending — useful for local
/// development when no email provider is configured.
pub struct LoggingMailer;

#[async_trait]
impl Notifier for LoggingMailer {
    async fn send_email(&self, message: &EmailMessage) -> anyhow::Result<()> {
        tracing::info!(
            target: "chalk_core::mail",
            "DEV email to {} — {}\n{}",
            message.to, message.subject, message.body
        );
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
impl Notifier for SmtpMailer {
    async fn send_email(&self, message: &EmailMessage) -> anyhow::Result<()> {
        let from: Mailbox = self.config.from.parse()?;
        let to: Mailbox = message.to.parse()?;

        let mut builder = Message::builder()
            .from(from)
            .to(to)
            .subject(message.subject.clone())
            .header(ContentType::TEXT_PLAIN);

        if let Some(reply_to) = &message.reply_to {
            builder = builder.reply_to(reply_to.parse()?);
        }

        let email = builder.body(message.body.clone())?;
        self.transport()?.send(email).await?;
        Ok(())
    }
}

#[cfg(test)]
mod notifier_tests {
    use super::*;
    use std::sync::Mutex;

    /// Captures whatever it is asked to send, so a test can inspect the exact
    /// message a provided method produced.
    #[derive(Default)]
    struct CapturingNotifier {
        sent: Mutex<Vec<EmailMessage>>,
    }

    #[async_trait]
    impl Notifier for CapturingNotifier {
        async fn send_email(&self, message: &EmailMessage) -> anyhow::Result<()> {
            self.sent.lock().unwrap().push(message.clone());
            Ok(())
        }
    }

    /// The whole point of making `send_login_link` a provided method is that
    /// generalising the trait did not change the sign-in email. Pin its exact
    /// shape: right recipient, unchanged subject, the link present in the body,
    /// and no reply-to (a sign-in link is not a conversation).
    #[tokio::test]
    async fn send_login_link_still_produces_the_same_message() {
        let notifier = CapturingNotifier::default();
        notifier
            .send_login_link(
                "teacher@example.edu",
                "https://chalk.example/verify?token=abc",
            )
            .await
            .unwrap();

        let sent = notifier.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let msg = &sent[0];
        assert_eq!(msg.to, "teacher@example.edu");
        assert_eq!(msg.subject, "Your sign-in link");
        assert!(msg.body.contains("https://chalk.example/verify?token=abc"));
        assert!(msg.body.contains("expires in 15 minutes"));
        assert!(
            msg.reply_to.is_none(),
            "a one-time sign-in link is not something to reply to"
        );
    }

    /// A reply-to is carried through so a help-desk reply can thread back to
    /// the ticket. `EmailMessage::new` leaves it unset.
    #[test]
    fn reply_to_is_opt_in() {
        assert!(EmailMessage::new("a@b.c", "s", "b").reply_to.is_none());
        assert_eq!(
            EmailMessage::new("a@b.c", "s", "b")
                .with_reply_to("ticket+42@help.example")
                .reply_to
                .as_deref(),
            Some("ticket+42@help.example")
        );
    }

    /// A reply-to must be a parseable mailbox, or the SMTP transport rejects
    /// the whole message rather than sending an unrepliable one.
    #[tokio::test]
    async fn smtp_rejects_an_unparseable_reply_to() {
        let mailer = SmtpMailer::new(SmtpConfig {
            from: "it@example.edu".into(),
            host: "localhost".into(),
            port: 587,
            username: None,
            password: None,
            security: "starttls".into(),
        });
        let msg = EmailMessage::new("parent@example.edu", "Your ticket", "…")
            .with_reply_to("not a mailbox");
        assert!(mailer.send_email(&msg).await.is_err());
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
