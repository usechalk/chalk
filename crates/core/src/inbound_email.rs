//! Turning an email into a ticket, or into a reply on one.
//!
//! # Why there is a seam here
//!
//! Hosted receives mail through Postmark's inbound webhook. A self-hosted
//! district will not pay for that, and will point whatever relay it already
//! runs at Chalk instead. Both arrive as an HTTP request with a JSON body and
//! differ only in the shape of that body, so the provider-specific part is a
//! [`InboundEmailParser`] — one small function per provider — and everything
//! that decides what actually happens to the mail is shared.
//!
//! The alternative, a parser per provider that each creates tickets its own
//! way, is how one provider's mail quietly gets different threading, different
//! loop protection, or a different idea of who the requester is.
//!
//! # The three things that make email ingestion dangerous
//!
//! **Loops.** Chalk emails a requester; their out-of-office replies; that
//! creates a ticket; Chalk emails them about it. A mail loop with a school
//! district on one end is a bad afternoon, so anything that announces itself
//! as automatic is dropped before it can become a ticket.
//!
//! **Retries.** Providers re-deliver on any non-2xx, and Postmark keeps trying
//! for hours. Ingestion is keyed on the message id with a unique index behind
//! it, so a redelivery lands on the row that already exists rather than
//! creating a second ticket saying the same thing.
//!
//! **Spoofing.** `From:` is a claim, not an identity. It is only allowed to
//! bind a message to a roster user when the provider says the sending domain
//! authenticated — otherwise anybody who can send mail could file tickets as
//! the superintendent. An unauthenticated message still becomes a ticket; it
//! is simply attributed to the address rather than to the person.

use std::sync::Arc;

use crate::db::repository::TicketRepository;
use crate::error::Result;
use crate::models::ticket::{NewTicketComment, Ticket, TicketPriority, TicketSource};
use crate::models::user::User;
use crate::ticket_service::{NewTicket, TicketService};

/// What the sending domain proved about itself.
///
/// Providers report SPF and DKIM results; a relay that reports nothing gets
/// [`Unverified`](Authentication::Unverified), which is treated the same as a
/// failure. Not knowing and knowing it failed lead to the same decision, and
/// collapsing them means a misconfigured relay cannot accidentally be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Authentication {
    /// SPF or DKIM passed for the sending domain.
    Passed,
    #[default]
    Unverified,
}

/// One inbound message, in the shape everything downstream works with.
#[derive(Debug, Clone, Default)]
pub struct InboundMessage {
    /// RFC 5322 `Message-ID`. The idempotency key.
    pub message_id: String,
    pub from: String,
    /// `In-Reply-To`, then every id in `References`. Order matters: the direct
    /// parent is the best answer.
    pub in_reply_to: Vec<String>,
    pub subject: String,
    /// Plain text. HTML is deliberately not stored — see [`strip_quoted`].
    pub body: String,
    pub authentication: Authentication,
    /// `true` when the message announced itself as machine-generated.
    pub automatic: bool,
    pub attachments: Vec<InboundAttachment>,
}

#[derive(Debug, Clone, Default)]
pub struct InboundAttachment {
    pub filename: String,
    pub bytes: Vec<u8>,
}

/// Turns one provider's webhook body into an [`InboundMessage`].
pub trait InboundEmailParser: Send + Sync {
    /// The value an operator puts in `provider =`.
    fn name(&self) -> &'static str;
    fn parse(&self, body: &[u8]) -> Result<InboundMessage>;
}

/// What happened to a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingested {
    /// A new ticket, with its id.
    Raised(String),
    /// A reply threaded onto an existing ticket.
    Replied(String),
    /// Seen before. The webhook is being retried; the ticket already exists.
    AlreadySeen(String),
    /// Deliberately not turned into anything, and why.
    Dropped(DropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// An auto-reply, vacation responder, or bounce.
    Automatic,
    /// Nothing in it — no subject and no body.
    Empty,
    /// No usable `Message-ID`, so it cannot be deduplicated and a retry would
    /// create a duplicate every time.
    NoMessageId,
}

impl DropReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Automatic => "automatic message",
            Self::Empty => "empty message",
            Self::NoMessageId => "no Message-ID",
        }
    }
}

/// Headers whose presence means "a machine sent this".
///
/// Checked by the provider adapters, which is where raw headers exist. Listed
/// here so every provider drops the same things.
pub const AUTOMATIC_HEADERS: &[&str] = &[
    "auto-submitted", // RFC 3834, the standard one
    "x-autoreply",    // widely used
    "x-autorespond",  //
    "x-auto-response-suppress",
];

/// Whether a `Precedence:` value marks bulk or automatic mail.
pub fn precedence_is_automatic(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "bulk" | "junk" | "auto_reply" | "list"
    )
}

/// Whether an `Auto-Submitted:` value means anything other than a human.
///
/// RFC 3834: `no` is the value a person's mail carries. Anything else — and
/// notably the header being absent entirely — is not automatic.
pub fn auto_submitted_is_automatic(value: &str) -> bool {
    !value.trim().is_empty() && !value.trim().eq_ignore_ascii_case("no")
}

/// Remove the quoted history from a reply.
///
/// Mail clients quote the entire previous message, so without this every reply
/// carries a copy of the whole thread and a technician scrolls past their own
/// words to find the new sentence. Conservative on purpose: a wrong guess here
/// deletes what somebody wrote, so only the two unambiguous markers are cut —
/// the `--` signature separator on its own line, and a run of `>` quoting that
/// continues to the end.
pub fn strip_quoted(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();

    // Everything from the signature separator on.
    let end = lines
        .iter()
        .position(|l| l.trim_end() == "--" || l.trim_end() == "-- ")
        .unwrap_or(lines.len());
    let mut kept = &lines[..end];

    // A trailing block of quoted lines, plus the "On <date>, X wrote:" line
    // immediately above it if there is one.
    while kept
        .last()
        .is_some_and(|l| l.trim_start().starts_with('>') || l.trim().is_empty())
    {
        kept = &kept[..kept.len() - 1];
    }
    if kept
        .last()
        .is_some_and(|l| l.trim_end().ends_with("wrote:") || l.trim_end().ends_with("écrit :"))
    {
        kept = &kept[..kept.len() - 1];
    }

    kept.join("\n").trim().to_string()
}

/// Extract a ticket number from a subject like `Re: [#412] Broken screen`.
///
/// The bracketed token is what outbound notifications put there, so a reply
/// threads even when a client drops `In-Reply-To` — which Outlook does when
/// somebody forwards rather than replies.
pub fn ticket_number_in_subject(subject: &str) -> Option<i64> {
    let start = subject.find("[#")?;
    let rest = &subject[start + 2..];
    let end = rest.find(']')?;
    rest[..end].trim().parse().ok()
}

/// Resolves a sending address to a roster user.
///
/// A closure rather than a `UserRepository`, because the only thing needed is
/// one lookup and a caller processing a batch will want to do it once.
pub type ResolveSender = Box<dyn Fn(&str) -> Option<User> + Send + Sync>;

/// Everything ingestion needs that is not the mail itself.
pub struct EmailIngestor {
    tickets: Arc<dyn TicketRepository>,
    service: TicketService,
    resolve: ResolveSender,
}

impl EmailIngestor {
    pub fn new(
        tickets: Arc<dyn TicketRepository>,
        service: TicketService,
        resolve: ResolveSender,
    ) -> Self {
        Self {
            tickets,
            service,
            resolve,
        }
    }

    /// Ingest one message.
    ///
    /// Every path returns `Ok`. A message we decline to act on is not an
    /// error — returning one would make the provider retry it forever.
    pub async fn ingest(&self, message: InboundMessage) -> Result<Ingested> {
        if message.automatic {
            return Ok(Ingested::Dropped(DropReason::Automatic));
        }
        if message.message_id.trim().is_empty() {
            return Ok(Ingested::Dropped(DropReason::NoMessageId));
        }

        let body = strip_quoted(&message.body);
        let subject = message.subject.trim();
        if body.is_empty() && subject.is_empty() && message.attachments.is_empty() {
            return Ok(Ingested::Dropped(DropReason::Empty));
        }

        // Idempotency first, and on *both* tables. A redelivered first message
        // is a ticket row; a redelivered reply is a comment row. Checking only
        // the first lets a repeated reply hit the unique index on
        // `ticket_comments.email_message_id`, error, and be retried by the
        // provider forever — which is the loop this exists to prevent.
        if let Some(existing) = self
            .tickets
            .get_ticket_by_message_id(&message.message_id)
            .await?
        {
            return Ok(Ingested::AlreadySeen(existing.id));
        }
        if let Some(ticket_id) = self
            .tickets
            .ticket_id_for_comment_message_id(&message.message_id)
            .await?
        {
            return Ok(Ingested::AlreadySeen(ticket_id));
        }

        if let Some(ticket) = self.find_thread(&message).await? {
            return self.append_reply(&ticket, &message, &body).await;
        }
        self.raise(&message, &body, subject).await
    }

    /// The ticket this message is a reply to, if any.
    async fn find_thread(&self, message: &InboundMessage) -> Result<Option<Ticket>> {
        // The mail client's own threading is the most reliable signal.
        for parent in &message.in_reply_to {
            if let Some(t) = self.tickets.get_ticket_by_message_id(parent).await? {
                return Ok(Some(t));
            }
        }
        // Then the number we put in the subject, for clients that lose the
        // header.
        if let Some(number) = ticket_number_in_subject(&message.subject) {
            if let Some(t) = self.tickets.get_ticket_by_number(number).await? {
                return Ok(Some(t));
            }
        }
        Ok(None)
    }

    async fn append_reply(
        &self,
        ticket: &Ticket,
        message: &InboundMessage,
        body: &str,
    ) -> Result<Ingested> {
        let author = self.roster_user(message);
        let text = if body.is_empty() {
            "Sent an attachment.".to_string()
        } else {
            body.to_string()
        };

        let comment = NewTicketComment {
            ticket_id: ticket.id.clone(),
            author_user_sourced_id: author.as_ref().map(|u| u.sourced_id.clone()),
            author_email: Some(crate::email::address_from_header(&message.from)),
            body: text,
            // A message from outside is never an internal note. There is no
            // path here that could make one.
            is_internal: false,
            source: TicketSource::Email,
            email_message_id: Some(message.message_id.clone()),
        };
        self.tickets.append_comment(&comment).await?;
        Ok(Ingested::Replied(ticket.id.clone()))
    }

    async fn raise(&self, message: &InboundMessage, body: &str, subject: &str) -> Result<Ingested> {
        let user = self.roster_user(message);
        let new = NewTicket {
            requester_user_sourced_id: user.as_ref().map(|u| u.sourced_id.clone()),
            requester_email: Some(crate::email::address_from_header(&message.from)),
            subject: if subject.is_empty() {
                "(no subject)".to_string()
            } else {
                strip_reply_prefixes(subject)
            },
            body: body.to_string(),
            priority: TicketPriority::default(),
            source: TicketSource::Email,
            email_message_id: Some(message.message_id.clone()),
            ..Default::default()
        };

        let prepared = self
            .service
            .prepare(uuid::Uuid::new_v4().to_string(), new)
            .await?;
        let created = self.tickets.create_ticket(&prepared).await?;
        Ok(Ingested::Raised(created.id))
    }

    /// The roster user this message may be attributed to.
    ///
    /// **Only when the sending domain authenticated.** `From:` is a claim, and
    /// binding an unauthenticated one to a roster row would let anybody who
    /// can send mail file tickets as somebody else. The message still becomes
    /// a ticket either way — it is simply attributed to the address.
    fn roster_user(&self, message: &InboundMessage) -> Option<User> {
        if message.authentication != Authentication::Passed {
            return None;
        }
        (self.resolve)(&crate::email::address_from_header(&message.from))
    }
}

/// `Re:`, `Fwd:` and their common translations, stripped from a new ticket's
/// subject so a queue does not fill with `Re: Re: Fwd:`.
pub fn strip_reply_prefixes(subject: &str) -> String {
    const PREFIXES: &[&str] = &["re:", "fw:", "fwd:", "aw:", "sv:", "vs:", "rv:"];
    let mut s = subject.trim();
    loop {
        let lower = s.to_ascii_lowercase();
        match PREFIXES.iter().find(|p| lower.starts_with(**p)) {
            Some(p) => s = s[p.len()..].trim_start(),
            None => break,
        }
    }
    if s.is_empty() {
        subject.trim().to_string()
    } else {
        s.to_string()
    }
}

pub mod providers;

#[cfg(test)]
mod tests;
