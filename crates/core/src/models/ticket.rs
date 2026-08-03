//! Helpdesk tickets, their comments and their attachments (migration 020).
//!
//! # The number is not the id
//!
//! [`Ticket::id`] is a UUID and [`Ticket::number`] is what a human says out
//! loud. They are separate because the number has to be small, ordered and
//! quotable over a radio — "ticket four-one-two" — while the id has to be
//! unguessable and stable. Districts refer to tickets by number in email
//! subjects and on work orders, so it is part of the product, not a display
//! detail.
//!
//! # Why a requester can be an email address
//!
//! `requester_user_sourced_id` is the roster link and `requester_email` is the
//! fallback. A ticket that arrives by email from a parent, a substitute, or a
//! staff member whose account has not synced yet is still a ticket. Refusing it
//! for want of a roster row would send mail into a void, and the sender would
//! never know.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::str_enum::str_enum;

str_enum! {
    /// Where a ticket is in its life.
    ///
    /// `waiting` means waiting on the *requester*, which is the distinction
    /// that makes an SLA honest: a technician cannot be held to a clock that
    /// is running while they wait for someone to answer a question.
    pub enum TicketStatus {
        #[default]
        Open => "open",
        InProgress => "in_progress",
        Waiting => "waiting",
        Resolved => "resolved",
        Closed => "closed",
    }
    with_default
}

impl TicketStatus {
    /// True once the ticket no longer needs work.
    pub fn is_settled(&self) -> bool {
        matches!(self, Self::Resolved | Self::Closed)
    }

    /// True while an SLA clock should be running.
    ///
    /// Paused for `waiting`, because the district is waiting on its own user.
    pub fn clock_runs(&self) -> bool {
        matches!(self, Self::Open | Self::InProgress)
    }

    /// Where this status sits in the workflow, most-active first.
    ///
    /// Used for sorting. The stored strings sort alphabetically as
    /// closed, in_progress, open, resolved, waiting — an order that means
    /// nothing to anybody.
    pub fn workflow_rank(&self) -> i32 {
        match self {
            Self::Open => 0,
            Self::InProgress => 1,
            Self::Waiting => 2,
            Self::Resolved => 3,
            Self::Closed => 4,
        }
    }

    /// The `status IN (...)` list matching [`Self::clock_runs`], for the one
    /// predicate both drivers need.
    ///
    /// This rule was written out three times — here, in the SQLite query
    /// builder and in the Postgres one — and all three disagreed with
    /// [`Self::clock_runs`], so a ticket waiting on its requester was shown as
    /// past due. Deriving the fragment from the same `match` is what stops the
    /// fourth copy. The values are enum literals, never user input.
    pub fn clock_running_sql_in() -> String {
        let list = Self::ALL
            .iter()
            .filter(|s| s.clock_runs())
            .map(|s| format!("'{}'", s.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        format!("status IN ({list})")
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::InProgress => "In progress",
            Self::Waiting => "Waiting on requester",
            Self::Resolved => "Resolved",
            Self::Closed => "Closed",
        }
    }
}

str_enum! {
    /// How urgent the requester or a technician says this is.
    pub enum TicketPriority {
        Low => "low",
        #[default]
        Normal => "normal",
        High => "high",
        Urgent => "urgent",
    }
    with_default
}

impl TicketPriority {
    /// Severity, ascending, so a plain `ORDER BY ... DESC` puts urgent first.
    ///
    /// The stored strings sort alphabetically as high, low, normal, urgent,
    /// which puts *low* above *normal* and *high* at the bottom — precisely
    /// backwards for the sort a technician reaches for most.
    pub fn severity_rank(&self) -> i32 {
        match self {
            Self::Low => 0,
            Self::Normal => 1,
            Self::High => 2,
            Self::Urgent => 3,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Normal => "Normal",
            Self::High => "High",
            Self::Urgent => "Urgent",
        }
    }
}

str_enum! {
    /// Where a ticket or comment came from.
    ///
    /// Recorded because it changes what a reply should do: a portal ticket
    /// notifies, an email ticket threads, and an agent-raised one may have no
    /// human on the other end at all.
    pub enum TicketSource {
        #[default]
        Portal => "portal",
        Email => "email",
        Api => "api",
        Agent => "agent",
    }
    with_default
}

/// A row of `tickets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ticket {
    /// UUID.
    pub id: String,
    /// Human-facing, monotonic, allocated from `ticket_counters`.
    pub number: i64,
    pub requester_user_sourced_id: Option<String>,
    /// Retained for email-sourced tickets from senders with no roster row.
    pub requester_email: Option<String>,
    /// Auto-attached from the requester's assignment at creation.
    pub asset_id: Option<String>,
    pub school_org_sourced_id: Option<String>,
    pub assignee_user_sourced_id: Option<String>,
    pub status: TicketStatus,
    pub priority: TicketPriority,
    pub category: Option<String>,
    pub subject: String,
    pub body: String,
    pub source: TicketSource,
    /// RFC 5322 `Message-ID` of the originating mail. Unique when present —
    /// the index is what makes email dedup an insert conflict.
    pub email_message_id: Option<String>,
    pub sla_due_at: Option<DateTime<Utc>>,
    /// When a technician first said something the requester could see.
    /// Internal notes deliberately do not count.
    pub first_response_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Ticket {
    /// A minimal ticket. The number is assigned by the repository, not here —
    /// allocating one outside the insert transaction is how two tickets end up
    /// sharing it.
    pub fn new(id: impl Into<String>, subject: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            number: 0,
            requester_user_sourced_id: None,
            requester_email: None,
            asset_id: None,
            school_org_sourced_id: None,
            assignee_user_sourced_id: None,
            status: TicketStatus::default(),
            priority: TicketPriority::default(),
            category: None,
            subject: subject.into(),
            body: String::new(),
            source: TicketSource::default(),
            email_message_id: None,
            sla_due_at: None,
            first_response_at: None,
            resolved_at: None,
            closed_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// True when the SLA has run out and the ticket still needs work.
    ///
    /// A settled ticket is never breached, however late it was resolved —
    /// past-tense lateness belongs in a report, not in a queue badge that
    /// tells a technician what to do next.
    ///
    /// Nor is a ticket *waiting on its requester* breached. That is the whole
    /// point of [`TicketStatus::clock_runs`]: a clock that is paused cannot
    /// run out. Marking it past due would show a technician a badge they
    /// cannot clear by doing anything, which is how a queue stops being
    /// believed.
    pub fn is_breached(&self, now: DateTime<Utc>) -> bool {
        self.status.clock_runs() && self.sla_due_at.is_some_and(|due| due < now)
    }

    /// Whether anyone has answered the requester yet.
    pub fn awaiting_first_response(&self) -> bool {
        self.first_response_at.is_none() && !self.status.is_settled()
    }
}

/// A comment on a ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TicketComment {
    pub id: i64,
    pub ticket_id: String,
    pub author_user_sourced_id: Option<String>,
    /// For email replies from senders with no roster row.
    pub author_email: Option<String>,
    pub body: String,
    /// Internal notes never reach the requester portal or an outbound email.
    pub is_internal: bool,
    pub source: TicketSource,
    pub email_message_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A comment to append. No `id` and no `created_at` — the database assigns
/// both, which is what makes the thread append-only rather than authored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewTicketComment {
    pub ticket_id: String,
    pub author_user_sourced_id: Option<String>,
    pub author_email: Option<String>,
    pub body: String,
    pub is_internal: bool,
    pub source: TicketSource,
    pub email_message_id: Option<String>,
}

impl NewTicketComment {
    /// A visible reply from a roster user.
    pub fn reply(
        ticket_id: impl Into<String>,
        author: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            ticket_id: ticket_id.into(),
            author_user_sourced_id: Some(author.into()),
            author_email: None,
            body: body.into(),
            is_internal: false,
            source: TicketSource::Portal,
            email_message_id: None,
        }
    }

    /// A comment from whoever is signed in to the admin console.
    ///
    /// `author` is `None` because the console's sign-in is a shared district
    /// password, not a per-person account: Chalk genuinely does not know which
    /// technician typed this. Writing a roster id we do not have would be a
    /// worse answer than admitting it — `ticket_comments.author_user_sourced_id`
    /// is a foreign key into `users`, so an invented id is not even storable.
    ///
    /// When per-administrator accounts arrive, pass the id here and the thread
    /// starts naming people with no other change.
    pub fn from_console(
        ticket_id: impl Into<String>,
        author: Option<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            ticket_id: ticket_id.into(),
            author_user_sourced_id: author,
            author_email: None,
            body: body.into(),
            is_internal: false,
            source: TicketSource::Portal,
            email_message_id: None,
        }
    }

    /// The same comment, hidden from the requester.
    pub fn internal(self) -> Self {
        Self {
            is_internal: true,
            ..self
        }
    }

    /// A note only technicians see.
    pub fn internal_note(
        ticket_id: impl Into<String>,
        author: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            is_internal: true,
            ..Self::reply(ticket_id, author, body)
        }
    }
}

/// A stored attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TicketAttachment {
    /// UUID, which doubles as the stem of the storage key.
    pub id: String,
    pub ticket_id: String,
    pub comment_id: Option<i64>,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    /// Of the bytes as stored. Lets a restore prove it got back what it put in.
    pub sha256: String,
    /// Opaque to everything but the `AttachmentStore` that wrote it.
    pub storage_key: String,
    pub created_at: DateTime<Utc>,
}

/// What a queue is filtered by.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TicketFilter {
    pub status: Option<TicketStatus>,
    pub priority: Option<TicketPriority>,
    pub assignee_user_sourced_id: Option<String>,
    pub requester_user_sourced_id: Option<String>,
    pub school_org_sourced_id: Option<String>,
    pub asset_id: Option<String>,
    /// `Some(true)` = only tickets nobody has picked up.
    pub unassigned: Option<bool>,
    /// Only tickets whose SLA has run out and which still need work.
    pub breached_only: bool,
    /// Case-insensitive substring over subject and body.
    pub search: Option<String>,
    pub sort: TicketSort,
    pub direction: super::page::SortDirection,
}

/// Which schools' tickets a caller is allowed to see.
///
/// # Why this is a parameter and not a filter field
///
/// It started as `TicketFilter::school_org_sourced_ids` and was moved out,
/// because a filter field is a field a caller can forget. `TicketFilter`
/// derives `Default`, so every `..Default::default()` silently meant
/// "unrestricted" — a boundary that defaults to open is not a boundary, it is
/// a comment.
///
/// As a required argument to every listing method, omitting it does not
/// compile. [`Unrestricted`](Self::Unrestricted) still exists, but a caller has
/// to type it, which is the difference between a decision and an oversight.
///
/// It ANDs with whatever school the caller filtered on, so their own choice
/// narrows *within* the boundary and can never widen past it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketScope {
    /// The console admin, the CLI, a job — anyone acting for the district
    /// itself.
    Unrestricted,
    /// A scoped API token. An empty list is *no* schools rather than all of
    /// them: a grant that named nothing granted nothing.
    Schools(Vec<String>),
}

impl TicketScope {
    /// The schools to restrict to, or `None` for no restriction.
    pub fn schools(&self) -> Option<&[String]> {
        match self {
            Self::Unrestricted => None,
            Self::Schools(s) => Some(s),
        }
    }

    /// True when this scope can see nothing at all.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Schools(s) if s.is_empty())
    }
}

/// Columns a queue may be ordered by.
///
/// A closed enum because the value is interpolated into `ORDER BY`; it exists
/// so that string can never carry caller input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TicketSort {
    #[default]
    Number,
    CreatedAt,
    UpdatedAt,
    SlaDueAt,
    Priority,
    Status,
}

impl TicketSort {
    /// What to sort by, which is not always the column.
    ///
    /// `priority` and `status` are stored as words, and sorting words puts
    /// *low* above *normal* and *closed* above *open*. Both get a `CASE` over
    /// their rank instead. The literals come from the enums, never from user
    /// input, so this cannot carry anything injectable.
    pub fn order_expr(&self, alias: &str) -> String {
        match self {
            Self::Priority => case_rank(
                alias,
                "priority",
                TicketPriority::ALL
                    .iter()
                    .map(|p| (p.as_str(), p.severity_rank())),
            ),
            Self::Status => case_rank(
                alias,
                "status",
                TicketStatus::ALL
                    .iter()
                    .map(|s| (s.as_str(), s.workflow_rank())),
            ),
            other => format!("{alias}{}", other.as_sql_column()),
        }
    }

    pub fn as_sql_column(&self) -> &'static str {
        match self {
            Self::Number => "number",
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::SlaDueAt => "sla_due_at",
            Self::Priority => "priority",
            Self::Status => "status",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "number" => Self::Number,
            "created_at" => Self::CreatedAt,
            "updated_at" => Self::UpdatedAt,
            "sla_due_at" => Self::SlaDueAt,
            "priority" => Self::Priority,
            "status" => Self::Status,
            _ => return None,
        })
    }
}

/// `CASE col WHEN 'a' THEN 0 ... ELSE <n> END` — one expression both drivers
/// accept, built from the enum so a new variant cannot be left unranked and
/// silently sorted to the end.
fn case_rank<'a>(alias: &str, column: &str, ranks: impl Iterator<Item = (&'a str, i32)>) -> String {
    let mut out = format!("CASE {alias}{column}");
    let mut max = 0;
    for (value, rank) in ranks {
        out.push_str(&format!(" WHEN '{value}' THEN {rank}"));
        max = max.max(rank);
    }
    // A value the enum does not know about sorts last rather than first: an
    // unreadable row must not be the top of a triage queue.
    out.push_str(&format!(" ELSE {} END", max + 1));
    out
}

impl TicketFilter {
    /// The `ORDER BY` clause, optionally table-qualified.
    ///
    /// Lives here rather than in each driver so SQLite and Postgres cannot
    /// drift on column, direction or tiebreaker. `number` is the tiebreaker
    /// because it is unique and monotonic, which keeps paging stable.
    pub fn order_by_sql(&self, alias: &str) -> String {
        let dir = self.direction.as_sql();
        format!(
            "ORDER BY {} {dir}, {alias}number {dir}",
            self.sort.order_expr(alias)
        )
    }
}

/// A partial update to a ticket.
///
/// `None` means unchanged. Nullable columns use [`super::asset::Patch`] so a
/// deliberate clear is distinguishable from "leave it alone" — unassigning a
/// ticket and not mentioning the assignee must not be the same request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TicketPatch {
    pub status: Option<TicketStatus>,
    pub priority: Option<TicketPriority>,
    pub assignee_user_sourced_id: super::asset::Patch<String>,
    pub school_org_sourced_id: super::asset::Patch<String>,
    pub asset_id: super::asset::Patch<String>,
    pub category: super::asset::Patch<String>,
    pub subject: Option<String>,
    pub sla_due_at: super::asset::Patch<DateTime<Utc>>,
    pub first_response_at: super::asset::Patch<DateTime<Utc>>,
    pub resolved_at: super::asset::Patch<DateTime<Utc>>,
    pub closed_at: super::asset::Patch<DateTime<Utc>>,
}

#[cfg(test)]
mod tests;
