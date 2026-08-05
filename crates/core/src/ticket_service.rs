//! Raising a ticket, with the decisions that must not differ by who raised it.
//!
//! # Why this is not in the handler
//!
//! Three things will create tickets: an administrator logging a phone call, a
//! teacher in the portal, and inbound email. If each computes its own response
//! target and does its own device lookup, a district ends up with three
//! different SLAs depending on how the request arrived — and the one that
//! arrived by email, from the person least able to chase it, is the one that
//! gets the worst treatment. So the policy lives here and the surfaces only
//! collect input.
//!
//! # What the service does and does not own
//!
//! It owns the *derived* fields: the response target, and the device the
//! requester is holding. It does **not** own the ticket number — that is
//! allocated inside the insert transaction by the repository, because it has
//! to be unique under concurrent submissions and only the database can
//! promise that.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};

use crate::config::HelpdeskConfig;
use crate::db::repository::AssetRepository;
use crate::error::{ChalkError, Result};
use crate::models::asset::AssetFilter;
use crate::models::page::PageRequest;
use crate::models::ticket::{Ticket, TicketPriority, TicketSource};

/// The longest a subject may be. Long enough for a real sentence, short enough
/// that a queue row stays readable.
pub const MAX_SUBJECT: usize = 200;

/// The longest a description may be. Attachments carry the rest.
pub const MAX_BODY: usize = 20_000;

/// What a person actually supplies when raising a ticket.
///
/// Everything derived — number, response target, the attached device, the
/// timestamps — is absent by construction, so no caller can set them
/// inconsistently and none of them can be forgotten.
#[derive(Debug, Clone, Default)]
pub struct NewTicket {
    /// The roster user raising it, when there is one.
    pub requester_user_sourced_id: Option<String>,
    /// The address it came from, for a sender with no roster row.
    pub requester_email: Option<String>,
    pub subject: String,
    pub body: String,
    pub priority: TicketPriority,
    pub category: Option<String>,
    pub school_org_sourced_id: Option<String>,
    /// A device named explicitly. When absent the service may attach the
    /// requester's own — see [`HelpdeskConfig::attach_requester_device`].
    pub asset_id: Option<String>,
    pub source: TicketSource,
    pub email_message_id: Option<String>,
}

/// Why a ticket could not be raised, in words a form can show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewTicketError {
    NoRequester,
    EmptySubject,
    SubjectTooLong,
    BodyTooLong,
}

impl NewTicketError {
    /// Addressed to the person who typed it, saying what to do rather than
    /// what was violated.
    pub fn message(&self) -> String {
        match self {
            Self::NoRequester => {
                "A ticket needs somebody to answer. Choose a person or give an email address."
                    .into()
            }
            Self::EmptySubject => "Give the ticket a short subject.".into(),
            Self::SubjectTooLong => {
                format!("That subject is too long — keep it under {MAX_SUBJECT} characters.")
            }
            Self::BodyTooLong => {
                "That description is too long. Attach the detail as a file instead.".into()
            }
        }
    }
}

impl From<NewTicketError> for ChalkError {
    fn from(e: NewTicketError) -> Self {
        ChalkError::Validation(e.message())
    }
}

impl NewTicket {
    /// Reject what a form must not accept.
    ///
    /// A requester is required in *some* form. A ticket nobody can be answered
    /// to is not a ticket; it is a note, and it will sit in the queue being
    /// counted as work forever.
    pub fn validate(&self) -> std::result::Result<(), NewTicketError> {
        let has_requester = self
            .requester_user_sourced_id
            .as_ref()
            .is_some_and(|v| !v.trim().is_empty())
            || self
                .requester_email
                .as_ref()
                .is_some_and(|v| !v.trim().is_empty());
        if !has_requester {
            return Err(NewTicketError::NoRequester);
        }
        if self.subject.trim().is_empty() {
            return Err(NewTicketError::EmptySubject);
        }
        if self.subject.chars().count() > MAX_SUBJECT {
            return Err(NewTicketError::SubjectTooLong);
        }
        if self.body.chars().count() > MAX_BODY {
            return Err(NewTicketError::BodyTooLong);
        }
        Ok(())
    }
}

/// Turns what a person typed into a ticket the district can be held to.
pub struct TicketService {
    config: HelpdeskConfig,
    /// Absent when the device module is off. The helpdesk still works; it
    /// simply stops attaching devices, rather than refusing tickets.
    assets: Option<Arc<dyn AssetRepository>>,
}

impl TicketService {
    pub fn new(config: HelpdeskConfig, assets: Option<Arc<dyn AssetRepository>>) -> Self {
        Self { config, assets }
    }

    /// Build the ticket to insert. Does not touch the database except to look
    /// up the requester's device.
    ///
    /// `id` is supplied rather than generated so the caller controls
    /// idempotency — email ingestion needs to derive it from the `Message-ID`.
    pub async fn prepare(&self, id: impl Into<String>, new: NewTicket) -> Result<Ticket> {
        self.prepare_at(id, new, Utc::now()).await
    }

    /// `prepare` with the clock injected, so the response-target arithmetic is
    /// testable without sleeping or accepting "about right".
    pub async fn prepare_at(
        &self,
        id: impl Into<String>,
        new: NewTicket,
        now: DateTime<Utc>,
    ) -> Result<Ticket> {
        new.validate()?;

        let mut ticket = Ticket::new(id, new.subject.trim());
        ticket.body = new.body.trim().to_string();
        ticket.priority = new.priority;
        ticket.source = new.source;
        ticket.category = new.category.filter(|c| !c.trim().is_empty());
        ticket.email_message_id = new.email_message_id;
        ticket.created_at = now;
        ticket.updated_at = now;

        ticket.requester_user_sourced_id = new
            .requester_user_sourced_id
            .filter(|v| !v.trim().is_empty());
        ticket.requester_email = new
            .requester_email
            .map(|v| v.trim().to_lowercase())
            .filter(|v| !v.is_empty());

        ticket.sla_due_at = self
            .config
            .response_hours(new.priority)
            .map(|h| now + Duration::hours(h));

        ticket.asset_id = new.asset_id.filter(|v| !v.trim().is_empty());
        if ticket.asset_id.is_none() {
            ticket.asset_id = self
                .device_held_by(ticket.requester_user_sourced_id.as_deref())
                .await;
        }

        // The school comes from the device when the form did not say, because
        // a device knows which building it lives in and a requester may work
        // in several.
        ticket.school_org_sourced_id = new.school_org_sourced_id.filter(|v| !v.trim().is_empty());
        if ticket.school_org_sourced_id.is_none() {
            if let (Some(assets), Some(asset_id)) = (&self.assets, &ticket.asset_id) {
                if let Ok(Some(a)) = assets.get_asset(asset_id).await {
                    ticket.school_org_sourced_id = a.school_org_sourced_id;
                }
            }
        }

        Ok(ticket)
    }

    /// The device this requester is holding, if exactly one is known.
    ///
    /// Silent on ambiguity by design: a user assigned two devices gives no
    /// answer rather than an arbitrary one. Guessing here would put the wrong
    /// asset tag on a repair ticket, which is worse than leaving it blank for
    /// a technician to fill in — they can see both devices on the user's page.
    async fn device_held_by(&self, user: Option<&str>) -> Option<String> {
        if !self.config.attach_requester_device {
            return None;
        }
        let (assets, user) = (self.assets.as_ref()?, user?);

        let filter = AssetFilter {
            assigned_user_sourced_id: Some(user.to_string()),
            ..Default::default()
        };
        // Two is all the evidence needed to know it is ambiguous.
        let page = assets
            .list_assets(&filter, PageRequest::from_page_number(1, 2))
            .await
            .ok()?;
        match page.items.as_slice() {
            [only] => Some(only.id.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
