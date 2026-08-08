//! The technician queue and one ticket's thread (WS-4).
//!
//! # What this screen is for
//!
//! A technician opens it to answer one question: *what should I do next?* Every
//! choice here serves that. Breached tickets are called out because they are
//! the answer more often than not; unanswered ones are marked because a
//! district's first-response time is the number it is judged on; and the
//! device sits beside the requester because "Lisa's Chromebook" is how the
//! conversation actually goes.
//!
//! # Internal notes never leave IT
//!
//! The thread is fetched with `include_internal = true` here and would be
//! fetched with `false` for the requester's own portal. That distinction lives
//! in the repository's SQL rather than in a template condition, so a note
//! cannot leak by someone reordering a loop.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::console_user::Actor;
use chalk_core::models::page::SortDirection;
use chalk_core::models::ticket::{
    NewTicketComment, Ticket, TicketFilter, TicketPriority, TicketScope, TicketSort, TicketStatus,
};
use chrono::Utc;
use serde::Deserialize;

use crate::AppState;

pub const TICKETS_PATH: &str = "/tickets";

/// Shown as the author of anything the console posts.
///
/// The console's sign-in is one shared district password, so there is no
/// person to name. Saying "IT staff" is the truthful version of that; putting
/// a plausible name there would be a fabrication a district might later rely
/// on. See [`NewTicketComment::from_console`].
const CONSOLE_AUTHOR: &str = "IT staff";

/// The HTMX swap target, so a sort cannot leave the count describing the
/// previous view.
const REGION_ID: &str = "tickets-region";

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TicketsQuery {
    pub status: String,
    pub priority: String,
    pub assignee: String,
    /// A technician's console_user id — narrows to their queue. Distinct from
    /// `assignee` (the legacy roster field), and what the analytics page and a
    /// "my tickets" link point at.
    pub owner: String,
    /// `unassigned` narrows to tickets nobody has picked up.
    pub assigned: String,
    /// `1` narrows to overdue-and-still-actionable.
    pub breached: String,
    /// Narrows to tickets carrying this tag.
    pub tag: String,
    pub q: String,
    pub page: String,
    pub sort: String,
    pub dir: String,
    pub per_page: String,
}

fn non_empty(v: &str) -> Option<String> {
    let v = v.trim();
    (!v.is_empty()).then(|| v.to_string())
}

impl TicketsQuery {
    /// Unparseable values are dropped rather than rejected, so a hand-edited
    /// URL degrades to a wider view instead of a 400 — the same rule the
    /// device inventory follows.
    fn to_filter(&self) -> TicketFilter {
        TicketFilter {
            status: TicketStatus::parse(self.status.trim()).ok(),
            priority: TicketPriority::parse(self.priority.trim()).ok(),
            assignee_user_sourced_id: non_empty(&self.assignee),
            assignee_console_user_id: non_empty(&self.owner),
            tag: non_empty(&self.tag),
            unassigned: (self.assigned.trim() == "unassigned").then_some(true),
            breached_only: self.breached.trim() == "1",
            search: non_empty(&self.q),
            sort: self.sort_column(),
            direction: self.sort_direction(),
            ..Default::default()
        }
    }

    /// Newest first by default: a queue is read from the top, and the ticket
    /// that arrived while you were reading should be there when you look up.
    fn sort_column(&self) -> TicketSort {
        TicketSort::parse(self.sort.trim()).unwrap_or(TicketSort::Number)
    }

    fn sort_direction(&self) -> SortDirection {
        match self.dir.trim() {
            "asc" => SortDirection::Asc,
            _ => SortDirection::Desc,
        }
    }

    fn page_number(&self) -> i64 {
        self.page.trim().parse::<i64>().unwrap_or(1).max(1)
    }

    fn per_page(&self) -> i64 {
        crate::table::clamp_page_size(self.per_page.trim().parse::<i64>().ok())
    }

    /// The filter as URL pairs, so every sort link and page link carries the
    /// view the technician is actually looking at.
    fn filter_pairs(&self) -> Vec<(String, String)> {
        vec![
            ("q".to_string(), self.q.trim().to_string()),
            ("status".to_string(), self.status.trim().to_string()),
            ("priority".to_string(), self.priority.trim().to_string()),
            ("assignee".to_string(), self.assignee.trim().to_string()),
            ("owner".to_string(), self.owner.trim().to_string()),
            ("tag".to_string(), self.tag.trim().to_string()),
            ("assigned".to_string(), self.assigned.trim().to_string()),
            (
                "breached".to_string(),
                if self.breached.trim() == "1" {
                    "1".to_string()
                } else {
                    String::new()
                },
            ),
        ]
    }

    fn to_nav(&self, total: i64) -> crate::table::TableNav {
        crate::table::TableNav {
            base_path: TICKETS_PATH.to_string(),
            region_id: REGION_ID.to_string(),
            filter_pairs: self.filter_pairs(),
            sort: self.sort_column().as_sql_column().to_string(),
            direction: match self.sort_direction() {
                SortDirection::Desc => "desc".to_string(),
                SortDirection::Asc => "asc".to_string(),
            },
            page: self.page_number(),
            per_page: self.per_page(),
            total,
        }
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

pub struct TicketRowView {
    pub id: String,
    pub number: i64,
    pub subject: String,
    pub status_label: String,
    pub status_class: String,
    pub priority_label: String,
    pub priority_class: String,
    pub requester: String,
    pub assignee: String,
    pub age: String,
    /// Overdue and still actionable.
    pub breached: bool,
    /// Nobody has answered the requester yet.
    pub unanswered: bool,
    /// This ticket's tags, each a link to the queue filtered to it.
    pub tags: Vec<String>,
}

pub struct QueueView {
    pub rows: Vec<TicketRowView>,
    pub nav: crate::table::TableNav,
    pub query: TicketsQuery,
    pub breached_count: i64,
    pub unassigned_count: i64,
    pub open_count: i64,
    /// True on an HTMX swap: the fragment carries its own announcer, because
    /// a full page already has the permanent one from `base.html`.
    pub oob_announcer: bool,
    /// `(value, label, selected)` — built in Rust from the enum's `ALL` so a
    /// new status cannot be added without appearing in the filter.
    pub status_options: Vec<(String, String, bool)>,
    pub priority_options: Vec<(String, String, bool)>,
    /// `(value, label, selected)` — "Any" plus every tag in use. Empty when no
    /// ticket has been tagged, and the dropdown is not rendered.
    pub tag_options: Vec<(String, String, bool)>,
    /// Saved views: `(id, name, href)`.
    pub views: Vec<(String, String, String)>,
    /// The current filter serialized as a query string (no leading `?`), for
    /// the save-view form. Empty when nothing is filtered — an unfiltered
    /// queue is not worth naming.
    pub current_query: String,
    /// For the save-view and delete-view forms.
    pub csrf_token: String,
}

impl QueueView {
    pub fn has_rows(&self) -> bool {
        !self.rows.is_empty()
    }

    /// True when the queue is empty *because of a filter* rather than because
    /// there is no work. Telling a technician "no tickets yet" while a filter
    /// is active reads as data loss.
    pub fn is_filtered_empty(&self) -> bool {
        self.rows.is_empty() && self.has_filter()
    }

    pub fn has_filter(&self) -> bool {
        self.query.filter_pairs().iter().any(|(_, v)| !v.is_empty())
    }

    /// The dropdown only appears once at least one ticket is tagged.
    pub fn has_tag_options(&self) -> bool {
        self.tag_options.len() > 1
    }

    pub fn has_views(&self) -> bool {
        !self.views.is_empty()
    }

    /// A view is only worth saving when a filter is on.
    pub fn can_save_view(&self) -> bool {
        !self.current_query.is_empty()
    }

    /// Spoken after an HTMX swap, which is otherwise silent (§5.12).
    pub fn announcement(&self) -> String {
        format!("{}, {}", self.nav.range_summary(), self.sort_phrase())
    }

    fn sort_phrase(&self) -> String {
        format!(
            "sorted by {} {}",
            self.nav.sort.replace('_', " "),
            if self.nav.direction == "asc" {
                "ascending"
            } else {
                "descending"
            }
        )
    }

    pub fn caption(&self) -> String {
        format!(
            "Tickets, {}. Past-due and unanswered tickets are marked.",
            self.sort_phrase()
        )
    }
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "tickets/index.html")]
pub struct QueueTemplate {
    pub view: QueueView,
    pub nav: crate::nav::Nav,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "tickets/region.html")]
pub struct QueueRegionTemplate {
    pub view: QueueView,
}

pub struct CommentView {
    pub author: String,
    pub when: String,
    pub body: String,
    pub is_internal: bool,
}

pub struct FileView {
    pub id: String,
    pub filename: String,
    pub size: String,
    pub is_image: bool,
}

pub struct DetailView {
    pub id: String,
    pub number: i64,
    pub subject: String,
    pub body: String,
    pub status_label: String,
    pub status_class: String,
    pub priority_label: String,
    pub priority_class: String,
    pub requester: String,
    pub assignee: String,
    pub school: String,
    /// The device the ticket is about, and a link to it. This is the join the
    /// whole product argues for: a helpdesk that already knows the hardware.
    pub device: String,
    pub device_id: String,
    pub created: String,
    pub first_response: String,
    pub sla_due: String,
    pub breached: bool,
    pub resolution_due: String,
    pub resolution_breached: bool,
    pub comments: Vec<CommentView>,
    pub files: Vec<FileView>,
    pub status_options: Vec<(String, String, bool)>,
    /// `(value, label, selected)` — every priority, for the reclassify form.
    pub priority_options: Vec<(String, String, bool)>,
    /// The current category text, editable in the same form.
    pub category: String,
    /// This ticket's tags, each a link to the queue filtered to it.
    pub tags: Vec<String>,
    /// The same tags comma-joined, prefilling the edit box.
    pub tags_text: String,
    /// `(id, name, selected)` — "Unassigned" plus each active technician.
    pub assignee_options: Vec<(String, String, bool)>,
    /// The signed-in technician's own id, for the one-click "Claim" button.
    /// Empty for the shared-password admin, who has no account to claim under.
    pub claim_as: String,
    /// Saved reply templates `(title, body)` for the reply-box picker. Empty
    /// when the feature is not wired.
    pub canned: Vec<(String, String)>,
    pub csrf_token: String,
    pub flash: String,
}

impl DetailView {
    pub fn has_files(&self) -> bool {
        !self.files.is_empty()
    }

    pub fn has_device(&self) -> bool {
        !self.device_id.is_empty()
    }

    pub fn has_comments(&self) -> bool {
        !self.comments.is_empty()
    }

    /// Whether to show the one-click "Claim" button — only a real signed-in
    /// technician has an account to claim under.
    pub fn can_claim(&self) -> bool {
        !self.claim_as.is_empty()
    }

    pub fn has_canned(&self) -> bool {
        !self.canned.is_empty()
    }
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "tickets/detail.html")]
pub struct DetailTemplate {
    pub view: DetailView,
    pub nav: crate::nav::Nav,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /tickets`
pub async fn queue_page(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<TicketsQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_configured();
    };

    let filter = query.to_filter();
    // The console admin acts for the district, so the boundary is explicitly
    // unrestricted. Typing it is the point: `TicketScope` is a required
    // argument precisely so nobody omits it and gets this by accident.
    let scope = TicketScope::Unrestricted;

    let page = match tickets
        .list_tickets(&filter, &scope, query.to_nav(0).page_request())
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("could not list tickets: {e}");
            return load_failed();
        }
    };

    let now = Utc::now();
    let referenced: Vec<&Option<String>> = page
        .items
        .iter()
        .flat_map(|t| [&t.requester_user_sourced_id, &t.assignee_user_sourced_id])
        .collect();
    let names = roster_names(&state, &referenced).await;
    let tech_names = technician_names(&technicians(&state).await);
    // One query for every tag on this page of rows.
    let page_ids: Vec<String> = page.items.iter().map(|t| t.id.clone()).collect();
    let row_tags = tickets
        .get_tags_for_tickets(&page_ids)
        .await
        .unwrap_or_default();
    let rows: Vec<TicketRowView> = page
        .items
        .iter()
        .map(|t| row_view(t, &names, &tech_names, &row_tags, now))
        .collect();

    // The three counts a technician triages by, each over the whole queue
    // rather than the page — a badge that only described this page would be
    // worse than none.
    let breached_count = tickets
        .count_tickets(
            &TicketFilter {
                breached_only: true,
                ..Default::default()
            },
            &scope,
        )
        .await
        .unwrap_or(0);
    let unassigned_count = tickets
        .count_tickets(
            &TicketFilter {
                unassigned: Some(true),
                ..Default::default()
            },
            &scope,
        )
        .await
        .unwrap_or(0);
    let open_count = tickets
        .count_tickets(
            &TicketFilter {
                status: Some(TicketStatus::Open),
                ..Default::default()
            },
            &scope,
        )
        .await
        .unwrap_or(0);

    // Every tag in use, for the filter dropdown; the saved views bar; and the
    // current filter as a query string for the save form.
    let all_tags = tickets.list_all_tags().await.unwrap_or_default();
    let selected_tag = query.tag.trim();
    let mut tag_options = vec![(String::new(), "Any".to_string(), selected_tag.is_empty())];
    tag_options.extend(
        all_tags
            .iter()
            .map(|t| (t.clone(), t.clone(), t == selected_tag)),
    );
    let views: Vec<(String, String, String)> = match state.saved_views.as_ref() {
        Some(repo) => repo
            .list_saved_views()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|v| {
                let href = if v.query_string.is_empty() {
                    TICKETS_PATH.to_string()
                } else {
                    format!("{TICKETS_PATH}?{}", v.query_string)
                };
                (v.id, v.name, href)
            })
            .collect(),
        None => Vec::new(),
    };
    let current_query = query
        .filter_pairs()
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let view = QueueView {
        nav: query.to_nav(page.total),
        status_options: options(
            TicketStatus::ALL,
            |s| (s.as_str().to_string(), s.label().to_string()),
            &query.status,
        ),
        priority_options: options(
            TicketPriority::ALL,
            |p| (p.as_str().to_string(), p.label().to_string()),
            &query.priority,
        ),
        tag_options,
        views,
        current_query,
        csrf_token: csrf.0,
        oob_announcer: headers.get("HX-Request").is_some(),
        rows,
        query,
        breached_count,
        unassigned_count,
        open_count,
    };

    if view.oob_announcer {
        render(QueueRegionTemplate { view })
    } else {
        render(QueueTemplate {
            view,
            nav: crate::nav::Nav::new(&state.config, "tickets"),
        })
    }
}

/// "Any" plus every variant, marking the selected one. Generated from the
/// enum rather than typed into the template, so a new variant cannot be
/// filtered by URL but missing from the dropdown.
fn options<T: Copy>(
    all: &[T],
    describe: impl Fn(&T) -> (String, String),
    selected: &str,
) -> Vec<(String, String, bool)> {
    let mut out = vec![(String::new(), "Any".to_string(), selected.trim().is_empty())];
    out.extend(all.iter().map(|v| {
        let (value, label) = describe(v);
        let is_selected = value == selected.trim();
        (value, label, is_selected)
    }));
    out
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NoticeQuery {
    pub notice: String,
}

impl NoticeQuery {
    /// A closed set of codes rather than reflected text, so a crafted link
    /// cannot put arbitrary words on the page.
    fn message(&self) -> String {
        match self.notice.as_str() {
            "commented" => "Your reply was added.".to_string(),
            "noted" => "Internal note added. The requester cannot see it.".to_string(),
            "empty" => "Write something before posting.".to_string(),
            "status" => "Status updated.".to_string(),
            "reclassified" => "Priority and category updated.".to_string(),
            "tagged" => "Tags updated.".to_string(),
            "assigned" => "Ticket assigned.".to_string(),
            "unassigned" => "Ticket returned to the unassigned queue.".to_string(),
            "assign_unknown" => "That technician is not an active console user.".to_string(),
            "raised" => "Ticket raised.".to_string(),
            "file_empty" => "That file was empty — nothing was posted.".to_string(),
            "file_large" => "That file is too big. Files need to be under 6 MB.".to_string(),
            "file_many" => "You can attach up to 5 files at a time.".to_string(),
            "failed" => "That could not be saved. Check the server log.".to_string(),
            _ => String::new(),
        }
    }
}

/// `GET /tickets/{id}`
pub async fn ticket_detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(notice): Query<NoticeQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_configured();
    };
    let Ok(Some(ticket)) = tickets.get_ticket(&id).await else {
        return not_found();
    };
    let techs = technicians(&state).await;
    let tech_names = technician_names(&techs);
    let ticket_tags = tickets.get_ticket_tags(&id).await.unwrap_or_default();

    // `true`: this is the technician's view. The requester's portal will pass
    // `false`, and the filtering happens in SQL either way.
    let comments = tickets.list_comments(&id, true).await.unwrap_or_default();
    let files = tickets.list_attachments(&id).await.unwrap_or_default();
    let mut referenced: Vec<&Option<String>> = vec![
        &ticket.requester_user_sourced_id,
        &ticket.assignee_user_sourced_id,
    ];
    referenced.extend(comments.iter().map(|c| &c.author_user_sourced_id));
    let names = roster_names(&state, &referenced).await;
    let now = Utc::now();

    let device = match &ticket.asset_id {
        Some(asset_id) => match state.assets.as_ref() {
            Some(assets) => assets
                .get_asset(asset_id)
                .await
                .ok()
                .flatten()
                .map(|a| {
                    // The asset tag is what is written on the lid, so it is
                    // what a technician can act on. The serial is the fallback
                    // because it is at least readable off the device.
                    a.asset_tag
                        .or(a.serial_number)
                        .unwrap_or_else(|| "Unnamed device".to_string())
                })
                // `tickets.asset_id` is a foreign key with ON DELETE SET NULL,
                // so a dangling id is not representable at rest — this covers
                // only the window where the device is deleted between the two
                // reads.
                .unwrap_or_else(|| "Device no longer in the inventory".to_string()),
            // Helpdesk without the device module: the ticket still names an id
            // rather than pretending there is no device.
            None => format!("Device {asset_id}"),
        },
        None => String::new(),
    };

    render(DetailTemplate {
        view: DetailView {
            id: ticket.id.clone(),
            number: ticket.number,
            subject: ticket.subject.clone(),
            body: if ticket.body.trim().is_empty() {
                "No description was given.".to_string()
            } else {
                ticket.body.clone()
            },
            status_label: ticket.status.label().to_string(),
            status_class: status_class(ticket.status).to_string(),
            priority_label: ticket.priority.label().to_string(),
            priority_class: priority_class(ticket.priority).to_string(),
            requester: requester_name(&ticket, &names),
            assignee: ticket
                .assignee_console_user_id
                .as_ref()
                .map(|id| display_name(id, &tech_names))
                .unwrap_or_else(|| "Nobody yet".to_string()),
            school: ticket
                .school_org_sourced_id
                .as_ref()
                .map(|id| display_name(id, &names))
                .unwrap_or_else(|| "—".to_string()),
            device_id: ticket.asset_id.clone().unwrap_or_default(),
            device,
            created: ticket.created_at.format("%Y-%m-%d %H:%M").to_string(),
            first_response: ticket
                .first_response_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Nobody has answered yet".to_string()),
            sla_due: ticket
                .sla_due_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "No target set".to_string()),
            breached: ticket.is_breached(now),
            resolution_due: ticket
                .resolution_due_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "No target set".to_string()),
            resolution_breached: ticket.is_resolution_breached(now),
            comments: comments
                .iter()
                .map(|c| CommentView {
                    author: c
                        .author_user_sourced_id
                        .as_ref()
                        .map(|id| display_name(id, &names))
                        .or_else(|| c.author_email.clone())
                        .unwrap_or_else(|| CONSOLE_AUTHOR.to_string()),
                    when: c.created_at.format("%Y-%m-%d %H:%M").to_string(),
                    body: c.body.clone(),
                    is_internal: c.is_internal,
                })
                .collect(),
            files: files
                .iter()
                .map(|a| FileView {
                    id: a.id.clone(),
                    filename: a.filename.clone(),
                    size: crate::help::human_size(a.size_bytes),
                    is_image: a.content_type.starts_with("image/"),
                })
                .collect(),
            status_options: TicketStatus::ALL
                .iter()
                .map(|s| {
                    (
                        s.as_str().to_string(),
                        s.label().to_string(),
                        *s == ticket.status,
                    )
                })
                .collect(),
            priority_options: TicketPriority::ALL
                .iter()
                .map(|p| {
                    (
                        p.as_str().to_string(),
                        p.label().to_string(),
                        *p == ticket.priority,
                    )
                })
                .collect(),
            category: ticket.category.clone().unwrap_or_default(),
            tags_text: ticket_tags.join(", "),
            tags: ticket_tags,
            assignee_options: assignee_options(&techs, ticket.assignee_console_user_id.as_deref()),
            claim_as: actor.console_user_id().unwrap_or("").to_string(),
            canned: crate::canned::canned_options(&state)
                .await
                .into_iter()
                .map(|c| (c.title, c.body))
                .collect(),
            csrf_token: csrf.0,
            flash: notice.message(),
        },
        nav: crate::nav::Nav::new(&state.config, "tickets"),
    })
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CommentForm {
    pub body: String,
    /// `"1"` posts an internal note instead of a visible reply.
    pub internal: String,
}

/// `POST /tickets/{id}/comment`
pub async fn add_comment(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    multipart: axum::extract::Multipart,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_configured();
    };

    let (fields, files) = match crate::ticket_files::read_multipart(multipart).await {
        Ok(v) => v,
        Err(e) => return crate::ticket_files::upload_refused(&id, TICKETS_PATH, e),
    };
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.trim())
            .unwrap_or_default()
    };

    let body = field("body").to_string();
    let internal = field("internal") == "1";

    // A file with no words is still a message — a photograph of what was found
    // says more than "see attached" would. Refuse only when there is nothing.
    if body.is_empty() && files.is_empty() {
        return back(&id, "empty");
    }
    let text = if body.is_empty() {
        match files.len() {
            1 => "Attached a file.".to_string(),
            n => format!("Attached {n} files."),
        }
    } else {
        body
    };

    let comment = NewTicketComment::from_console(&id, None, &text);
    let comment = if internal {
        comment.internal()
    } else {
        comment
    };

    match tickets.append_comment(&comment).await {
        Ok(saved) => {
            crate::ticket_files::store_all(&state, &id, Some(saved.id), files).await;
            // A public reply is the one the requester is waiting for, so tell
            // them. An internal note is for the technicians and must never
            // leave the console. Best-effort: the reply already succeeded, and
            // a mail hiccup must not undo it.
            if !internal {
                notify_requester_of_reply(&state, &id, &text).await;
            }
            back(&id, if internal { "noted" } else { "commented" })
        }
        Err(e) => {
            tracing::error!("could not comment on ticket {id}: {e}");
            back(&id, "failed")
        }
    }
}

/// Email the requester that IT has replied, if the deployment can send mail.
///
/// This is the first thing the generalized [`Notifier`](chalk_core::mail::Notifier)
/// carries beyond a sign-in link, and it closes the "help desk is inbound-only"
/// gap: until now a technician's reply lived only in the console and the
/// requester had no way to know it existed.
///
/// The subject carries `[#N]`, so when the requester replies by email the
/// existing inbound webhook threads it back onto the same ticket — the loop
/// closes without a special reply-to address. Entirely best-effort: no mailer,
/// no `public_url`, or no requester address just means no email, never a failed
/// reply.
async fn notify_requester_of_reply(state: &Arc<AppState>, ticket_id: &str, reply_text: &str) {
    let Some(mailer) = state.mailer.clone() else {
        return;
    };
    let Some(base) = state.config.chalk.absolute_url_base() else {
        tracing::debug!("no public_url; skipping ticket-reply email");
        return;
    };
    let Some(tickets) = state.tickets.clone() else {
        return;
    };
    let Ok(Some(ticket)) = tickets.get_ticket(ticket_id).await else {
        return;
    };

    // The requester's address: the one on the ticket (an email-raised ticket
    // carries it directly), else the roster user's.
    let to = match ticket.requester_email.as_deref() {
        Some(e) if !e.is_empty() => e.to_string(),
        _ => match &ticket.requester_user_sourced_id {
            Some(sid) => match state.repo.get_user(sid).await {
                Ok(Some(u)) => u.email.unwrap_or_default(),
                _ => String::new(),
            },
            None => String::new(),
        },
    };
    if to.is_empty() {
        tracing::debug!("ticket {ticket_id} has no requester email; skipping reply notification");
        return;
    }

    let subject = format!("[#{}] {}", ticket.number, ticket.subject);
    let body = format!(
        "IT Help replied to your request:\n\n{reply_text}\n\n\
         ----\n\
         View the full conversation and reply here:\n{base}{TICKETS_PATH_PORTAL}/{ticket_id}\n\n\
         You can also just reply to this email.\n"
    );
    if let Err(e) = mailer
        .send_email(&chalk_core::mail::EmailMessage::new(to, subject, body))
        .await
    {
        tracing::warn!("could not email ticket-reply notification for {ticket_id}: {e}");
    }
}

/// The requester-facing portal path (their view of a ticket), distinct from the
/// technician `/tickets` surface.
const TICKETS_PATH_PORTAL: &str = "/help";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct StatusForm {
    pub status: String,
}

/// `POST /tickets/{id}/status`
pub async fn set_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<StatusForm>,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_configured();
    };
    let Ok(status) = TicketStatus::parse(form.status.trim()) else {
        return back(&id, "failed");
    };

    // Resolving stamps the time, because "when was this fixed" is asked far
    // more often than it is recorded, and asking a technician to type it is
    // asking for it to be wrong.
    let now = Utc::now();
    let patch = chalk_core::models::ticket::TicketPatch {
        status: Some(status),
        resolved_at: match status {
            TicketStatus::Resolved => chalk_core::models::asset::Patch::Set(now),
            // Reopening clears it: a ticket that is open again was not
            // resolved, and leaving the stamp would make the report lie.
            TicketStatus::Open | TicketStatus::InProgress | TicketStatus::Waiting => {
                chalk_core::models::asset::Patch::Clear
            }
            TicketStatus::Closed => chalk_core::models::asset::Patch::Unchanged,
        },
        closed_at: match status {
            TicketStatus::Closed => chalk_core::models::asset::Patch::Set(now),
            TicketStatus::Resolved => chalk_core::models::asset::Patch::Unchanged,
            _ => chalk_core::models::asset::Patch::Clear,
        },
        ..Default::default()
    };

    match tickets.update_ticket(&id, &patch).await {
        Ok(true) => {
            // Resolving asks the requester how it went — once per ticket, and
            // only when a mailer, a public URL and an address all exist.
            // `send_survey_on_resolve` checks all of that itself.
            if status == TicketStatus::Resolved {
                crate::csat::send_survey_on_resolve(&state, &id).await;
            }
            back(&id, "status")
        }
        Ok(false) => not_found(),
        Err(e) => {
            tracing::error!("could not set status on ticket {id}: {e}");
            back(&id, "failed")
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AssignForm {
    /// A technician's console_user id, or empty to unassign.
    pub assignee: String,
}

/// `POST /tickets/{id}/assign`
///
/// The assignee is a console_user (F1 technician), not a roster user — the
/// person who works the ticket has an account in the console, not a row in the
/// SIS. An empty value releases the ticket back to the unassigned queue.
pub async fn assign(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<AssignForm>,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_configured();
    };
    let chosen = form.assignee.trim();

    // A named assignee must be a real, active technician. This rejects both a
    // stale id (the account was deleted) and a crafted one, and it is why the
    // FK alone is not enough: a suspended tech still satisfies the FK.
    let (patch_value, notice) = if chosen.is_empty() {
        (chalk_core::models::asset::Patch::Clear, "unassigned")
    } else {
        let is_active_tech = technicians(&state)
            .await
            .iter()
            .any(|u| u.id == chosen && u.is_active());
        if !is_active_tech {
            return back(&id, "assign_unknown");
        }
        (
            chalk_core::models::asset::Patch::Set(chosen.to_string()),
            "assigned",
        )
    };

    let patch = chalk_core::models::ticket::TicketPatch {
        assignee_console_user_id: patch_value,
        ..Default::default()
    };
    match tickets.update_ticket(&id, &patch).await {
        Ok(true) => back(&id, notice),
        Ok(false) => not_found(),
        Err(e) => {
            tracing::error!("could not assign ticket {id}: {e}");
            back(&id, "failed")
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ReclassifyForm {
    pub priority: String,
    /// Freeform; empty clears it.
    pub category: String,
}

/// `POST /tickets/{id}/reclassify`
///
/// Change a ticket's priority and category after it was raised. The important
/// part is the SLA: the response target was computed once at creation from the
/// priority then, and nothing recomputed it — so bumping a ticket to Urgent
/// left its deadline at the relaxed Normal value, and the breach badge lied.
/// Here a priority change recomputes `sla_due_at` from the ticket's *original*
/// arrival time (the clock started when it came in, not when it was
/// reclassified).
pub async fn reclassify(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<ReclassifyForm>,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_configured();
    };
    let Ok(priority) = TicketPriority::parse(form.priority.trim()) else {
        return back(&id, "failed");
    };
    let Ok(Some(ticket)) = tickets.get_ticket(&id).await else {
        return not_found();
    };

    let category = form.category.trim();
    let mut patch = chalk_core::models::ticket::TicketPatch {
        priority: Some(priority),
        category: if category.is_empty() {
            chalk_core::models::asset::Patch::Clear
        } else {
            chalk_core::models::asset::Patch::Set(category.to_string())
        },
        ..Default::default()
    };

    // Recompute the deadline only when the priority actually moved, so editing
    // the category alone never disturbs an existing target. Anchored to
    // `created_at`, because the first-response clock has been running since the
    // ticket arrived.
    if priority != ticket.priority {
        patch.sla_due_at = match state.config.helpdesk.response_hours(priority) {
            Some(h) => chalk_core::models::asset::Patch::Set(
                ticket.created_at + chrono::Duration::hours(h),
            ),
            None => chalk_core::models::asset::Patch::Clear,
        };
        patch.resolution_due_at = match state.config.helpdesk.resolution_hours(priority) {
            Some(h) => chalk_core::models::asset::Patch::Set(
                ticket.created_at + chrono::Duration::hours(h),
            ),
            None => chalk_core::models::asset::Patch::Clear,
        };
    }

    match tickets.update_ticket(&id, &patch).await {
        Ok(true) => back(&id, "reclassified"),
        Ok(false) => not_found(),
        Err(e) => {
            tracing::error!("could not reclassify ticket {id}: {e}");
            back(&id, "failed")
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TagsForm {
    /// Comma-separated; the repository normalizes (trim, lowercase, dedup).
    pub tags: String,
}

/// `POST /tickets/{id}/tags` — replace the ticket's tags with the submitted
/// set. An empty box clears them all, which is what an empty box says.
pub async fn set_tags(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<TagsForm>,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_configured();
    };
    // The ticket must exist — tagging nothing should say so rather than
    // silently writing rows the FK would reject.
    match tickets.get_ticket(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!("could not load ticket {id} for tagging: {e}");
            return back(&id, "failed");
        }
    }
    let tags: Vec<String> = form.tags.split(',').map(str::to_string).collect();
    match tickets.set_ticket_tags(&id, &tags).await {
        Ok(()) => back(&id, "tagged"),
        Err(e) => {
            tracing::error!("could not tag ticket {id}: {e}");
            back(&id, "failed")
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SaveViewForm {
    pub name: String,
    /// The queue's current filter, serialized by the queue itself.
    pub query: String,
}

/// `POST /tickets/views` — save the current filter as a named view.
pub async fn save_view(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<SaveViewForm>,
) -> Response {
    let Some(views) = state.saved_views.clone() else {
        return not_configured();
    };
    let name = form.name.trim();
    let query = form.query.trim().trim_start_matches('?');
    if name.is_empty() || query.is_empty() {
        // Nothing filtered is nothing worth naming; send them back unchanged.
        return Redirect::to(TICKETS_PATH).into_response();
    }
    let view = chalk_core::models::saved_view::SavedView::new(
        uuid::Uuid::new_v4().to_string(),
        name,
        query,
    );
    match views.create_saved_view(&view).await {
        // Land on the view just saved, so the save visibly took.
        Ok(()) => Redirect::to(&format!("{TICKETS_PATH}?{query}")).into_response(),
        Err(e) => {
            tracing::error!("could not save view: {e}");
            Redirect::to(TICKETS_PATH).into_response()
        }
    }
}

/// `POST /tickets/views/{id}/delete`
pub async fn delete_view(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(views) = state.saved_views.clone() else {
        return not_configured();
    };
    if let Err(e) = views.delete_saved_view(&id).await {
        tracing::error!("could not delete view {id}: {e}");
    }
    Redirect::to(TICKETS_PATH).into_response()
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn row_view(
    t: &Ticket,
    names: &[(String, String)],
    tech_names: &[(String, String)],
    row_tags: &[(String, String)],
    now: chrono::DateTime<Utc>,
) -> TicketRowView {
    TicketRowView {
        id: t.id.clone(),
        number: t.number,
        subject: t.subject.clone(),
        status_label: t.status.label().to_string(),
        status_class: status_class(t.status).to_string(),
        priority_label: t.priority.label().to_string(),
        priority_class: priority_class(t.priority).to_string(),
        requester: requester_name(t, names),
        assignee: t
            .assignee_console_user_id
            .as_ref()
            .map(|id| display_name(id, tech_names))
            .unwrap_or_else(|| "—".to_string()),
        age: humanise_age(now - t.created_at),
        breached: t.is_breached(now),
        unanswered: t.awaiting_first_response(),
        tags: row_tags
            .iter()
            .filter(|(id, _)| *id == t.id)
            .map(|(_, tag)| tag.clone())
            .collect(),
    }
}

/// "3d", "4h", "12m" — a technician reads age as a rough magnitude, and a
/// timestamp makes them do the subtraction.
fn humanise_age(d: chrono::Duration) -> String {
    let mins = d.num_minutes().max(0);
    if mins < 60 {
        format!("{mins}m")
    } else if mins < 60 * 24 {
        format!("{}h", mins / 60)
    } else {
        format!("{}d", mins / (60 * 24))
    }
}

fn requester_name(t: &Ticket, names: &[(String, String)]) -> String {
    t.requester_user_sourced_id
        .as_ref()
        .map(|id| display_name(id, names))
        // An email-sourced ticket from someone with no roster row still has a
        // person behind it, and the address is who they are.
        .or_else(|| t.requester_email.clone())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn display_name(id: &str, names: &[(String, String)]) -> String {
    names
        .iter()
        .find(|(sid, _)| sid == id)
        .map(|(_, n)| n.clone())
        // Named rather than blanked: a row nobody can chase is worse than an
        // ugly one.
        .unwrap_or_else(|| id.to_string())
}

/// Every console user (technician), for both resolving an assignee's name and
/// populating the assign dropdown. Empty when the module is not wired — a
/// self-host that never created console users simply cannot assign, which is
/// the same "Nobody yet" it saw before.
///
/// The list is inherently small (a district has a handful of IT staff), so one
/// query is right — unlike the roster, which must be looked up per-id.
async fn technicians(state: &Arc<AppState>) -> Vec<chalk_core::models::console_user::ConsoleUser> {
    match state.console_users.as_ref() {
        Some(repo) => repo.list_console_users().await.unwrap_or_default(),
        None => Vec::new(),
    }
}

/// `(id, display_name)` for name resolution, over *all* technicians — a ticket
/// assigned to someone since suspended must still show their name.
fn technician_names(
    techs: &[chalk_core::models::console_user::ConsoleUser],
) -> Vec<(String, String)> {
    techs
        .iter()
        .map(|u| (u.id.clone(), u.display_name.clone()))
        .collect()
}

/// The assign dropdown: "Unassigned" plus every *active* technician, marking
/// the current assignee. A suspended tech is not offered — you cannot hand a
/// ticket to an account that can no longer sign in.
fn assignee_options(
    techs: &[chalk_core::models::console_user::ConsoleUser],
    current: Option<&str>,
) -> Vec<(String, String, bool)> {
    let mut out = vec![(String::new(), "Unassigned".to_string(), current.is_none())];
    out.extend(techs.iter().filter(|u| u.is_active()).map(|u| {
        (
            u.id.clone(),
            u.display_name.clone(),
            current == Some(u.id.as_str()),
        )
    }));
    out
}

/// Display names for exactly the people and schools named on this page.
///
/// Deliberately **not** `list_users(&Default::default())`. A district with
/// twenty thousand roster users would load all twenty thousand to label fifty
/// rows — the same mistake `users_list` makes and the reason a paginated table
/// can still be O(district). One page names at most a couple of dozen distinct
/// people, so it is a couple of dozen lookups.
///
/// Schools are a different case: a district has tens of them, `list_orgs` is
/// already cached-shaped, and every ticket has one — so one query beats N.
async fn roster_names(state: &Arc<AppState>, ids: &[&Option<String>]) -> Vec<(String, String)> {
    let mut wanted: Vec<&str> = ids
        .iter()
        .filter_map(|id| id.as_deref())
        .filter(|id| !id.is_empty())
        .collect();
    wanted.sort_unstable();
    wanted.dedup();

    let mut out: Vec<(String, String)> = Vec::with_capacity(wanted.len());
    for id in wanted {
        if let Ok(Some(u)) = state.repo.get_user(id).await {
            out.push((u.sourced_id, format!("{}, {}", u.family_name, u.given_name)));
        }
    }
    out.extend(
        state
            .repo
            .list_orgs()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|o| (o.sourced_id, o.name)),
    );
    out
}

pub(crate) fn status_class(s: TicketStatus) -> &'static str {
    match s {
        TicketStatus::Open => "badge badge--info",
        TicketStatus::InProgress => "badge badge--warning",
        TicketStatus::Waiting => "badge badge--neutral",
        TicketStatus::Resolved => "badge badge--success",
        TicketStatus::Closed => "badge badge--neutral",
    }
}

fn priority_class(p: TicketPriority) -> &'static str {
    match p {
        TicketPriority::Low => "badge badge--neutral",
        TicketPriority::Normal => "badge badge--neutral",
        TicketPriority::High => "badge badge--warning",
        TicketPriority::Urgent => "badge badge--danger",
    }
}

fn back(id: &str, code: &str) -> Response {
    Redirect::to(&format!("{TICKETS_PATH}/{id}?notice={code}")).into_response()
}

// ---------------------------------------------------------------------------
// Analytics
// ---------------------------------------------------------------------------

pub const ANALYTICS_PATH: &str = "/tickets/analytics";

/// One count with a label, a badge class, and the queue link that produced it.
pub struct MetricRow {
    pub label: String,
    pub class: String,
    pub count: i64,
    pub href: String,
}

/// A technician's current workload. `breached` is the subset of `total` that is
/// overdue and still actionable — the number that says who needs help.
pub struct TechRow {
    pub name: String,
    pub total: i64,
    pub breached: i64,
    pub href: String,
}

pub struct SchoolTicketRow {
    pub name: String,
    pub total: i64,
    pub href: String,
}

pub struct AnalyticsView {
    pub total: i64,
    pub unassigned: i64,
    pub unassigned_href: String,
    pub breached: i64,
    pub breached_href: String,
    pub by_status: Vec<MetricRow>,
    pub by_priority: Vec<MetricRow>,
    pub technicians: Vec<TechRow>,
    pub schools: Vec<SchoolTicketRow>,
    /// Surveys sent since CSAT went live.
    pub csat_sent: i64,
    pub csat_responded: i64,
    /// "4.6 / 5", or empty when nothing has been answered — an absent average
    /// is honest where "0.0" would read as catastrophe.
    pub csat_average: String,
}

impl AnalyticsView {
    pub fn has_technicians(&self) -> bool {
        !self.technicians.is_empty()
    }
    pub fn has_schools(&self) -> bool {
        !self.schools.is_empty()
    }
    pub fn has_csat(&self) -> bool {
        self.csat_sent > 0
    }
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "tickets/analytics.html")]
pub struct AnalyticsTemplate {
    pub view: AnalyticsView,
    pub nav: crate::nav::Nav,
}

/// A queue link carrying the given filter pairs, empty values dropped.
fn queue_href(pairs: &[(&str, &str)]) -> String {
    let q: Vec<String> = pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    if q.is_empty() {
        TICKETS_PATH.to_string()
    } else {
        format!("{TICKETS_PATH}?{}", q.join("&"))
    }
}

/// `GET /tickets/analytics`
///
/// The counts a help-desk lead triages a team by: volume by status and
/// priority, the backlog that is unassigned or breached, per-technician
/// workload (which F1 identity and assignment finally make real), and volume by
/// school. Every number links to the queue filtered to exactly it — a count you
/// cannot open is trivia.
///
/// Deliberately counts rather than averages: resolution-time aggregates need a
/// query the repository does not expose yet, and a wrong average is worse than
/// an absent one. Those arrive when the aggregate does.
pub async fn analytics_page(State(state): State<Arc<AppState>>) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_configured();
    };
    let scope = TicketScope::Unrestricted;

    let count = |filter: TicketFilter| {
        let tickets = tickets.clone();
        let scope = scope.clone();
        async move { tickets.count_tickets(&filter, &scope).await.unwrap_or(0) }
    };

    let total = count(TicketFilter::default()).await;
    let unassigned = count(TicketFilter {
        unassigned: Some(true),
        ..Default::default()
    })
    .await;
    let breached = count(TicketFilter {
        breached_only: true,
        ..Default::default()
    })
    .await;

    let mut by_status = Vec::new();
    for s in TicketStatus::ALL {
        by_status.push(MetricRow {
            label: s.label().to_string(),
            class: status_class(*s).to_string(),
            count: count(TicketFilter {
                status: Some(*s),
                ..Default::default()
            })
            .await,
            href: queue_href(&[("status", s.as_str())]),
        });
    }

    let mut by_priority = Vec::new();
    for p in TicketPriority::ALL {
        by_priority.push(MetricRow {
            label: p.label().to_string(),
            class: priority_class(*p).to_string(),
            count: count(TicketFilter {
                priority: Some(*p),
                ..Default::default()
            })
            .await,
            href: queue_href(&[("priority", p.as_str())]),
        });
    }

    // Per-technician workload. Only technicians who actually hold tickets are
    // listed — a roster of idle accounts is noise on a triage page.
    let mut tech_rows = Vec::new();
    for u in technicians_active_first(&technicians(&state).await) {
        let total = count(TicketFilter {
            assignee_console_user_id: Some(u.id.clone()),
            ..Default::default()
        })
        .await;
        if total == 0 {
            continue;
        }
        let breached = count(TicketFilter {
            assignee_console_user_id: Some(u.id.clone()),
            breached_only: true,
            ..Default::default()
        })
        .await;
        tech_rows.push(TechRow {
            name: u.display_name.clone(),
            total,
            breached,
            href: queue_href(&[("owner", &u.id)]),
        });
    }

    // Volume by school. Iterating schools is one query each, but a district has
    // tens of schools, not thousands — the same shape `reports.rs` uses.
    let mut schools = Vec::new();
    for (id, name) in school_names(&state).await {
        let total = count(TicketFilter {
            school_org_sourced_id: Some(id.clone()),
            ..Default::default()
        })
        .await;
        if total == 0 {
            continue;
        }
        schools.push(SchoolTicketRow {
            name,
            total,
            href: queue_href(&[("school", &id)]),
        });
    }
    schools.sort_by_key(|s| std::cmp::Reverse(s.total));

    // CSAT: sent/answered/average. Absent repository shows as zero sent, and
    // the card stays hidden.
    let csat_stats = match state.csat.as_ref() {
        Some(repo) => repo.csat_stats().await.ok(),
        None => None,
    };
    let (csat_sent, csat_responded, csat_average) = match csat_stats {
        Some(s) => (
            s.sent,
            s.responded,
            s.average.map(|a| format!("{a:.1} / 5")).unwrap_or_default(),
        ),
        None => (0, 0, String::new()),
    };

    render(AnalyticsTemplate {
        view: AnalyticsView {
            total,
            unassigned,
            unassigned_href: queue_href(&[("assigned", "unassigned")]),
            breached,
            breached_href: queue_href(&[("breached", "1")]),
            by_status,
            by_priority,
            technicians: tech_rows,
            schools,
            csat_sent,
            csat_responded,
            csat_average,
        },
        nav: crate::nav::Nav::new(&state.config, "tickets"),
    })
}

/// Active accounts first, then the rest — a suspended tech may still hold
/// tickets that need reassigning, so they are shown, just lower.
fn technicians_active_first(
    techs: &[chalk_core::models::console_user::ConsoleUser],
) -> Vec<chalk_core::models::console_user::ConsoleUser> {
    let mut out = techs.to_vec();
    out.sort_by_key(|u| !u.is_active());
    out
}

/// `(sourced_id, name)` for every school, so the report reads in names.
async fn school_names(state: &Arc<AppState>) -> Vec<(String, String)> {
    state
        .repo
        .list_orgs()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|o| matches!(o.org_type, chalk_core::models::common::OrgType::School))
        .map(|o| (o.sourced_id, o.name))
        .collect()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!("ticket render failed: {e}");
            load_failed()
        }
    }
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Helpdesk</h1><p>Tickets are not enabled here.</p>".to_string()),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html(
            "<h1>No such ticket</h1><p><a href=\"/tickets\">Back to the queue</a></p>".to_string(),
        ),
    )
        .into_response()
}

fn load_failed() -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Html("<h1>Helpdesk</h1><p>The queue could not be loaded.</p>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Raising a ticket
// ---------------------------------------------------------------------------

/// Candidates offered by the requester picker. Small on purpose — a technician
/// types enough of a name to find one person, not to browse a district.
const REQUESTER_PICKER_LIMIT: i64 = 20;

pub struct RequesterOption {
    pub sourced_id: String,
    pub name: String,
    pub email: String,
    pub selected: bool,
}

pub struct NewTicketView {
    pub subject: String,
    pub body: String,
    pub requester: String,
    pub requester_email: String,
    pub priority: String,
    pub category: String,
    pub search: String,
    pub candidates: Vec<RequesterOption>,
    pub searched: bool,
    pub priority_options: Vec<(String, String, bool)>,
    /// What the district's own config promises for the chosen priority, said
    /// before the ticket is raised rather than discovered afterwards.
    pub target_note: String,
    pub attaches_device: bool,
    pub error: String,
    pub csrf_token: String,
}

impl NewTicketView {
    pub fn has_candidates(&self) -> bool {
        !self.candidates.is_empty()
    }

    pub fn has_error(&self) -> bool {
        !self.error.is_empty()
    }
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "tickets/new.html")]
pub struct NewTicketTemplate {
    pub view: NewTicketView,
    pub nav: crate::nav::Nav,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewTicketForm {
    pub subject: String,
    pub body: String,
    /// Roster `sourced_id` chosen from the picker.
    pub requester: String,
    /// Free-text address, for somebody with no roster row.
    pub requester_email: String,
    pub priority: String,
    pub category: String,
    /// The picker's search box. Present on a GET too.
    pub q: String,
    /// Echoed back when the form is re-rendered after a refusal.
    ///
    /// The middleware attaches a `CsrfToken` extension on GET only, so a POST
    /// handler cannot extract one — and minting a fresh token here would not
    /// match the cookie the browser already holds, making the corrected
    /// resubmission fail with a CSRF error the user cannot act on. The token
    /// that arrived is the one that is still valid.
    pub csrf_token: String,
}

/// `GET /tickets/new`
pub async fn new_ticket_page(
    State(state): State<Arc<AppState>>,
    Query(mut form): Query<NewTicketForm>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    if state.tickets.is_none() {
        return not_configured();
    }
    form.csrf_token = csrf.0;
    render(NewTicketTemplate {
        view: build_new_view(&state, &form, String::new()).await,
        nav: crate::nav::Nav::new(&state.config, "tickets"),
    })
}

/// `POST /tickets/new`
pub async fn create_ticket(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<NewTicketForm>,
) -> Response {
    let Some(tickets) = state.tickets.clone() else {
        return not_configured();
    };

    let service = state.ticket_service();
    let new = chalk_core::ticket_service::NewTicket {
        requester_user_sourced_id: non_empty(&form.requester),
        requester_email: non_empty(&form.requester_email),
        subject: form.subject.clone(),
        body: form.body.clone(),
        priority: TicketPriority::parse(form.priority.trim()).unwrap_or_default(),
        category: non_empty(&form.category),
        school_org_sourced_id: None,
        asset_id: None,
        source: chalk_core::models::ticket::TicketSource::Portal,
        email_message_id: None,
    };

    let prepared = match service.prepare(uuid::Uuid::new_v4().to_string(), new).await {
        Ok(t) => t,
        // Re-render the form with what they typed still in it. Redirecting to
        // an empty form and a banner would throw away the description, which
        // is the part that took effort to write.
        Err(chalk_core::error::ChalkError::Validation(message)) => {
            return render(NewTicketTemplate {
                view: build_new_view(&state, &form, message).await,
                nav: crate::nav::Nav::new(&state.config, "tickets"),
            });
        }
        Err(e) => {
            tracing::error!("could not prepare ticket: {e}");
            return load_failed();
        }
    };

    match tickets.create_ticket(&prepared).await {
        // Straight to the ticket, not back to the queue: whoever raised it is
        // about to work on it or hand it over, and both need the number.
        Ok(t) => Redirect::to(&format!("{TICKETS_PATH}/{}?notice=raised", t.id)).into_response(),
        Err(e) => {
            tracing::error!("could not create ticket: {e}");
            render(NewTicketTemplate {
                view: build_new_view(
                    &state,
                    &form,
                    "That could not be saved. Check the server log.".to_string(),
                )
                .await,
                nav: crate::nav::Nav::new(&state.config, "tickets"),
            })
        }
    }
}

async fn build_new_view(
    state: &Arc<AppState>,
    form: &NewTicketForm,
    error: String,
) -> NewTicketView {
    let term = form.q.trim().to_string();
    let mut candidates: Vec<RequesterOption> = Vec::new();
    if !term.is_empty() {
        match state
            .repo
            .list_users(&chalk_core::models::sync::UserFilter::search(
                &term,
                REQUESTER_PICKER_LIMIT,
            ))
            .await
        {
            Ok(users) => {
                candidates = users
                    .iter()
                    .map(|u| RequesterOption {
                        selected: u.sourced_id == form.requester.trim(),
                        sourced_id: u.sourced_id.clone(),
                        name: format!("{}, {}", u.family_name, u.given_name),
                        email: u.email.clone().unwrap_or_default(),
                    })
                    .collect()
            }
            Err(e) => tracing::error!("requester search failed: {e}"),
        }
    }

    // If they already chose somebody, keep them in the list even when the
    // search box no longer matches — otherwise a stray keystroke silently
    // clears the selection.
    if let Some(chosen) = non_empty(&form.requester) {
        if !candidates.iter().any(|c| c.sourced_id == chosen) {
            if let Ok(Some(u)) = state.repo.get_user(&chosen).await {
                candidates.insert(
                    0,
                    RequesterOption {
                        selected: true,
                        sourced_id: u.sourced_id.clone(),
                        name: format!("{}, {}", u.family_name, u.given_name),
                        email: u.email.clone().unwrap_or_default(),
                    },
                );
            }
        }
    }

    let priority = TicketPriority::parse(form.priority.trim()).unwrap_or_default();
    let target_note = match state.config.helpdesk.response_hours(priority) {
        Some(1) => "Answer within 1 hour.".to_string(),
        Some(h) if h < 24 => format!("Answer within {h} hours."),
        Some(h) if h % 24 == 0 => {
            let d = h / 24;
            format!("Answer within {d} day{}.", if d == 1 { "" } else { "s" })
        }
        Some(h) => format!("Answer within {h} hours."),
        None => "No response target is set for this priority.".to_string(),
    };

    NewTicketView {
        subject: form.subject.clone(),
        body: form.body.clone(),
        requester: form.requester.trim().to_string(),
        requester_email: form.requester_email.trim().to_string(),
        priority: priority.as_str().to_string(),
        category: form.category.clone(),
        searched: !term.is_empty(),
        search: term,
        candidates,
        priority_options: TicketPriority::ALL
            .iter()
            .map(|p| {
                (
                    p.as_str().to_string(),
                    p.label().to_string(),
                    *p == priority,
                )
            })
            .collect(),
        target_note,
        attaches_device: state.config.helpdesk.attach_requester_device && state.assets.is_some(),
        error,
        csrf_token: form.csrf_token.clone(),
    }
}
