//! The staff help portal — where the person with the broken Chromebook goes.
//!
//! # Why this is not behind the roster/SSO module
//!
//! The helpdesk is sold in the Devices + Helpdesk tier, and that tier does not
//! get Chalk's identity layer. If the only way in were the SAML IdP, a district
//! would be sold a help desk with nowhere for its staff to use it. So sign-in
//! here is a magic link to a roster email address: it needs no identity
//! provider, no per-district OAuth client, and no password for a teacher to
//! forget. Email is already required for ticket notification, so it is one
//! dependency rather than two.
//!
//! # What a requester may see
//!
//! Their own tickets and nothing else. That is enforced by filtering on the
//! requester in the query, not by checking an id after loading — and comments
//! are fetched with `include_internal = false`, which the repository honours in
//! SQL. An internal note cannot reach this page by someone reordering a
//! template loop.
//!
//! # On sharing the magic-link token table with admin login
//!
//! Both mint into `magic_login_tokens`, and that is safe in both directions.
//! A staff token redeemed at `/login/verify` is refused there by an explicit
//! role check; an admin token redeemed here yields a portal session, which any
//! roster user is entitled to anyway. Neither direction grants something the
//! holder did not already have.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::cookies::{clear_cookie, set_cookie, CookieAttrs, SameSite};
use chalk_core::models::page::PageRequest;
use chalk_core::models::sso::PortalSession;
use chalk_core::models::ticket::{
    NewTicketComment, Ticket, TicketFilter, TicketPriority, TicketScope, TicketSort,
};
use chalk_core::models::user::User;
use chalk_core::ticket_service::{NewTicket, TicketService};
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::AppState;

pub const HELP_PATH: &str = "/help";

/// The cookie the SSO launcher portal already uses. Shared deliberately: a
/// teacher who signed in there is the same person, and asking them to sign in
/// twice to the same product would be an invention of ours, not a requirement.
const PORTAL_COOKIE: &str = "chalk_portal";

/// How long a sign-in link is good for.
const LINK_TTL_MINUTES: i64 = 15;

/// How long a portal session lasts. Shorter than the admin console's: this is
/// a shared classroom machine as often as not.
const SESSION_HOURS: i64 = 12;

const PAGE_SIZE: i64 = 25;

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "help/signin.html")]
pub struct SignInTemplate {
    pub notice: String,
    pub error: String,
    pub email: String,
    pub csrf_token: String,
    /// Whether to show the form at all.
    ///
    /// Not inferable from the other fields, which is how this went wrong: the
    /// form used to render whenever `notice` was empty, so a deployment that
    /// could not send mail showed "Email sign-in is not set up" *and* a working
    /// "Email me a link" button underneath it. A refusal with a button is not
    /// a refusal.
    pub can_send: bool,
}

pub struct MyTicketRow {
    pub id: String,
    pub number: i64,
    pub subject: String,
    pub status_label: String,
    pub status_class: String,
    pub updated: String,
    /// True while the district still owes them an answer.
    pub awaiting: bool,
}

pub struct MyTicketsView {
    pub display_name: String,
    pub rows: Vec<MyTicketRow>,
    pub notice: String,
}

impl MyTicketsView {
    pub fn has_rows(&self) -> bool {
        !self.rows.is_empty()
    }
    pub fn has_notice(&self) -> bool {
        !self.notice.is_empty()
    }
}

#[derive(Template)]
#[template(path = "help/index.html")]
pub struct MyTicketsTemplate {
    pub view: MyTicketsView,
}

pub struct MyCommentView {
    pub author: String,
    pub when: String,
    pub body: String,
    /// Their own message, so the thread reads as a conversation.
    pub is_mine: bool,
}

pub struct AttachmentView {
    pub id: String,
    pub filename: String,
    pub size: String,
    /// Images get shown, everything else gets a link.
    pub is_image: bool,
}

pub struct MyTicketView {
    pub id: String,
    pub number: i64,
    pub subject: String,
    pub body: String,
    pub status_label: String,
    pub status_class: String,
    pub opened: String,
    pub device: String,
    pub comments: Vec<MyCommentView>,
    pub files: Vec<AttachmentView>,
    pub settled: bool,
    pub notice: String,
    pub csrf_token: String,
}

impl MyTicketView {
    pub fn has_files(&self) -> bool {
        !self.files.is_empty()
    }
    pub fn has_comments(&self) -> bool {
        !self.comments.is_empty()
    }
    pub fn has_device(&self) -> bool {
        !self.device.is_empty()
    }
    pub fn has_notice(&self) -> bool {
        !self.notice.is_empty()
    }
}

#[derive(Template)]
#[template(path = "help/detail.html")]
pub struct MyTicketTemplate {
    pub view: MyTicketView,
}

pub struct NewRequestView {
    pub display_name: String,
    pub subject: String,
    pub body: String,
    pub error: String,
    pub device_note: String,
    pub csrf_token: String,
}

impl NewRequestView {
    pub fn has_error(&self) -> bool {
        !self.error.is_empty()
    }
    pub fn has_device_note(&self) -> bool {
        !self.device_note.is_empty()
    }
}

#[derive(Template)]
#[template(path = "help/new.html")]
pub struct NewRequestTemplate {
    pub view: NewRequestView,
}

// ---------------------------------------------------------------------------
// Sign in
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SignInForm {
    pub email: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct VerifyQuery {
    pub token: String,
}

/// What a deployment with no way to send mail tells a teacher.
///
/// Chalk itself does not deliver email — the trait is here and the
/// implementation comes from whatever runs it (Postmark on hosted). On a
/// deployment that supplied none, the honest answer is that this door is shut,
/// and saying so is *much* better than the alternative: a neutral "a link is
/// on its way" for a link that will never arrive, which leaves somebody
/// refreshing their inbox over a broken feature.
const NO_MAILER: &str = "Email sign-in is not set up on this Chalk. \
     Ask your IT administrator to raise your request for you.";

/// Whether this deployment can actually deliver a *usable* sign-in link.
///
/// Both halves are required. A mailer with no `public_url` sends a message
/// containing `/help/verify?token=…` — which no mail client can open, so the
/// mail arrives, looks entirely correct, and does nothing. That is the most
/// expensive kind of broken, because nobody reports it as a bug; they report
/// that sign-in "sometimes doesn't work".
fn can_send_links(state: &Arc<AppState>) -> bool {
    state.mailer.is_some() && state.config.chalk.absolute_url_base().is_some()
}

/// `GET /help/signin`
pub async fn signin_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    if !can_send_links(&state) {
        return render(SignInTemplate {
            notice: String::new(),
            error: NO_MAILER.to_string(),
            email: String::new(),
            csrf_token: csrf.0,
            can_send: false,
        });
    }
    render(SignInTemplate {
        notice: String::new(),
        error: String::new(),
        email: String::new(),
        csrf_token: csrf.0,
        can_send: true,
    })
}

/// `POST /help/signin` — mint a link for a roster email.
///
/// The response never differs by whether the address exists. Telling a
/// stranger "no such person" turns this form into a roster-membership oracle,
/// and a school roster is exactly the list not to leak.
pub async fn signin_submit(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<SignInForm>,
) -> Response {
    // Nothing can be sent, so there is nothing to be neutral about: the
    // anti-enumeration wording exists to hide whether an address is on the
    // roster, and no lookup is going to happen.
    if !can_send_links(&state) {
        if state.mailer.is_some() {
            tracing::error!(
                "chalk.public_url is not set, so a sign-in link would have no host and \
                 could not be opened. Set it and staff can sign in."
            );
        }
        return render(SignInTemplate {
            notice: String::new(),
            error: NO_MAILER.to_string(),
            email: String::new(),
            csrf_token: String::new(),
            can_send: false,
        });
    }

    let email = form.email.trim().to_ascii_lowercase();
    let neutral = SignInTemplate {
        notice: format!(
            "If that address belongs to someone at this district, a sign-in link is on \
             its way. It expires in {LINK_TTL_MINUTES} minutes."
        ),
        error: String::new(),
        email: String::new(),
        csrf_token: String::new(),
        can_send: true,
    };

    if email.is_empty() || !email.contains('@') {
        return render(SignInTemplate {
            notice: String::new(),
            error: "Enter your school email address.".to_string(),
            email: form.email.clone(),
            csrf_token: String::new(),
            can_send: true,
        });
    }

    if let Some(user) = find_by_email(&state, &email).await {
        // The same mint-and-digest the admin magic link uses. Sharing them is
        // the point: a second implementation of "hash the token before storing
        // it" is a second chance to store it in the clear.
        let raw = crate::auth::generate_session_token();
        let hash = crate::auth::hash_token(&raw);
        let expires = Utc::now() + Duration::minutes(LINK_TTL_MINUTES);
        match state
            .repo
            .create_magic_login_token(&user.sourced_id, &hash, expires)
            .await
        {
            Ok(()) => {
                // The general mailer, not `magic_login` — that one selects how
                // the admin console authenticates, and a district that has
                // never enabled it still needs its staff able to sign in here.
                if let Some(mailer) = state.mailer.clone() {
                    // Checked above, so this cannot be empty.
                    let base = state
                        .config
                        .chalk
                        .absolute_url_base()
                        .unwrap_or_default()
                        .to_string();
                    let link = format!("{base}{HELP_PATH}/verify?token={raw}");
                    let to = user.email.clone().unwrap_or_default();
                    tokio::spawn(async move {
                        if let Err(e) = mailer.send_login_link(&to, &link).await {
                            tracing::warn!("help portal sign-in email failed: {e}");
                        }
                    });
                }
            }
            Err(e) => tracing::error!("could not mint a help portal sign-in token: {e}"),
        }
    }

    render(neutral)
}

/// `GET /help/verify?token=…`
pub async fn verify(State(state): State<Arc<AppState>>, Query(q): Query<VerifyQuery>) -> Response {
    let token = q.token.trim();
    if token.is_empty() {
        return expired_link();
    }
    let user_id = match state.repo.consume_magic_login_token(token).await {
        Ok(Some(id)) => id,
        Ok(None) => return expired_link(),
        Err(e) => {
            tracing::error!("could not consume a help portal token: {e}");
            return expired_link();
        }
    };

    // The token proves control of the address; this proves the roster row still
    // exists. A user removed between minting and redeeming must not get in.
    if state.repo.get_user(&user_id).await.ok().flatten().is_none() {
        return expired_link();
    }

    let session = PortalSession {
        id: crate::auth::generate_session_token(),
        user_sourced_id: user_id,
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(SESSION_HOURS),
    };
    if let Err(e) = state.repo.create_portal_session(&session).await {
        tracing::error!("could not start a help portal session: {e}");
        return expired_link();
    }

    let cookie = set_cookie(
        PORTAL_COOKIE,
        &session.id,
        &CookieAttrs {
            same_site: SameSite::Lax,
            http_only: true,
            secure: state.config.chalk.cookies_secure(),
            path: "/",
            max_age_secs: Some(SESSION_HOURS * 3600),
        },
    );
    (
        axum::http::StatusCode::SEE_OTHER,
        [
            (axum::http::header::SET_COOKIE, cookie),
            (axum::http::header::LOCATION, HELP_PATH.to_string()),
        ],
    )
        .into_response()
}

/// `POST /help/signout`
pub async fn signout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(id) = session_cookie(&headers) {
        let _ = state.repo.delete_portal_session(&id).await;
    }
    let cookie = clear_cookie(
        PORTAL_COOKIE,
        &CookieAttrs {
            same_site: SameSite::Lax,
            http_only: true,
            secure: state.config.chalk.cookies_secure(),
            path: "/",
            max_age_secs: None,
        },
    );
    (
        axum::http::StatusCode::SEE_OTHER,
        [
            (axum::http::header::SET_COOKIE, cookie),
            (axum::http::header::LOCATION, format!("{HELP_PATH}/signin")),
        ],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// The requester's own tickets
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NoticeQuery {
    pub notice: String,
}

impl NoticeQuery {
    fn message(&self) -> String {
        match self.notice.as_str() {
            "raised" => "Your request has been sent to IT.".to_string(),
            "replied" => "Your reply was added.".to_string(),
            "empty" => "Write something before sending.".to_string(),
            "failed" => "That could not be saved. Please try again.".to_string(),
            "file_empty" => "That file was empty — nothing was sent.".to_string(),
            "file_large" => "That file is too big. Try a photo rather than a video.".to_string(),
            "file_many" => "You can attach up to 5 files at a time.".to_string(),
            _ => String::new(),
        }
    }
}

/// `GET /help`
pub async fn my_tickets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(notice): Query<NoticeQuery>,
) -> Response {
    let Some((user, tickets)) = signed_in(&state, &headers).await else {
        return to_signin();
    };

    let page = tickets
        .list_tickets(
            &mine(&user),
            // Scope is about *schools*; the requester filter above is what
            // narrows this to one person. Both are required arguments, so
            // neither can be omitted by accident.
            &TicketScope::Unrestricted,
            PageRequest::from_page_number(1, PAGE_SIZE),
        )
        .await
        .unwrap_or_else(|e| {
            tracing::error!("could not list a requester's tickets: {e}");
            chalk_core::models::page::Page {
                items: Vec::new(),
                total: 0,
                limit: PAGE_SIZE,
                offset: 0,
            }
        });

    render(MyTicketsTemplate {
        view: MyTicketsView {
            display_name: display_name(&user),
            rows: page.items.iter().map(row_view).collect(),
            notice: notice.message(),
        },
    })
}

/// `GET /help/new`
pub async fn new_request_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    let Some((user, _)) = signed_in(&state, &headers).await else {
        return to_signin();
    };
    render(NewRequestTemplate {
        view: NewRequestView {
            display_name: display_name(&user),
            subject: String::new(),
            body: String::new(),
            error: String::new(),
            device_note: device_note(&state, &user).await,
            csrf_token: csrf.0,
        },
    })
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewRequestForm {
    pub subject: String,
    pub body: String,
    pub csrf_token: String,
}

/// `POST /help/new`
pub async fn create_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<NewRequestForm>,
) -> Response {
    let Some((user, tickets)) = signed_in(&state, &headers).await else {
        return to_signin();
    };

    let service = TicketService::new(state.config.helpdesk.clone(), state.assets.clone());
    let new = NewTicket {
        // Always the signed-in user. The form cannot name a requester, so
        // nobody can raise a ticket as somebody else.
        requester_user_sourced_id: Some(user.sourced_id.clone()),
        requester_email: user.email.clone(),
        subject: form.subject.clone(),
        body: form.body.clone(),
        priority: TicketPriority::Normal,
        source: chalk_core::models::ticket::TicketSource::Portal,
        ..Default::default()
    };

    let prepared = match service.prepare(uuid::Uuid::new_v4().to_string(), new).await {
        Ok(t) => t,
        Err(chalk_core::error::ChalkError::Validation(message)) => {
            return render(NewRequestTemplate {
                view: NewRequestView {
                    display_name: display_name(&user),
                    subject: form.subject.clone(),
                    body: form.body.clone(),
                    error: message,
                    device_note: device_note(&state, &user).await,
                    csrf_token: form.csrf_token.clone(),
                },
            })
        }
        Err(e) => {
            tracing::error!("could not prepare a portal ticket: {e}");
            return failed();
        }
    };

    match tickets.create_ticket(&prepared).await {
        Ok(t) => Redirect::to(&format!("{HELP_PATH}/{}?notice=raised", t.id)).into_response(),
        Err(e) => {
            tracing::error!("could not create a portal ticket: {e}");
            failed()
        }
    }
}

/// `GET /help/{id}`
pub async fn my_ticket(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(notice): Query<NoticeQuery>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    let Some((user, tickets)) = signed_in(&state, &headers).await else {
        return to_signin();
    };
    let Some(ticket) = owned_by(&tickets, &id, &user).await else {
        return not_found();
    };

    // `false` — the requester's view. The repository drops internal notes in
    // SQL, so one cannot arrive here and be filtered out by a template.
    let comments = tickets.list_comments(&id, false).await.unwrap_or_default();
    let files = tickets.list_attachments(&id).await.unwrap_or_default();

    let device = match (&ticket.asset_id, state.assets.as_ref()) {
        (Some(asset_id), Some(assets)) => assets
            .get_asset(asset_id)
            .await
            .ok()
            .flatten()
            .and_then(|a| a.asset_tag.or(a.serial_number))
            .unwrap_or_default(),
        _ => String::new(),
    };

    render(MyTicketTemplate {
        view: MyTicketView {
            id: ticket.id.clone(),
            number: ticket.number,
            subject: ticket.subject.clone(),
            body: ticket.body.clone(),
            status_label: requester_status(&ticket),
            status_class: crate::tickets::status_class(ticket.status).to_string(),
            opened: ticket.created_at.format("%-d %B %Y").to_string(),
            device,
            comments: comments
                .iter()
                .map(|c| MyCommentView {
                    is_mine: c.author_user_sourced_id.as_deref() == Some(&user.sourced_id),
                    author: if c.author_user_sourced_id.as_deref() == Some(&user.sourced_id) {
                        "You".to_string()
                    } else {
                        "IT".to_string()
                    },
                    when: c.created_at.format("%-d %B, %H:%M").to_string(),
                    body: c.body.clone(),
                })
                .collect(),
            files: files.iter().map(attachment_view).collect(),
            settled: ticket.status.is_settled(),
            notice: notice.message(),
            csrf_token: csrf.0,
        },
    })
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ReplyForm {
    pub body: String,
}

/// `POST /help/{id}/reply`
pub async fn reply(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    multipart: axum::extract::Multipart,
) -> Response {
    let Some((user, tickets)) = signed_in(&state, &headers).await else {
        return to_signin();
    };
    // Checked before the body is read, so an upload to somebody else's ticket
    // is refused without anything being written anywhere.
    if owned_by(&tickets, &id, &user).await.is_none() {
        return not_found();
    }

    let (fields, files) = match crate::ticket_files::read_multipart(multipart).await {
        Ok(v) => v,
        Err(e) => return crate::ticket_files::upload_refused(&id, HELP_PATH, e),
    };
    let body = fields
        .iter()
        .find(|(k, _)| k == "body")
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();

    // A photograph with no words is a perfectly good reply.
    if body.is_empty() && files.is_empty() {
        return back(&id, "empty");
    }
    let text = if body.is_empty() {
        "Attached a photo.".to_string()
    } else {
        body
    };

    // A requester's reply is never internal — there is no path from this
    // handler that could make it one.
    let comment = NewTicketComment::reply(&id, &user.sourced_id, &text);
    match tickets.append_comment(&comment).await {
        Ok(saved) => {
            crate::ticket_files::store_all(&state, &id, Some(saved.id), files).await;
            back(&id, "replied")
        }
        Err(e) => {
            tracing::error!("could not add a requester reply: {e}");
            back(&id, "failed")
        }
    }
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// The filter that limits a page to one person's tickets.
///
/// Both identifiers, because a ticket raised by email before their account
/// synced carries the address rather than the roster id, and it is still
/// theirs.
fn mine(user: &User) -> TicketFilter {
    TicketFilter {
        requester_user_sourced_id: Some(user.sourced_id.clone()),
        sort: TicketSort::UpdatedAt,
        direction: chalk_core::models::page::SortDirection::Desc,
        ..Default::default()
    }
}

/// Load a ticket only if it belongs to this requester.
///
/// Returns `None` rather than a distinguishable "forbidden", so the portal
/// cannot be used to discover that a ticket number exists.
async fn owned_by(
    tickets: &Arc<dyn chalk_core::db::repository::TicketRepository>,
    id: &str,
    user: &User,
) -> Option<Ticket> {
    let ticket = tickets.get_ticket(id).await.ok().flatten()?;
    crate::ticket_files::owns(&ticket, user).then_some(ticket)
}

/// The signed-in roster user, for callers that do not need the repository.
pub(crate) async fn signed_in_user(state: &Arc<AppState>, headers: &HeaderMap) -> Option<User> {
    signed_in(state, headers).await.map(|(user, _)| user)
}

/// The signed-in roster user and the ticket repository, or nothing.
async fn signed_in(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Option<(User, Arc<dyn chalk_core::db::repository::TicketRepository>)> {
    let tickets = state.tickets.clone()?;
    let id = session_cookie(headers)?;
    let session = state.repo.get_portal_session(&id).await.ok().flatten()?;
    if session.expires_at <= Utc::now() {
        return None;
    }
    let user = state
        .repo
        .get_user(&session.user_sourced_id)
        .await
        .ok()
        .flatten()?;
    Some((user, tickets))
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .map(str::trim)
        .find_map(|c| c.strip_prefix(&format!("{PORTAL_COOKIE}=")))
        .map(str::to_string)
}

async fn find_by_email(state: &Arc<AppState>, email: &str) -> Option<User> {
    state
        .repo
        .list_users(&chalk_core::models::sync::UserFilter::search(email, 25))
        .await
        .ok()?
        .into_iter()
        .find(|u| {
            u.email
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case(email))
        })
}

fn display_name(user: &User) -> String {
    user.given_name.clone()
}

/// What the requester is told their device is, if Chalk knows.
async fn device_note(state: &Arc<AppState>, user: &User) -> String {
    let Some(assets) = state.assets.as_ref() else {
        return String::new();
    };
    if !state.config.helpdesk.attach_requester_device {
        return String::new();
    }
    let filter = chalk_core::models::asset::AssetFilter {
        assigned_user_sourced_id: Some(user.sourced_id.clone()),
        ..Default::default()
    };
    let Ok(page) = assets
        .list_assets(&filter, PageRequest::from_page_number(1, 2))
        .await
    else {
        return String::new();
    };
    match page.items.as_slice() {
        [only] => {
            let label = only
                .asset_tag
                .clone()
                .or_else(|| only.serial_number.clone())
                .unwrap_or_default();
            if label.is_empty() {
                String::new()
            } else {
                format!("We will attach your device ({label}) to this request.")
            }
        }
        _ => String::new(),
    }
}

/// Status in words a requester understands.
///
/// "Waiting" means waiting on *them*, which is the one status where the label
/// a technician reads is actively misleading to the person it describes: they
/// would see "waiting" and reasonably conclude IT is dealing with it.
fn requester_status(t: &Ticket) -> String {
    use chalk_core::models::ticket::TicketStatus::*;
    match t.status {
        Open => "Received".to_string(),
        InProgress => "Being worked on".to_string(),
        Waiting => "Waiting for your reply".to_string(),
        Resolved => "Fixed".to_string(),
        Closed => "Closed".to_string(),
    }
}

fn row_view(t: &Ticket) -> MyTicketRow {
    MyTicketRow {
        id: t.id.clone(),
        number: t.number,
        subject: t.subject.clone(),
        status_label: requester_status(t),
        status_class: crate::tickets::status_class(t.status).to_string(),
        updated: t.updated_at.format("%-d %B").to_string(),
        awaiting: t.awaiting_first_response(),
    }
}

/// Human-sized, because "2,411,904 bytes" tells a teacher nothing.
pub(crate) fn human_size(bytes: i64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    const KB: f64 = 1024.0;
    let b = bytes.max(0) as f64;
    if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.0} KB", b / KB)
    } else {
        format!("{bytes} bytes")
    }
}

fn attachment_view(a: &chalk_core::models::ticket::TicketAttachment) -> AttachmentView {
    AttachmentView {
        id: a.id.clone(),
        filename: a.filename.clone(),
        size: human_size(a.size_bytes),
        is_image: a.content_type.starts_with("image/"),
    }
}

fn back(id: &str, code: &str) -> Response {
    Redirect::to(&format!("{HELP_PATH}/{id}?notice={code}")).into_response()
}

fn to_signin() -> Response {
    Redirect::to(&format!("{HELP_PATH}/signin")).into_response()
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!("help portal render failed: {e}");
            failed()
        }
    }
}

fn expired_link() -> Response {
    (
        axum::http::StatusCode::OK,
        Html(
            "<h1>That link has expired</h1><p>Sign-in links last 15 minutes and work \
             once. <a href=\"/help/signin\">Ask for a new one</a>.</p>"
                .to_string(),
        ),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Not found</h1><p><a href=\"/help\">Back to your requests</a></p>".to_string()),
    )
        .into_response()
}

fn failed() -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Html("<h1>Something went wrong</h1><p>Please try again.</p>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
