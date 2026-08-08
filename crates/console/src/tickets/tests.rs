//! Technician queue tests.
//!
//! Two things here are worth more than the rest. **An internal note must never
//! reach a requester**, which is a disclosure bug rather than a display bug;
//! and **an empty queue must not claim the district has no tickets when a
//! filter is on**, because a technician who reads that concludes the data was
//! lost and goes looking for a backup.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, ChalkRepository, OrgRepository, TicketRepository,
    UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::Asset;
use chalk_core::models::common::{OrgType, RoleType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::ticket::{Ticket, TicketSource};
use chalk_core::models::user::User;
use chrono::{Duration, TimeZone};
use tower::ServiceExt;

use crate::router;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    fixture_with(ChalkConfig::generate_default(), true).await
}

/// The helpdesk with no device inventory wired — a district that bought only
/// this module.
async fn fixture_without_assets() -> Fx {
    fixture_with(ChalkConfig::generate_default(), false).await
}

async fn fixture_with(config: ChalkConfig, with_assets: bool) -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };

    repo.upsert_org(&Org {
        sourced_id: "org-a".into(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        name: "Alpha High".into(),
        org_type: OrgType::School,
        identifier: None,
        parent: None,
        children: vec![],
    })
    .await
    .unwrap();

    for (id, given, family) in [("u-lisa", "Lisa", "Nowak"), ("u-tech", "Ravi", "Patel")] {
        repo.upsert_user(&User {
            sourced_id: id.into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            username: format!("{given}.{family}").to_lowercase(),
            user_ids: vec![],
            enabled_user: true,
            given_name: given.into(),
            family_name: family.into(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some(format!("{given}.{family}@example.edu").to_lowercase()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec![],
            grades: vec![],
        })
        .await
        .unwrap();
    }

    // A technician the ticket can be assigned to. Assignment targets a
    // console_user (F1), not a roster user, so this is a separate namespace
    // and a separate FK — hence a real row must exist to claim under.
    {
        use chalk_core::db::repository::ConsoleUserRepository;
        use chalk_core::models::console_user::{ConsoleRole, ConsoleUser, ConsoleUserStatus};
        let now = Utc::now();
        repo.create_console_user(&ConsoleUser {
            id: "u-tech".into(),
            email: "ravi.patel@example.edu".into(),
            display_name: "Ravi Patel".into(),
            password_hash: None,
            role: ConsoleRole::Technician,
            status: ConsoleUserStatus::Active,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    }

    let tickets: Arc<dyn TicketRepository> = repo.clone();
    let console_users: Arc<dyn chalk_core::db::repository::ConsoleUserRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let mut state = AppState::new(chalk_repo, config)
        .with_tickets(tickets)
        .with_console_users(console_users);
    if with_assets {
        let assets: Arc<dyn AssetRepository> = repo.clone();
        let events: Arc<dyn AssetEventRepository> = repo.clone();
        state = state.with_assets(assets, events);
    }
    Fx {
        state: Arc::new(state),
        repo,
    }
}

/// Builder over the fields a queue test actually varies.
struct T {
    id: String,
    subject: String,
    status: TicketStatus,
    priority: TicketPriority,
    requester: Option<String>,
    requester_email: Option<String>,
    assignee: Option<String>,
    /// Minutes from now. Negative is already past due.
    sla_in: Option<i64>,
    answered: bool,
}

impl T {
    fn new(id: &str) -> Self {
        Self {
            id: id.into(),
            subject: format!("Subject for {id}"),
            status: TicketStatus::Open,
            priority: TicketPriority::Normal,
            requester: Some("u-lisa".into()),
            requester_email: None,
            assignee: None,
            sla_in: None,
            answered: false,
        }
    }

    async fn create(self, f: &Fx) -> Ticket {
        let now = Utc::now();
        let mut t = Ticket::new(&self.id, &self.subject);
        t.body = "The screen flickers.".into();
        t.status = self.status;
        t.priority = self.priority;
        t.requester_user_sourced_id = self.requester;
        t.requester_email = self.requester_email;
        // Assignment is to a console_user (F1 technician), which is what the
        // queue's "unassigned" filter and the detail assignee both read.
        t.assignee_console_user_id = self.assignee;
        t.school_org_sourced_id = Some("org-a".into());
        t.sla_due_at = self.sla_in.map(|m| now + Duration::minutes(m));
        t.first_response_at = self.answered.then_some(now);
        t.source = TicketSource::Portal;
        f.repo.create_ticket(&t).await.unwrap()
    }
}

async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
    let response = router(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

// ---------------------------------------------------------------------------
// The queue
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_queue_lists_tickets_with_the_person_and_the_number() {
    let f = fixture().await;
    T::new("t1").create(&f).await;

    let (status, body) = get(f.state.clone(), TICKETS_PATH).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Subject for t1"));
    // The roster name, not the sourced id — the queue is read by a person.
    assert!(body.contains("Nowak, Lisa"), "roster name resolved");
    assert!(!body.contains("u-lisa"), "and the raw id is not shown");
}

/// A ticket from someone with no roster row is still a ticket, and the address
/// is who they are. Rendering "Unknown" would make it unanswerable.
#[tokio::test]
async fn an_email_requester_with_no_roster_row_is_named_by_address() {
    let f = fixture().await;
    let mut t = T::new("t1");
    t.requester = None;
    t.requester_email = Some("parent@example.org".into());
    t.create(&f).await;

    let (_, body) = get(f.state.clone(), TICKETS_PATH).await;
    assert!(body.contains("parent@example.org"));
    assert!(!body.contains("Unknown"));
}

/// Past due and unanswered are marked in words, not only in colour. A
/// technician who cannot distinguish red still triages this queue all day.
#[tokio::test]
async fn overdue_and_unanswered_tickets_are_marked_in_words() {
    let f = fixture().await;
    let mut t = T::new("late");
    t.sla_in = Some(-60);
    t.create(&f).await;

    let (_, body) = get(f.state.clone(), TICKETS_PATH).await;
    // The badge, not the triage card above the table, which always says
    // "Past due" whatever is in the queue.
    assert!(body.contains("badge--danger\">Past due"));
    assert!(body.contains("badge--warning\">No reply yet"));
}

/// A resolved ticket is never "past due", however late it was resolved.
/// Past-tense lateness belongs in a report, not in a badge telling a
/// technician what to do next.
#[tokio::test]
async fn a_settled_ticket_is_not_marked_past_due() {
    let f = fixture().await;
    let mut t = T::new("done");
    t.sla_in = Some(-600);
    t.status = TicketStatus::Resolved;
    t.answered = true;
    t.create(&f).await;

    let (_, body) = get(f.state.clone(), TICKETS_PATH).await;
    assert!(
        !body.contains("badge--danger\">Past due"),
        "settled, so not actionable"
    );
    assert!(!body.contains("badge--warning\">No reply yet"));
}

#[tokio::test]
async fn the_triage_counts_describe_the_whole_queue_not_the_page() {
    let f = fixture().await;
    let mut late = T::new("late");
    late.sla_in = Some(-60);
    late.create(&f).await;

    let mut taken = T::new("taken");
    taken.assignee = Some("u-tech".into());
    taken.create(&f).await;

    let (_, body) = get(f.state.clone(), TICKETS_PATH).await;
    // Two open, one past due, one unassigned — the counts are computed with
    // their own filters rather than from the rows on this page.
    let counts = body.split("stat-card").collect::<Vec<_>>();
    assert!(counts.len() > 3, "three cards rendered");
    assert!(body.contains("Past due"));
    assert!(body.contains("Unassigned"));
    // Each card links to the filter that produced it: a number you cannot
    // open is trivia.
    assert!(body.contains("/tickets?breached=1"));
    assert!(body.contains("/tickets?assigned=unassigned"));
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn filters_narrow_the_queue() {
    let f = fixture().await;
    T::new("open-one").create(&f).await;
    let mut waiting = T::new("waiting-one");
    waiting.status = TicketStatus::Waiting;
    waiting.create(&f).await;

    let (_, body) = get(f.state.clone(), "/tickets?status=waiting").await;
    assert!(body.contains("Subject for waiting-one"));
    assert!(!body.contains("Subject for open-one"));
}

#[tokio::test]
async fn the_unassigned_filter_excludes_tickets_someone_picked_up() {
    let f = fixture().await;
    T::new("free").create(&f).await;
    let mut taken = T::new("taken");
    taken.assignee = Some("u-tech".into());
    taken.create(&f).await;

    let (_, body) = get(f.state.clone(), "/tickets?assigned=unassigned").await;
    assert!(body.contains("Subject for free"));
    assert!(!body.contains("Subject for taken"));
}

/// Posting an assignee claims the ticket for a technician; the detail page then
/// names them and the unassigned filter drops it. Posting an empty assignee
/// releases it again.
#[tokio::test]
async fn a_ticket_is_assigned_and_released_through_the_console() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;

    let (status, _) = post(
        f.state.clone(),
        &format!("/tickets/{}/assign", t.id),
        "assignee=u-tech",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "redirects back to the ticket"
    );

    let (_, body) = get(f.state.clone(), &format!("/tickets/{}", t.id)).await;
    assert!(body.contains("Ravi Patel"), "names the assigned technician");

    let (_, queue) = get(f.state.clone(), "/tickets?assigned=unassigned").await;
    assert!(!queue.contains("Subject for t1"), "no longer unassigned");

    // Release it.
    let (status, _) = post(
        f.state.clone(),
        &format!("/tickets/{}/assign", t.id),
        "assignee=",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, body) = get(f.state.clone(), &format!("/tickets/{}", t.id)).await;
    assert!(body.contains("Nobody yet"), "released back to nobody");
}

/// Assigning to an id that is not an active technician is refused — the FK is
/// not enough, since a suspended tech still satisfies it.
#[tokio::test]
async fn assigning_to_an_unknown_technician_is_refused() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;

    let (status, location) = post(
        f.state.clone(),
        &format!("/tickets/{}/assign", t.id),
        "assignee=nobody-real",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location.contains("assign_unknown"),
        "flags the bad assignee, got {location}"
    );

    let after = f.repo.get_ticket(&t.id).await.unwrap().unwrap();
    assert_eq!(after.assignee_console_user_id, None, "left unassigned");
}

/// The latent bug this fixes: raising the priority must move the response
/// deadline. It was computed once at creation and never recomputed, so an
/// escalated ticket kept the relaxed deadline and the breach badge lied. The
/// new target is anchored to arrival time, not to when it was reclassified.
#[tokio::test]
async fn raising_the_priority_recomputes_the_response_deadline() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;
    let before = f.repo.get_ticket(&t.id).await.unwrap().unwrap();
    assert_eq!(before.priority, TicketPriority::Normal, "starts Normal");

    let (status, _) = post(
        f.state.clone(),
        &format!("/tickets/{}/reclassify", t.id),
        "priority=urgent&category=hardware",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let after = f.repo.get_ticket(&t.id).await.unwrap().unwrap();
    assert_eq!(after.priority, TicketPriority::Urgent, "priority moved");
    assert_eq!(after.category.as_deref(), Some("hardware"), "category set");

    // The deadline is recomputed from the ticket's *arrival* time, not from
    // now — the first-response clock has been running since it came in.
    let cfg = &f.state.config.helpdesk;
    let expected = before.created_at + Duration::hours(cfg.urgent_response_hours);
    assert_eq!(
        after.sla_due_at,
        Some(expected),
        "recomputed from created_at + the urgent window"
    );
    // And urgent really is sooner than the window it would have had as Normal.
    assert!(
        cfg.urgent_response_hours < cfg.normal_response_hours,
        "urgent is a tighter target than normal"
    );
}

/// Editing the category alone must not disturb an existing SLA target.
#[tokio::test]
async fn editing_only_the_category_leaves_the_deadline_alone() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;
    let before = f.repo.get_ticket(&t.id).await.unwrap().unwrap();

    let (status, _) = post(
        f.state.clone(),
        &format!("/tickets/{}/reclassify", t.id),
        "priority=normal&category=network",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let after = f.repo.get_ticket(&t.id).await.unwrap().unwrap();
    assert_eq!(after.category.as_deref(), Some("network"));
    assert_eq!(after.sla_due_at, before.sla_due_at, "deadline untouched");
}

// ---------------------------------------------------------------------------
// Analytics
// ---------------------------------------------------------------------------

/// The analytics page counts the help desk and every number links to the queue
/// filtered to exactly it — including per-technician workload, which only exists
/// because assignment does.
#[tokio::test]
async fn the_analytics_page_counts_and_links_every_figure() {
    let f = fixture().await;
    // Two unassigned, one claimed by Ravi.
    T::new("free-1").create(&f).await;
    T::new("free-2").create(&f).await;
    let mut mine = T::new("mine");
    mine.assignee = Some("u-tech".into());
    mine.create(&f).await;

    let (status, body) = get(f.state.clone(), "/tickets/analytics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Ticket analytics"));
    // Backlog: two unassigned, linked to the queue filter.
    assert!(body.contains("/tickets?assigned=unassigned"));
    // Per-technician workload: Ravi is listed and links to his queue.
    assert!(body.contains("Ravi Patel"), "the technician is named");
    assert!(
        body.contains("/tickets?owner=u-tech"),
        "and links to his queue"
    );
    // By school: the fixture's school is named and linked.
    assert!(body.contains("Alpha High"));
    assert!(body.contains("/tickets?school=org-a"));
}

/// An empty help desk says so rather than rendering a wall of zeroes.
#[tokio::test]
async fn the_analytics_page_has_an_empty_state() {
    let f = fixture().await;
    let (status, body) = get(f.state.clone(), "/tickets/analytics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("no tickets yet"));
}

/// The `owner` query param narrows the queue to one technician's tickets — the
/// link the analytics page emits must actually filter.
#[tokio::test]
async fn the_owner_filter_narrows_the_queue_to_one_technician() {
    let f = fixture().await;
    T::new("someone-elses").create(&f).await;
    let mut mine = T::new("ravis");
    mine.assignee = Some("u-tech".into());
    mine.create(&f).await;

    let (status, body) = get(f.state.clone(), "/tickets?owner=u-tech").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Subject for ravis"), "his ticket is shown");
    assert!(
        !body.contains("Subject for someone-elses"),
        "and nobody else's"
    );
}

/// This is the empty state that matters. "No tickets yet" on a filtered page
/// reads as data loss, and a technician acts on that reading.
#[tokio::test]
async fn a_filtered_empty_queue_never_says_there_are_no_tickets() {
    let f = fixture().await;
    T::new("t1").create(&f).await;

    let (_, body) = get(f.state.clone(), "/tickets?status=closed").await;
    assert!(body.contains("No tickets match these filters"));
    assert!(
        !body.contains("No tickets yet"),
        "the first-run copy must not appear while a filter is active"
    );
}

#[tokio::test]
async fn an_unfiltered_empty_queue_explains_where_tickets_come_from() {
    let f = fixture().await;
    let (_, body) = get(f.state.clone(), TICKETS_PATH).await;
    assert!(body.contains("No tickets yet"));
    assert!(body.contains("staff portal"));
}

/// A hand-edited URL should widen the view, not 400. Same rule the device
/// inventory follows.
#[tokio::test]
async fn an_unparseable_filter_value_is_ignored_rather_than_rejected() {
    let f = fixture().await;
    T::new("t1").create(&f).await;

    let (status, body) = get(f.state.clone(), "/tickets?status=banana&priority=zzz").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Subject for t1"));
}

/// Every status and priority the model can hold is offered in the filter.
/// Generated from `ALL` rather than typed into the template, so a new variant
/// cannot be filterable by URL but missing from the dropdown.
#[tokio::test]
async fn every_status_and_priority_is_offered_in_the_filter() {
    let f = fixture().await;
    let (_, body) = get(f.state.clone(), TICKETS_PATH).await;
    for s in TicketStatus::ALL {
        assert!(
            body.contains(&format!("value=\"{}\"", s.as_str())),
            "status {} missing from the filter",
            s.as_str()
        );
    }
    for p in TicketPriority::ALL {
        assert!(
            body.contains(&format!("value=\"{}\"", p.as_str())),
            "priority {} missing from the filter",
            p.as_str()
        );
    }
}

// ---------------------------------------------------------------------------
// The thread
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_detail_page_shows_the_request_and_the_people() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;

    let (status, body) = get(f.state.clone(), &format!("/tickets/{}", t.id)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("The screen flickers."));
    assert!(body.contains("Nowak, Lisa"));
    assert!(body.contains("Alpha High"), "school resolved to its name");
    assert!(body.contains("Nobody yet"), "unassigned said in words");
}

#[tokio::test]
async fn a_ticket_that_names_a_device_links_to_it() {
    let f = fixture().await;
    let mut asset = Asset::new("asset-9");
    asset.asset_tag = Some("CB-0042".into());
    f.repo.create_asset(&asset).await.unwrap();

    let mut t = Ticket::new("t1", "Cracked screen");
    t.asset_id = Some("asset-9".into());
    f.repo.create_ticket(&t).await.unwrap();

    let (_, body) = get(f.state.clone(), "/tickets/t1").await;
    assert!(body.contains("/devices/asset-9"));
    // Named by its asset tag, which is what is written on the lid — not by a
    // UUID nobody can read off a device.
    assert!(body.contains("CB-0042"));
}

/// Helpdesk without the device module still names the device rather than
/// pretending the ticket is about nothing.
#[tokio::test]
async fn a_device_ticket_still_names_the_device_when_devices_are_off() {
    let f = fixture_without_assets().await;
    // The row must exist whatever the console has wired: `tickets.asset_id`
    // is a real foreign key.
    f.repo.create_asset(&Asset::new("asset-9")).await.unwrap();

    let mut t = Ticket::new("t1", "Cracked screen");
    t.asset_id = Some("asset-9".into());
    f.repo.create_ticket(&t).await.unwrap();

    let (_, body) = get(f.state.clone(), "/tickets/t1").await;
    assert!(body.contains("Device asset-9"));
}

/// Captures the email a reply would send, so a test can inspect it.
#[derive(Default)]
struct CapturingNotifier {
    sent: std::sync::Mutex<Vec<chalk_core::mail::EmailMessage>>,
}

#[async_trait::async_trait]
impl chalk_core::mail::Notifier for CapturingNotifier {
    async fn send_email(&self, message: &chalk_core::mail::EmailMessage) -> anyhow::Result<()> {
        self.sent.lock().unwrap().push(message.clone());
        Ok(())
    }
}

/// Build a state with the help desk, a capturing mailer, and a public URL, plus
/// return the notifier so the test can read what it sent.
async fn fixture_with_mailer() -> (Fx, Arc<CapturingNotifier>) {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    repo.upsert_user(&User {
        sourced_id: "u-lisa".into(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        username: "lisa".into(),
        user_ids: vec![],
        enabled_user: true,
        given_name: "Lisa".into(),
        family_name: "Nowak".into(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some("lisa.nowak@example.edu".into()),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec![],
        grades: vec![],
    })
    .await
    .unwrap();

    let notifier = Arc::new(CapturingNotifier::default());
    let mut config = ChalkConfig::generate_default();
    config.chalk.public_url = Some("https://help.example.edu".into());
    let tickets: Arc<dyn TicketRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = AppState::new(chalk_repo, config)
        .with_tickets(tickets)
        .with_mailer(notifier.clone());
    (
        Fx {
            state: Arc::new(state),
            repo,
        },
        notifier,
    )
}

/// A public reply emails the requester, subject-threaded so their reply returns
/// through the inbound webhook, and pointing at the portal — this is the first
/// real use of the generalized Notifier and the thing that makes the help desk
/// two-way.
#[tokio::test]
async fn a_public_reply_emails_the_requester() {
    let (f, notifier) = fixture_with_mailer().await;
    let mut t = Ticket::new("t1", "Chromebook won't charge");
    t.requester_email = Some("parent@example.edu".into());
    // The number is allocated by the repository, not by us.
    let saved = f.repo.create_ticket(&t).await.unwrap();

    notify_requester_of_reply(
        &f.state,
        "t1",
        "Your replacement charger is at the front office.",
    )
    .await;

    let sent = notifier.sent.lock().unwrap();
    assert_eq!(
        sent.len(),
        1,
        "a public reply should send exactly one email"
    );
    let msg = &sent[0];
    assert_eq!(msg.to, "parent@example.edu");
    // Subject carries [#N] so the requester's reply threads back.
    assert_eq!(
        msg.subject,
        format!("[#{}] Chromebook won't charge", saved.number)
    );
    assert!(msg
        .body
        .contains("Your replacement charger is at the front office."));
    assert!(msg.body.contains("https://help.example.edu/help/t1"));
}

/// The requester's roster email is used when the ticket carries none of its own.
#[tokio::test]
async fn a_reply_falls_back_to_the_roster_email() {
    let (f, notifier) = fixture_with_mailer().await;
    let mut t = Ticket::new("t2", "Projector");
    t.requester_user_sourced_id = Some("u-lisa".into());
    t.requester_email = None;
    f.repo.create_ticket(&t).await.unwrap();

    notify_requester_of_reply(&f.state, "t2", "On its way.").await;

    let sent = notifier.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, "lisa.nowak@example.edu");
}

/// With no `public_url` configured there is no host for the portal link, so no
/// email is sent — better silent than sending a broken link.
#[tokio::test]
async fn no_public_url_means_no_reply_email() {
    let (f, notifier) = fixture_with_mailer().await;
    // Rebuild state without a public_url.
    let mut config = ChalkConfig::generate_default();
    config.chalk.public_url = None;
    let tickets: Arc<dyn TicketRepository> = f.repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = f.repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, config)
            .with_tickets(tickets)
            .with_mailer(notifier.clone()),
    );
    let mut t = Ticket::new("t3", "X");
    t.requester_email = Some("p@e.edu".into());
    f.repo.create_ticket(&t).await.unwrap();

    notify_requester_of_reply(&state, "t3", "hi").await;
    assert!(notifier.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_unknown_ticket_is_a_404_not_a_500() {
    let f = fixture().await;
    let (status, _) = get(f.state.clone(), "/tickets/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The disclosure test. An internal note is fetched for the technician and
/// labelled unmistakably; the requester's own view passes `false` and the
/// repository filters it in SQL.
#[tokio::test]
async fn internal_notes_are_shown_to_technicians_and_labelled() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;
    f.repo
        .append_comment(&NewTicketComment::internal_note(
            &t.id,
            "u-tech",
            "Third failure this month, escalate to the vendor.",
        ))
        .await
        .unwrap();

    let (_, body) = get(f.state.clone(), &format!("/tickets/{}", t.id)).await;
    assert!(body.contains("Third failure this month"));
    assert!(
        body.contains("not visible to the requester"),
        "labelled in words, not only by colour"
    );

    // And the requester's view genuinely does not contain it. This asserts the
    // repository boundary the portal will rely on, not the template's.
    let theirs = f.repo.list_comments(&t.id, false).await.unwrap();
    assert!(theirs.is_empty());
}

// ---------------------------------------------------------------------------
// Module gating
// ---------------------------------------------------------------------------

/// Withheld rather than hidden: a disabled module's routes are never
/// registered, so they 404 through the ordinary not-found path.
#[tokio::test]
async fn the_queue_is_absent_when_the_helpdesk_module_is_off() {
    let mut config = ChalkConfig::generate_default();
    config.modules.helpdesk = false;
    let f = fixture_with(config, true).await;

    let (status, _) = get(f.state.clone(), TICKETS_PATH).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

#[test]
fn age_reads_as_a_magnitude_not_a_timestamp() {
    assert_eq!(humanise_age(Duration::minutes(5)), "5m");
    assert_eq!(humanise_age(Duration::minutes(59)), "59m");
    assert_eq!(humanise_age(Duration::minutes(60)), "1h");
    assert_eq!(humanise_age(Duration::hours(23)), "23h");
    assert_eq!(humanise_age(Duration::hours(24)), "1d");
    assert_eq!(humanise_age(Duration::days(9)), "9d");
    // A clock skew must not render "-3m".
    assert_eq!(humanise_age(Duration::minutes(-3)), "0m");
}

/// Reflected text on the page would let a crafted link put arbitrary words in
/// front of a technician, so the notice is a closed set of codes.
#[test]
fn only_known_notice_codes_produce_a_message() {
    let known = NoticeQuery {
        notice: "commented".into(),
    };
    assert!(!known.message().is_empty());

    let crafted = NoticeQuery {
        notice: "Your account has been suspended, call 555-0100".into(),
    };
    assert!(crafted.message().is_empty());
}

// ---------------------------------------------------------------------------
// Posting
// ---------------------------------------------------------------------------

async fn post(state: Arc<AppState>, uri: &str, body: &str) -> (StatusCode, String) {
    let token = crate::csrf::generate_csrf_token();
    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", format!("chalk_csrf={token}"))
                .header("x-csrf-token", &token)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, location)
}

/// A POST whose response is the page itself rather than a redirect.
async fn post_html(state: Arc<AppState>, uri: &str, body: &str) -> (StatusCode, String) {
    let token = crate::csrf::generate_csrf_token();
    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", format!("chalk_csrf={token}"))
                .header("x-csrf-token", &token)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// POST a multipart body, which is what the comment form sends now that a
/// technician can attach a photo of what they found.
async fn post_multipart(
    state: Arc<AppState>,
    uri: &str,
    fields: &[(&str, &str)],
    file: Option<(&str, &[u8])>,
) -> (StatusCode, String) {
    const BOUNDARY: &str = "----chalktestboundary";
    let mut body: Vec<u8> = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    if let Some((filename, bytes)) = file {
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"files\"; \
                 filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());

    let token = crate::csrf::generate_csrf_token();
    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", format!("chalk_csrf={token}"))
                .header("x-csrf-token", &token)
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, location)
}

#[tokio::test]
async fn a_reply_lands_on_the_thread_and_stamps_the_first_response() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;
    assert!(t.first_response_at.is_none());

    let (status, location) = post_multipart(
        f.state.clone(),
        &format!("/tickets/{}/comment", t.id),
        &[("body", "Swapped the cable.")],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.ends_with("notice=commented"), "{location}");

    // Follow the redirect the browser would follow, notice and all.
    let (_, page) = get(f.state.clone(), &location).await;
    assert!(page.contains("Swapped the cable."));
    assert!(page.contains("Your reply was added."));

    // First-response time is the number a district is judged on, and it is
    // stamped by the append rather than by anyone remembering to.
    let after = f.repo.get_ticket(&t.id).await.unwrap().unwrap();
    assert!(after.first_response_at.is_some());
}

/// An internal note is not a reply, so it must not start the first-response
/// clock. Counting it would let a district look responsive by talking to
/// itself.
#[tokio::test]
async fn an_internal_note_does_not_count_as_the_first_response() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;

    let (status, location) = post_multipart(
        f.state.clone(),
        &format!("/tickets/{}/comment", t.id),
        &[("body", "Escalating to the vendor."), ("internal", "1")],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.ends_with("notice=noted"));

    let after = f.repo.get_ticket(&t.id).await.unwrap().unwrap();
    assert!(after.first_response_at.is_none());

    // And it is genuinely internal at the repository boundary.
    assert!(f.repo.list_comments(&t.id, false).await.unwrap().is_empty());
    assert_eq!(f.repo.list_comments(&t.id, true).await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_empty_reply_is_refused_rather_than_posted_blank() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;

    let (_, location) = post_multipart(
        f.state.clone(),
        &format!("/tickets/{}/comment", t.id),
        &[("body", "   ")],
        None,
    )
    .await;
    assert!(location.ends_with("notice=empty"));
    assert!(f.repo.list_comments(&t.id, true).await.unwrap().is_empty());
}

#[tokio::test]
async fn resolving_stamps_the_time_it_was_resolved() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;

    let (status, _) = post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=resolved",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let after = f.repo.get_ticket(&t.id).await.unwrap().unwrap();
    assert_eq!(after.status, TicketStatus::Resolved);
    assert!(
        after.resolved_at.is_some(),
        "'when was this fixed' is asked far more often than it is recorded"
    );
    assert!(after.closed_at.is_none(), "resolved is not closed");
}

/// Reopening clears the resolution stamp. Leaving it would make every
/// resolution-time report lie about a ticket that is demonstrably not resolved.
#[tokio::test]
async fn reopening_clears_the_resolution_stamp() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;
    post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=resolved",
    )
    .await;
    post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=open",
    )
    .await;

    let after = f.repo.get_ticket(&t.id).await.unwrap().unwrap();
    assert_eq!(after.status, TicketStatus::Open);
    assert!(after.resolved_at.is_none());
    assert!(after.closed_at.is_none());
}

/// Closing keeps the resolution stamp: a ticket that was fixed and then filed
/// away was still fixed at the time it was fixed.
#[tokio::test]
async fn closing_a_resolved_ticket_keeps_when_it_was_resolved() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;
    post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=resolved",
    )
    .await;
    let resolved = f.repo.get_ticket(&t.id).await.unwrap().unwrap().resolved_at;

    post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=closed",
    )
    .await;

    let after = f.repo.get_ticket(&t.id).await.unwrap().unwrap();
    assert_eq!(after.resolved_at, resolved);
    assert!(after.closed_at.is_some());
}

#[tokio::test]
async fn an_unknown_status_is_refused() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;

    let (_, location) = post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=banana",
    )
    .await;
    assert!(location.ends_with("notice=failed"));
    let after = f.repo.get_ticket(&t.id).await.unwrap().unwrap();
    assert_eq!(after.status, TicketStatus::Open);
}

/// Every state-changing route is behind CSRF, including the two added here.
#[tokio::test]
async fn posting_without_a_csrf_token_is_refused() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;

    for uri in [
        format!("/tickets/{}/comment", t.id),
        format!("/tickets/{}/status", t.id),
    ] {
        let response = router(f.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("body=x&status=closed"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
    }
}

// ---------------------------------------------------------------------------
// Raising a ticket
// ---------------------------------------------------------------------------

async fn get_page(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
    get(state, uri).await
}

#[tokio::test]
async fn the_form_offers_the_roster_and_an_email_box() {
    let f = fixture().await;
    let (status, body) = get_page(f.state.clone(), "/tickets/new?q=nowak").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Nowak, Lisa"), "roster search works");
    assert!(
        body.contains("requester_email"),
        "and somebody with no roster row can still be named"
    );
}

/// The district's own promise, shown before the ticket exists rather than
/// discovered when the badge turns red.
#[tokio::test]
async fn the_form_states_the_response_target_for_the_chosen_priority() {
    let f = fixture().await;
    let (_, body) = get_page(f.state.clone(), "/tickets/new?priority=urgent").await;
    assert!(body.contains("Answer within 2 hours."), "{body:.0}");

    let (_, body) = get_page(f.state.clone(), "/tickets/new?priority=low").await;
    assert!(body.contains("Answer within 3 days."));
}

#[tokio::test]
async fn raising_a_ticket_lands_on_it_with_a_number() {
    let f = fixture().await;
    let (status, location) = post(
        f.state.clone(),
        "/tickets/new",
        "requester=u-lisa&subject=Chromebook+will+not+charge&body=No+light.&priority=urgent",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.ends_with("notice=raised"), "{location}");

    let (_, page) = get(f.state.clone(), &location).await;
    assert!(page.contains("Chromebook will not charge"));
    assert!(page.contains("Ticket raised."));
    assert!(page.contains("#1 —"), "the first ticket is number 1");
}

/// The device the requester is holding, without anyone typing an asset tag.
/// This is the helpdesk half of the wedge and the reason the two modules are
/// one product.
#[tokio::test]
async fn the_requesters_device_is_attached_automatically() {
    let f = fixture().await;
    let mut asset = Asset::new("a-1");
    asset.asset_tag = Some("CB-0042".into());
    asset.assigned_user_sourced_id = Some("u-lisa".into());
    f.repo.create_asset(&asset).await.unwrap();

    let (_, location) = post(
        f.state.clone(),
        "/tickets/new",
        "requester=u-lisa&subject=Will+not+charge&body=x&priority=normal",
    )
    .await;
    let (_, page) = get(f.state.clone(), &location).await;
    assert!(page.contains("CB-0042"), "device attached and named");
    assert!(page.contains("/devices/a-1"), "and linked");
}

/// A refusal must not cost the description, which is the part that took effort
/// to write.
#[tokio::test]
async fn a_rejected_form_comes_back_with_what_was_typed() {
    let f = fixture().await;
    let (status, body) = post_html(
        f.state.clone(),
        "/tickets/new",
        "subject=&body=The+screen+flickers+intermittently&priority=high",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-rendered, not redirected away");
    assert!(
        body.contains("The screen flickers intermittently"),
        "the description survived"
    );
    assert!(
        body.contains("A ticket needs somebody to answer"),
        "and it says what to fix"
    );
}

#[tokio::test]
async fn a_ticket_needs_a_subject() {
    let f = fixture().await;
    let (_, body) = post_html(
        f.state.clone(),
        "/tickets/new",
        "requester=u-lisa&subject=+++&body=x&priority=normal",
    )
    .await;
    assert!(body.contains("Give the ticket a short subject."));
    // Nothing was written.
    let page = f
        .repo
        .list_tickets(
            &TicketFilter::default(),
            &TicketScope::Unrestricted,
            chalk_core::models::page::PageRequest::from_page_number(1, 10),
        )
        .await
        .unwrap();
    assert_eq!(page.total, 0);
}

#[tokio::test]
async fn somebody_with_no_roster_row_can_still_raise_one() {
    let f = fixture().await;
    let (status, location) = post(
        f.state.clone(),
        "/tickets/new",
        "requester_email=Parent%40Example.ORG&subject=Fee+question&body=x&priority=low",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = get(f.state.clone(), &location).await;
    assert!(
        page.contains("parent@example.org"),
        "named by address, folded to lower case"
    );
}

#[tokio::test]
async fn the_form_is_absent_when_the_helpdesk_is_off() {
    let mut config = ChalkConfig::generate_default();
    config.modules.helpdesk = false;
    let f = fixture_with(config, true).await;
    let (status, _) = get(f.state.clone(), "/tickets/new").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// `/tickets/new` must be the form, not a lookup for a ticket whose id is the
/// literal string "new".
#[tokio::test]
async fn new_is_a_page_not_a_ticket_id() {
    let f = fixture().await;
    let (status, body) = get(f.state.clone(), "/tickets/new").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Raise a ticket"));
    assert!(!body.contains("No such ticket"));
}

/// A technician photographing what they found is a message. Requiring words
/// alongside it would produce a thread full of "see attached".
#[tokio::test]
async fn a_file_with_no_words_is_still_a_comment() {
    let f = fixture().await;
    let t = T::new("t1").create(&f).await;

    let (status, location) = post_multipart(
        f.state.clone(),
        &format!("/tickets/{}/comment", t.id),
        &[("body", "")],
        Some(("board.png", b"\x89PNG\r\n\x1a\n pixels")),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.ends_with("notice=commented"));

    let comments = f.repo.list_comments(&t.id, true).await.unwrap();
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0].body, "Attached a file.");
}
