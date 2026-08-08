//! Ticket-raising policy.
//!
//! The two things worth most here: a response target that is the same however
//! the request arrived, and a device attachment that stays silent when it does
//! not know. Both are places where being confidently wrong is worse than being
//! blank.

use super::*;

use chrono::TimeZone;

use crate::db::repository::{AssetRepository, OrgRepository, UserRepository};
use crate::db::sqlite::SqliteRepository;
use crate::db::DatabasePool;
use crate::models::asset::Asset;
use crate::models::common::{OrgType, RoleType, Status};
use crate::models::org::Org;
use crate::models::user::User;

fn at(h: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 2, h, 0, 0).unwrap()
}

/// A repository with the roster rows the asset foreign keys require.
///
/// `assets.assigned_user_sourced_id` and `assets.school_org_sourced_id` are
/// real foreign keys, so a device cannot be seeded for a user who does not
/// exist — which is the correct schema and a fixture that forgets it fails
/// loudly rather than silently testing nothing.
async fn repo() -> Arc<SqliteRepository> {
    let repo = match DatabasePool::new_sqlite_memory().await.unwrap() {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    for (id, name) in [("org-hs", "Springfield High"), ("org-ms", "Kennedy Middle")] {
        repo.upsert_org(&Org {
            sourced_id: id.into(),
            status: Status::Active,
            date_last_modified: at(0),
            metadata: None,
            name: name.into(),
            org_type: OrgType::School,
            identifier: None,
            parent: None,
            children: vec![],
        })
        .await
        .unwrap();
    }
    repo.upsert_user(&User {
        sourced_id: "u-lisa".into(),
        status: Status::Active,
        date_last_modified: at(0),
        metadata: None,
        username: "lisa.nowak".into(),
        user_ids: vec![],
        enabled_user: true,
        given_name: "Lisa".into(),
        family_name: "Nowak".into(),
        middle_name: None,
        role: RoleType::Teacher,
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
    repo
}

async fn device_for(repo: &Arc<SqliteRepository>, id: &str, user: Option<&str>) {
    let mut a = Asset::new(id);
    a.asset_tag = Some(format!("CB-{id}"));
    a.assigned_user_sourced_id = user.map(str::to_string);
    repo.create_asset(&a).await.unwrap();
}

fn request(subject: &str) -> NewTicket {
    NewTicket {
        requester_user_sourced_id: Some("u-lisa".into()),
        subject: subject.into(),
        body: "It stopped working.".into(),
        ..Default::default()
    }
}

fn service(config: HelpdeskConfig, assets: Option<Arc<dyn AssetRepository>>) -> TicketService {
    TicketService::new(config, assets)
}

// ---------------------------------------------------------------------------
// The response target
// ---------------------------------------------------------------------------

/// Each priority gets its own target, and the arithmetic is exact — a test
/// that only asserted "some target was set" would pass with every priority
/// mapped to the same number, which is the whole thing this is for.
#[tokio::test]
async fn each_priority_gets_its_own_response_target() {
    let svc = service(HelpdeskConfig::default(), None);
    let expected = [
        (TicketPriority::Urgent, 2),
        (TicketPriority::High, 8),
        (TicketPriority::Normal, 24),
        (TicketPriority::Low, 72),
    ];

    let mut seen = Vec::new();
    for (priority, hours) in expected {
        let mut new = request("Screen");
        new.priority = priority;
        let t = svc.prepare_at("t", new, at(9)).await.unwrap();
        assert_eq!(
            t.sla_due_at,
            Some(at(9) + Duration::hours(hours)),
            "{priority} target"
        );
        seen.push(t.sla_due_at);
    }

    seen.dedup();
    assert_eq!(seen.len(), 4, "the four priorities must not share a target");
}

/// Each priority also gets its own *resolution* target — the second SLA — and
/// it is looser than the first-response one, because answering and fixing are
/// different promises.
#[tokio::test]
async fn each_priority_gets_its_own_resolution_target() {
    let svc = service(HelpdeskConfig::default(), None);
    let expected = [
        (TicketPriority::Urgent, 8),
        (TicketPriority::High, 24),
        (TicketPriority::Normal, 72),
        (TicketPriority::Low, 168),
    ];

    for (priority, hours) in expected {
        let mut new = request("Screen");
        new.priority = priority;
        let t = svc.prepare_at("t", new, at(9)).await.unwrap();
        assert_eq!(
            t.resolution_due_at,
            Some(at(9) + Duration::hours(hours)),
            "{priority} resolution target"
        );
        // Resolution is never sooner than first response.
        assert!(
            t.resolution_due_at >= t.sla_due_at,
            "{priority}: resolution target must not precede the response target"
        );
    }
}

/// The same request raised through three different surfaces gets the same
/// deadline. This is the reason the policy is not in the handlers: an
/// email-sourced ticket, from the person least able to chase it, must not
/// quietly get a worse target than one typed by an administrator.
#[tokio::test]
async fn the_target_does_not_depend_on_how_the_request_arrived() {
    let svc = service(HelpdeskConfig::default(), None);
    let mut targets = Vec::new();
    for source in [TicketSource::Portal, TicketSource::Email, TicketSource::Api] {
        let mut new = request("Screen");
        new.source = source;
        targets.push(svc.prepare_at("t", new, at(9)).await.unwrap().sla_due_at);
    }
    targets.dedup();
    assert_eq!(targets.len(), 1, "one policy, whatever the door");
}

/// A district that does not want to be measured on a priority gets no target,
/// rather than a deadline that is already in the past.
#[tokio::test]
async fn a_non_positive_target_means_no_target() {
    let config = HelpdeskConfig {
        low_response_hours: 0,
        ..Default::default()
    };
    let svc = service(config, None);
    let mut new = request("Question");
    new.priority = TicketPriority::Low;
    let t = svc.prepare_at("t", new, at(9)).await.unwrap();
    assert_eq!(t.sla_due_at, None);
    assert!(!t.is_breached(at(23)), "and it can never be past due");
}

// ---------------------------------------------------------------------------
// Attaching the device — the helpdesk half of the wedge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_requesters_own_device_is_attached_without_them_typing_it() {
    let repo = repo().await;
    device_for(&repo, "a-1", Some("u-lisa")).await;
    let svc = service(HelpdeskConfig::default(), Some(repo.clone()));

    let t = svc
        .prepare_at("t", request("Will not charge"), at(9))
        .await
        .unwrap();
    assert_eq!(t.asset_id.as_deref(), Some("a-1"));
}

/// Two devices is not a guess to make. The wrong asset tag on a repair ticket
/// sends a technician to the wrong machine; a blank one sends them to look,
/// and the user's page shows both.
#[tokio::test]
async fn an_ambiguous_assignment_attaches_nothing() {
    let repo = repo().await;
    device_for(&repo, "a-1", Some("u-lisa")).await;
    device_for(&repo, "a-2", Some("u-lisa")).await;
    let svc = service(HelpdeskConfig::default(), Some(repo.clone()));

    let t = svc
        .prepare_at("t", request("Will not charge"), at(9))
        .await
        .unwrap();
    assert_eq!(t.asset_id, None);
}

#[tokio::test]
async fn a_device_named_explicitly_wins_over_the_assignment() {
    let repo = repo().await;
    device_for(&repo, "a-1", Some("u-lisa")).await;
    device_for(&repo, "a-9", None).await;
    let svc = service(HelpdeskConfig::default(), Some(repo.clone()));

    let mut new = request("Cart projector");
    new.asset_id = Some("a-9".into());
    let t = svc.prepare_at("t", new, at(9)).await.unwrap();
    assert_eq!(
        t.asset_id.as_deref(),
        Some("a-9"),
        "the person in front of the device knows better than the assignment"
    );
}

#[tokio::test]
async fn nothing_is_attached_when_the_district_turned_it_off() {
    let repo = repo().await;
    device_for(&repo, "a-1", Some("u-lisa")).await;
    let config = HelpdeskConfig {
        attach_requester_device: false,
        ..Default::default()
    };
    let svc = service(config, Some(repo.clone()));

    let t = svc
        .prepare_at("t", request("Will not charge"), at(9))
        .await
        .unwrap();
    assert_eq!(t.asset_id, None);
}

/// The helpdesk works without the device module — it just stops attaching.
/// Refusing tickets because the inventory is absent would make one module's
/// absence break another's core function.
#[tokio::test]
async fn the_helpdesk_works_with_no_device_inventory_at_all() {
    let svc = service(HelpdeskConfig::default(), None);
    let t = svc
        .prepare_at("t", request("Will not charge"), at(9))
        .await
        .unwrap();
    assert_eq!(t.asset_id, None);
    assert!(t.sla_due_at.is_some(), "and still gets a response target");
}

/// An email from someone with no roster row cannot have a device looked up,
/// and must not error trying.
#[tokio::test]
async fn a_requester_with_no_roster_row_simply_gets_no_device() {
    let repo = repo().await;
    device_for(&repo, "a-1", Some("u-lisa")).await;
    let svc = service(HelpdeskConfig::default(), Some(repo.clone()));

    let new = NewTicket {
        requester_user_sourced_id: None,
        requester_email: Some("Parent@Example.ORG".into()),
        subject: "Fee question".into(),
        source: TicketSource::Email,
        ..Default::default()
    };
    let t = svc.prepare_at("t", new, at(9)).await.unwrap();
    assert_eq!(t.asset_id, None);
    assert_eq!(
        t.requester_email.as_deref(),
        Some("parent@example.org"),
        "addresses are folded so a reply threads onto the same person"
    );
}

/// The school comes from the device when the form did not say: a device knows
/// which building it lives in, and a requester may work in several.
#[tokio::test]
async fn the_school_is_taken_from_the_attached_device() {
    let repo = repo().await;
    let mut a = Asset::new("a-1");
    a.assigned_user_sourced_id = Some("u-lisa".into());
    a.school_org_sourced_id = Some("org-hs".into());
    repo.create_asset(&a).await.unwrap();
    let svc = service(HelpdeskConfig::default(), Some(repo.clone()));

    let t = svc
        .prepare_at("t", request("Will not charge"), at(9))
        .await
        .unwrap();
    assert_eq!(t.school_org_sourced_id.as_deref(), Some("org-hs"));
}

#[tokio::test]
async fn an_explicit_school_is_not_overwritten() {
    let repo = repo().await;
    let mut a = Asset::new("a-1");
    a.assigned_user_sourced_id = Some("u-lisa".into());
    a.school_org_sourced_id = Some("org-hs".into());
    repo.create_asset(&a).await.unwrap();
    let svc = service(HelpdeskConfig::default(), Some(repo.clone()));

    let mut new = request("Will not charge");
    new.school_org_sourced_id = Some("org-ms".into());
    let t = svc.prepare_at("t", new, at(9)).await.unwrap();
    assert_eq!(t.school_org_sourced_id.as_deref(), Some("org-ms"));
}

// ---------------------------------------------------------------------------
// Refusing what cannot be answered
// ---------------------------------------------------------------------------

/// A ticket nobody can be answered to is not a ticket; it is a note that will
/// sit in the queue counting as work forever.
#[test]
fn a_ticket_needs_somebody_to_answer() {
    let new = NewTicket {
        subject: "Something broke".into(),
        ..Default::default()
    };
    assert_eq!(new.validate(), Err(NewTicketError::NoRequester));

    // Whitespace is not a requester.
    let blank = NewTicket {
        requester_user_sourced_id: Some("   ".into()),
        requester_email: Some("".into()),
        subject: "Something broke".into(),
        ..Default::default()
    };
    assert_eq!(blank.validate(), Err(NewTicketError::NoRequester));

    // Either identifier alone is enough.
    let by_email = NewTicket {
        requester_email: Some("parent@example.org".into()),
        subject: "Something broke".into(),
        ..Default::default()
    };
    assert_eq!(by_email.validate(), Ok(()));
}

#[test]
fn a_ticket_needs_a_subject() {
    let mut new = request("   ");
    assert_eq!(new.validate(), Err(NewTicketError::EmptySubject));

    new.subject = "x".repeat(MAX_SUBJECT + 1);
    assert_eq!(new.validate(), Err(NewTicketError::SubjectTooLong));

    new.subject = "x".repeat(MAX_SUBJECT);
    assert_eq!(new.validate(), Ok(()), "the limit itself is allowed");
}

#[test]
fn an_over_long_description_is_refused_by_characters_not_bytes() {
    let mut new = request("Screen");
    // Multi-byte characters must not count double: a description in a
    // non-Latin script would otherwise be rejected at half the length.
    new.body = "é".repeat(MAX_BODY);
    assert_eq!(new.validate(), Ok(()));

    new.body = "é".repeat(MAX_BODY + 1);
    assert_eq!(new.validate(), Err(NewTicketError::BodyTooLong));
}

/// Every refusal tells the person what to do about it. A form that says
/// "validation failed" makes them guess.
#[test]
fn every_refusal_is_addressed_to_the_person_who_typed_it() {
    for e in [
        NewTicketError::NoRequester,
        NewTicketError::EmptySubject,
        NewTicketError::SubjectTooLong,
        NewTicketError::BodyTooLong,
    ] {
        let m = e.message();
        assert!(!m.is_empty());
        assert!(
            m.ends_with('.'),
            "{m:?} should read as a sentence to a human"
        );
        assert!(
            !m.to_lowercase().contains("invalid") && !m.to_lowercase().contains("error"),
            "{m:?} describes the fix, not the violation"
        );
    }
}

#[tokio::test]
async fn preparing_an_invalid_ticket_fails_before_touching_the_database() {
    let svc = service(HelpdeskConfig::default(), None);
    let new = NewTicket {
        subject: "No requester".into(),
        ..Default::default()
    };
    let err = svc.prepare_at("t", new, at(9)).await.unwrap_err();
    assert!(matches!(err, ChalkError::Validation(_)));
}

/// Subject and body are stored trimmed, so a queue row does not start with
/// three spaces because somebody pasted.
#[tokio::test]
async fn text_is_trimmed() {
    let svc = service(HelpdeskConfig::default(), None);
    let mut new = request("  Will not charge  ");
    new.body = "\n  It stopped.  \n".into();
    let t = svc.prepare_at("t", new, at(9)).await.unwrap();
    assert_eq!(t.subject, "Will not charge");
    assert_eq!(t.body, "It stopped.");
}

/// The number is the database's to assign, not the service's — it has to be
/// unique under concurrent submissions and only the insert transaction can
/// promise that.
#[tokio::test]
async fn the_service_does_not_invent_a_number() {
    let svc = service(HelpdeskConfig::default(), None);
    let t = svc.prepare_at("t", request("Screen"), at(9)).await.unwrap();
    assert_eq!(t.number, 0, "left for create_ticket to allocate");
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// The service routes at creation, so a ticket that arrives by any surface
/// gets the same owner. Rules are matched most-specific-first, and a service
/// with no routing wired leaves the ticket unassigned as before.
#[tokio::test]
async fn a_matching_rule_assigns_the_ticket_at_creation() {
    use crate::db::repository::{ConsoleUserRepository, RoutingRuleRepository};
    use crate::models::console_user::{ConsoleRole, ConsoleUser, ConsoleUserStatus};
    use crate::models::routing::RoutingRule;

    let repo = repo().await;
    repo.create_console_user(&ConsoleUser {
        id: "tech-ana".into(),
        email: "ana@district.test".into(),
        display_name: "Ana".into(),
        password_hash: None,
        role: ConsoleRole::Technician,
        status: ConsoleUserStatus::Active,
        created_at: at(0),
        updated_at: at(0),
    })
    .await
    .unwrap();
    repo.create_routing_rule(&RoutingRule {
        id: "r-1".into(),
        category: Some("hardware".into()),
        school_org_sourced_id: None,
        assignee_console_user_id: "tech-ana".into(),
        created_at: at(0),
    })
    .await
    .unwrap();

    let svc = TicketService::new(HelpdeskConfig::default(), None).with_routing(repo.clone());

    let mut new = request("Cracked screen");
    new.category = Some("Hardware".into());
    let routed = svc.prepare_at("t", new, at(9)).await.unwrap();
    assert_eq!(
        routed.assignee_console_user_id.as_deref(),
        Some("tech-ana"),
        "case-insensitive category match routes to the technician"
    );

    let unrouted = svc
        .prepare_at("t2", request("Password reset"), at(9))
        .await
        .unwrap();
    assert_eq!(
        unrouted.assignee_console_user_id, None,
        "no matching rule leaves it unassigned"
    );

    // No routing wired at all: unchanged behavior.
    let plain = service(HelpdeskConfig::default(), None);
    let mut new = request("Cracked screen");
    new.category = Some("hardware".into());
    let t = plain.prepare_at("t3", new, at(9)).await.unwrap();
    assert_eq!(t.assignee_console_user_id, None);
}
