//! Ticket model tests.
//!
//! These cover the judgements encoded in the type rather than the field list:
//! when an SLA clock runs, what counts as breached, and what a first response
//! is. Each is a promise a district measures its helpdesk against.

use super::*;

fn ticket() -> Ticket {
    Ticket::new("t-1", "Screen is cracked")
}

/// The clock pauses while the district is waiting on its own user. An SLA that
/// ran during `waiting` would hold a technician to time they cannot spend.
#[test]
fn the_sla_clock_runs_only_while_the_ticket_is_actionable() {
    assert!(TicketStatus::Open.clock_runs());
    assert!(TicketStatus::InProgress.clock_runs());
    assert!(
        !TicketStatus::Waiting.clock_runs(),
        "waiting on the requester"
    );
    assert!(!TicketStatus::Resolved.clock_runs());
    assert!(!TicketStatus::Closed.clock_runs());
}

#[test]
fn only_resolved_and_closed_are_settled() {
    assert!(TicketStatus::Resolved.is_settled());
    assert!(TicketStatus::Closed.is_settled());
    for s in [
        TicketStatus::Open,
        TicketStatus::InProgress,
        TicketStatus::Waiting,
    ] {
        assert!(!s.is_settled(), "{s:?} still needs work");
    }
}

/// A settled ticket is never breached, however late it was resolved.
/// Past-tense lateness belongs in a report, not in a queue badge telling a
/// technician what to do next.
#[test]
fn a_settled_ticket_is_never_breached_however_late_it_was() {
    let now = Utc::now();
    let mut t = ticket();
    t.sla_due_at = Some(now - chrono::Duration::days(3));

    assert!(t.is_breached(now), "open and overdue");

    t.status = TicketStatus::Resolved;
    assert!(!t.is_breached(now), "resolved late is not breached now");

    t.status = TicketStatus::Closed;
    assert!(!t.is_breached(now));
}

/// Resolution breach follows the same rules as first-response breach, measured
/// against `resolution_due_at`: overdue-and-open breaches, a settled or
/// paused-on-the-requester ticket does not, and no target never breaches.
#[test]
fn resolution_breach_mirrors_first_response_breach() {
    let now = Utc::now();
    let mut t = ticket();
    t.resolution_due_at = Some(now - chrono::Duration::days(1));
    assert!(
        t.is_resolution_breached(now),
        "open and past resolution target"
    );

    t.status = TicketStatus::Resolved;
    assert!(!t.is_resolution_breached(now), "settled is never breached");

    t.status = TicketStatus::Waiting;
    assert!(
        !t.is_resolution_breached(now),
        "a clock paused on the requester cannot run out"
    );

    t.status = TicketStatus::Open;
    t.resolution_due_at = None;
    assert!(!t.is_resolution_breached(now), "no target, no breach");
}

/// A ticket with no SLA cannot breach one. Districts may never set targets at
/// all, and a badge claiming otherwise would be noise.
#[test]
fn a_ticket_with_no_sla_never_breaches() {
    let mut t = ticket();
    t.sla_due_at = None;
    assert!(!t.is_breached(Utc::now()));
    assert!(!t.is_breached(Utc::now() + chrono::Duration::days(365)));
}

/// The boundary is strict: due exactly now is not yet late.
#[test]
fn a_ticket_due_this_instant_is_not_yet_breached() {
    let now = Utc::now();
    let mut t = ticket();
    t.sla_due_at = Some(now);
    assert!(!t.is_breached(now));
    assert!(t.is_breached(now + chrono::Duration::seconds(1)));
}

/// Awaiting-first-response stops mattering once the ticket is settled — a
/// resolved ticket nobody commented on is finished, not neglected.
#[test]
fn awaiting_a_first_response_stops_at_settled() {
    let mut t = ticket();
    assert!(t.awaiting_first_response());

    t.first_response_at = Some(Utc::now());
    assert!(!t.awaiting_first_response());

    let mut untouched = ticket();
    untouched.status = TicketStatus::Resolved;
    assert!(
        !untouched.awaiting_first_response(),
        "resolved without a comment is done, not waiting"
    );
}

/// An internal note is internal by construction, so a helper cannot
/// accidentally produce a visible one.
#[test]
fn an_internal_note_is_internal_and_a_reply_is_not() {
    let note = NewTicketComment::internal_note("t-1", "tech-1", "ordered a part");
    assert!(note.is_internal);
    assert_eq!(note.ticket_id, "t-1");
    assert_eq!(note.author_user_sourced_id.as_deref(), Some("tech-1"));

    let reply = NewTicketComment::reply("t-1", "tech-1", "we have your device");
    assert!(!reply.is_internal);
}

/// A new ticket carries number zero: the repository allocates it inside the
/// insert transaction. Assigning one here would allocate outside that
/// transaction, which is how two tickets end up sharing a number.
#[test]
fn a_new_ticket_has_no_number_until_the_repository_gives_it_one() {
    assert_eq!(ticket().number, 0);
    assert_eq!(ticket().status, TicketStatus::Open);
    assert_eq!(ticket().priority, TicketPriority::Normal);
    assert_eq!(ticket().source, TicketSource::Portal);
}

/// Sort columns are a closed set, because the value is interpolated into
/// `ORDER BY` and must never carry caller input.
#[test]
fn only_known_sort_columns_parse() {
    for raw in [
        "number",
        "created_at",
        "updated_at",
        "sla_due_at",
        "priority",
        "status",
    ] {
        let parsed = TicketSort::parse(raw).unwrap_or_else(|| panic!("{raw} should parse"));
        assert_eq!(parsed.as_sql_column(), raw);
    }
    assert!(TicketSort::parse("subject; DROP TABLE tickets").is_none());
    assert!(TicketSort::parse("").is_none());
}

/// Paging is stable because the tiebreaker is unique and monotonic. Without
/// one, two tickets sharing a sort value can swap between pages and a
/// technician sees the same row twice or never.
#[test]
fn the_order_by_always_carries_a_unique_tiebreaker() {
    let f = TicketFilter {
        sort: TicketSort::Priority,
        ..Default::default()
    };
    let sql = f.order_by_sql("t.");
    assert!(sql.contains("t.priority"));
    assert!(sql.ends_with("t.number ASC"), "got {sql}");
}

// ---------------------------------------------------------------------------
// The breach rule, which used to exist in three disagreeing copies
// ---------------------------------------------------------------------------

/// The guard. `is_breached` (Rust) and `clock_running_sql_in` (both drivers)
/// must agree with `clock_runs` for **every** status, so adding a status or
/// changing which ones pause the clock cannot leave one of the three behind.
///
/// This is written as a sweep rather than three assertions because the bug it
/// replaces was precisely that someone updated one copy and not the others.
#[test]
fn the_breach_rule_agrees_with_the_clock_for_every_status() {
    let now = Utc::now();
    let sql = TicketStatus::clock_running_sql_in();

    for status in TicketStatus::ALL {
        let mut t = Ticket::new("t", "s");
        t.status = *status;
        t.sla_due_at = Some(now - chrono::Duration::hours(1));

        assert_eq!(
            t.is_breached(now),
            status.clock_runs(),
            "is_breached disagrees with clock_runs for {status}"
        );

        let in_sql = sql.contains(&format!("'{}'", status.as_str()));
        assert_eq!(
            in_sql,
            status.clock_runs(),
            "the SQL status list disagrees with clock_runs for {status}: {sql}"
        );
    }
}

/// A ticket waiting on its requester is never past due. The technician cannot
/// clear that badge by doing anything, and a badge you cannot act on is noise
/// that teaches people to ignore the ones that matter.
#[test]
fn a_ticket_waiting_on_its_requester_is_not_past_due() {
    let now = Utc::now();
    let mut t = Ticket::new("t", "Projector will not mirror");
    t.status = TicketStatus::Waiting;
    t.sla_due_at = Some(now - chrono::Duration::days(4));
    assert!(!t.is_breached(now));

    // ...and it becomes past due again the moment the requester answers and a
    // technician moves it back.
    t.status = TicketStatus::Open;
    assert!(t.is_breached(now));
}

/// No target set means nothing to miss.
#[test]
fn a_ticket_with_no_response_target_is_never_past_due() {
    let mut t = Ticket::new("t", "s");
    t.status = TicketStatus::Open;
    t.sla_due_at = None;
    assert!(!t.is_breached(Utc::now()));
}

// ---------------------------------------------------------------------------
// Sorting by things whose stored form is a word
// ---------------------------------------------------------------------------

/// Sorting by priority must order by severity. Alphabetically the stored
/// strings run high, low, normal, urgent — which puts *low* above *normal*
/// and buries *high*, the exact opposite of what a triage sort is for.
#[test]
fn priority_sorts_by_severity_not_alphabetically() {
    let mut ranked: Vec<_> = TicketPriority::ALL.iter().collect();
    ranked.sort_by_key(|p| p.severity_rank());
    assert_eq!(
        ranked.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        vec!["low", "normal", "high", "urgent"]
    );

    let mut alphabetical: Vec<_> = TicketPriority::ALL.iter().map(|p| p.as_str()).collect();
    alphabetical.sort();
    assert_ne!(
        alphabetical,
        ranked.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "if these ever agree the CASE is pointless and this test is vacuous"
    );
}

#[test]
fn status_sorts_by_workflow_not_alphabetically() {
    let mut ranked: Vec<_> = TicketStatus::ALL.iter().collect();
    ranked.sort_by_key(|s| s.workflow_rank());
    assert_eq!(
        ranked.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        vec!["open", "in_progress", "waiting", "resolved", "closed"]
    );
}

/// Every rank must be distinct, or two priorities tie and the order becomes
/// whatever the storage engine felt like.
#[test]
fn ranks_are_distinct() {
    let mut p: Vec<_> = TicketPriority::ALL
        .iter()
        .map(|x| x.severity_rank())
        .collect();
    p.sort_unstable();
    p.dedup();
    assert_eq!(p.len(), TicketPriority::ALL.len());

    let mut s: Vec<_> = TicketStatus::ALL
        .iter()
        .map(|x| x.workflow_rank())
        .collect();
    s.sort_unstable();
    s.dedup();
    assert_eq!(s.len(), TicketStatus::ALL.len());
}

/// The generated `ORDER BY` mentions every variant, so adding one without a
/// rank cannot silently sort to the end.
#[test]
fn the_order_by_case_covers_every_variant() {
    let by_priority = TicketFilter {
        sort: TicketSort::Priority,
        ..Default::default()
    }
    .order_by_sql("t.");
    for p in TicketPriority::ALL {
        assert!(
            by_priority.contains(&format!("'{}'", p.as_str())),
            "{} missing from {by_priority}",
            p.as_str()
        );
    }
    assert!(by_priority.contains("t.number"), "stable tiebreaker kept");

    let by_status = TicketFilter {
        sort: TicketSort::Status,
        ..Default::default()
    }
    .order_by_sql("");
    for s in TicketStatus::ALL {
        assert!(by_status.contains(&format!("'{}'", s.as_str())));
    }
}

/// A sort that is a plain column stays a plain column — no CASE, no alias bug.
#[test]
fn ordinary_sorts_are_left_alone() {
    let sql = TicketFilter {
        sort: TicketSort::CreatedAt,
        ..Default::default()
    }
    .order_by_sql("t.");
    assert!(sql.starts_with("ORDER BY t.created_at "), "{sql}");
    assert!(!sql.contains("CASE"));
}
