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
