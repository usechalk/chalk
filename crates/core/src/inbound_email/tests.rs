//! Email ingestion.
//!
//! Three of these tests are load-bearing and the rest are conveniences. A
//! **loop** puts a school district in a mail exchange with itself. A missed
//! **retry** files the same complaint twice, every time the provider tries. A
//! trusted **spoof** lets anyone who can send mail act as somebody else.

use super::providers::{clean_message_id, parser_for, GenericInbound, PostmarkInbound};
use super::*;

use crate::config::HelpdeskConfig;
use crate::db::repository::{TicketRepository, UserRepository};
use crate::db::sqlite::SqliteRepository;
use crate::db::DatabasePool;
use crate::models::common::{RoleType, Status};
use chrono::{TimeZone, Utc};

/// A repository with the one roster row these tests attribute mail to.
///
/// `tickets.requester_user_sourced_id` is a real foreign key, so a ticket
/// cannot name a user who does not exist — correct schema, and a fixture that
/// forgets it fails loudly rather than quietly testing nothing.
async fn repo() -> Arc<SqliteRepository> {
    let repo = match DatabasePool::new_sqlite_memory().await.unwrap() {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    repo.upsert_user(&lisa()).await.unwrap();
    repo
}

fn lisa() -> User {
    User {
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
        role: RoleType::Teacher,
        identifier: None,
        email: Some("lisa@example.edu".into()),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec![],
        grades: vec![],
    }
}

/// An ingestor that knows exactly one roster address.
fn ingestor(repo: Arc<SqliteRepository>) -> EmailIngestor {
    let tickets: Arc<dyn TicketRepository> = repo;
    EmailIngestor::new(
        tickets.clone(),
        TicketService::new(HelpdeskConfig::default(), None),
        Box::new(|email| (email == "lisa@example.edu").then(lisa)),
    )
}

fn message(id: &str, subject: &str, body: &str) -> InboundMessage {
    InboundMessage {
        message_id: id.into(),
        from: "lisa@example.edu".into(),
        subject: subject.into(),
        body: body.into(),
        authentication: Authentication::Passed,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Loops
// ---------------------------------------------------------------------------

/// **The loop test.** Chalk emails a requester, their vacation responder
/// replies, that becomes a ticket, Chalk emails them about it. Each of these
/// headers is how a well-behaved auto-reply says "do not answer me".
#[tokio::test]
async fn automatic_mail_never_becomes_a_ticket() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());

    let mut m = message("auto-1", "Out of office", "I am away until Monday.");
    m.automatic = true;

    assert_eq!(
        ing.ingest(m).await.unwrap(),
        Ingested::Dropped(DropReason::Automatic)
    );
    assert_eq!(
        repo.count_tickets(
            &Default::default(),
            &crate::models::ticket::TicketScope::Unrestricted
        )
        .await
        .unwrap(),
        0
    );
}

#[test]
fn the_headers_that_mean_a_machine_sent_it() {
    // RFC 3834: `no` is what a person's mail carries, and the header is
    // usually absent entirely.
    assert!(!auto_submitted_is_automatic(""));
    assert!(!auto_submitted_is_automatic("no"));
    assert!(!auto_submitted_is_automatic(" No "));
    assert!(auto_submitted_is_automatic("auto-replied"));
    assert!(auto_submitted_is_automatic("auto-generated"));

    assert!(precedence_is_automatic("bulk"));
    assert!(precedence_is_automatic("  Junk "));
    assert!(precedence_is_automatic("list"));
    assert!(!precedence_is_automatic("normal"));
    assert!(!precedence_is_automatic(""));
}

/// Every provider must drop the same things, or a district switching provider
/// discovers a mail loop it did not have before.
#[test]
fn both_providers_recognise_the_same_automatic_headers() {
    for header in AUTOMATIC_HEADERS {
        let value = if header.eq_ignore_ascii_case("auto-submitted") {
            "auto-replied"
        } else {
            "yes"
        };

        let postmark = format!(
            r#"{{"MessageID":"m1","From":"a@b.c","Subject":"s","TextBody":"t",
                "Headers":[{{"Name":"{header}","Value":"{value}"}}]}}"#
        );
        assert!(
            PostmarkInbound
                .parse(postmark.as_bytes())
                .unwrap()
                .automatic,
            "postmark missed {header}"
        );

        let generic = format!(
            r#"{{"message_id":"m1","from":"a@b.c","subject":"s","body":"t",
                "headers":{{"{header}":"{value}"}}}}"#
        );
        assert!(
            GenericInbound.parse(generic.as_bytes()).unwrap().automatic,
            "generic missed {header}"
        );
    }
}

// ---------------------------------------------------------------------------
// Retries
// ---------------------------------------------------------------------------

/// **The retry test.** Providers re-deliver on any non-2xx, and Postmark keeps
/// trying for hours. The same message arriving twice must find the ticket it
/// already made.
#[tokio::test]
async fn a_redelivered_message_does_not_make_a_second_ticket() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());
    let m = message("dup-1", "Broken screen", "It is cracked.");

    let first = ing.ingest(m.clone()).await.unwrap();
    let second = ing.ingest(m).await.unwrap();

    let id = match first {
        Ingested::Raised(id) => id,
        other => panic!("expected a new ticket, got {other:?}"),
    };
    assert_eq!(second, Ingested::AlreadySeen(id));
    assert_eq!(
        repo.count_tickets(
            &Default::default(),
            &crate::models::ticket::TicketScope::Unrestricted
        )
        .await
        .unwrap(),
        1
    );
}

/// A message with no id cannot be deduplicated, so every retry would create
/// another ticket. Dropping it is the only safe answer.
#[tokio::test]
async fn a_message_with_no_id_is_refused_rather_than_duplicated() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());
    let mut m = message("", "Broken", "x");
    m.message_id = "   ".into();

    assert_eq!(
        ing.ingest(m).await.unwrap(),
        Ingested::Dropped(DropReason::NoMessageId)
    );
}

// ---------------------------------------------------------------------------
// Spoofing
// ---------------------------------------------------------------------------

/// **The spoofing test.** `From:` is a claim. Without the provider vouching
/// for the sending domain, anybody who can send mail could file tickets as the
/// superintendent — so the message becomes a ticket, attributed to the
/// address rather than to the person.
#[tokio::test]
async fn an_unauthenticated_sender_is_not_bound_to_a_roster_user() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());

    let mut m = message("spoof-1", "Broken screen", "It is cracked.");
    m.authentication = Authentication::Unverified;

    let Ingested::Raised(id) = ing.ingest(m).await.unwrap() else {
        panic!("it should still become a ticket");
    };
    let t = repo.get_ticket(&id).await.unwrap().unwrap();
    assert_eq!(
        t.requester_user_sourced_id, None,
        "an unverified From must not claim a roster identity"
    );
    assert_eq!(t.requester_email.as_deref(), Some("lisa@example.edu"));
}

#[tokio::test]
async fn an_authenticated_sender_is_matched_to_their_roster_row() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());

    let Ingested::Raised(id) = ing
        .ingest(message("ok-1", "Broken screen", "It is cracked."))
        .await
        .unwrap()
    else {
        panic!("expected a ticket");
    };
    let t = repo.get_ticket(&id).await.unwrap().unwrap();
    assert_eq!(t.requester_user_sourced_id.as_deref(), Some("u-lisa"));
}

// ---------------------------------------------------------------------------
// Threading
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_reply_threads_onto_the_ticket_it_answers() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());

    let Ingested::Raised(id) = ing
        .ingest(message("first-1", "Broken screen", "It is cracked."))
        .await
        .unwrap()
    else {
        panic!("expected a ticket");
    };

    let mut reply = message("reply-1", "Re: Broken screen", "It is worse today.");
    reply.in_reply_to = vec!["first-1".into()];

    assert_eq!(
        ing.ingest(reply).await.unwrap(),
        Ingested::Replied(id.clone())
    );
    assert_eq!(
        repo.count_tickets(
            &Default::default(),
            &crate::models::ticket::TicketScope::Unrestricted
        )
        .await
        .unwrap(),
        1,
        "a reply is not a new ticket"
    );
    let comments = repo.list_comments(&id, true).await.unwrap();
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0].body, "It is worse today.");
    assert!(
        !comments[0].is_internal,
        "mail from outside is never a note"
    );
}

/// Outlook drops `In-Reply-To` when somebody forwards rather than replies, so
/// the number in the subject is the fallback that keeps the thread together.
#[tokio::test]
async fn the_number_in_the_subject_threads_when_the_header_is_missing() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());

    let Ingested::Raised(id) = ing
        .ingest(message("first-2", "Broken screen", "cracked"))
        .await
        .unwrap()
    else {
        panic!("expected a ticket");
    };
    let number = repo.get_ticket(&id).await.unwrap().unwrap().number;

    let reply = message(
        "reply-2",
        &format!("Re: [#{number}] Broken screen"),
        "Still broken.",
    );
    assert_eq!(ing.ingest(reply).await.unwrap(), Ingested::Replied(id));
}

#[test]
fn a_ticket_number_is_read_out_of_a_subject() {
    assert_eq!(ticket_number_in_subject("Re: [#412] Broken"), Some(412));
    assert_eq!(ticket_number_in_subject("[#1] x"), Some(1));
    assert_eq!(ticket_number_in_subject("Broken screen"), None);
    assert_eq!(ticket_number_in_subject("[#notanumber] x"), None);
    assert_eq!(ticket_number_in_subject("[#] x"), None);
}

/// Threading must not depend on whether a provider kept the angle brackets: a
/// stored `<abc@x>` would never match an incoming `abc@x`, and the failure is
/// silent — a reply quietly becomes a new ticket.
#[tokio::test]
async fn angle_brackets_do_not_break_threading() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());

    let Ingested::Raised(id) = ing
        .ingest(message("bare-id@example.com", "Broken", "x"))
        .await
        .unwrap()
    else {
        panic!("expected a ticket");
    };

    let mut reply = message("reply-3", "Re: Broken", "still");
    reply.in_reply_to = vec![clean_message_id("<bare-id@example.com>")];
    assert_eq!(ing.ingest(reply).await.unwrap(), Ingested::Replied(id));
}

#[test]
fn message_ids_are_normalised() {
    assert_eq!(clean_message_id("<abc@x>"), "abc@x");
    assert_eq!(clean_message_id("  <abc@x>  "), "abc@x");
    assert_eq!(clean_message_id("abc@x"), "abc@x");
}

// ---------------------------------------------------------------------------
// What the ticket ends up saying
// ---------------------------------------------------------------------------

#[test]
fn quoted_history_is_removed_from_a_reply() {
    let body = "It is worse today.\n\nOn Monday, IT wrote:\n> Have you tried a different charger?\n> Let us know.";
    assert_eq!(strip_quoted(body), "It is worse today.");
}

#[test]
fn a_signature_is_removed() {
    let body = "Still broken.\n\n--\nLisa Nowak\nRoom 214";
    assert_eq!(strip_quoted(body), "Still broken.");
}

/// Conservative on purpose: guessing wrong here deletes what somebody wrote.
#[test]
fn ordinary_text_survives_untouched() {
    for body in [
        "It is cracked in the corner.",
        "Line one\nLine two\nLine three",
        "> is how I would write a quote in markdown\nbut this is my own text",
    ] {
        assert_eq!(strip_quoted(body), body.trim());
    }
}

#[test]
fn reply_prefixes_are_stripped_from_a_new_subject() {
    assert_eq!(strip_reply_prefixes("Re: Broken screen"), "Broken screen");
    assert_eq!(strip_reply_prefixes("RE: FW: Re: Broken"), "Broken");
    assert_eq!(strip_reply_prefixes("Fwd: Broken"), "Broken");
    assert_eq!(strip_reply_prefixes("Broken"), "Broken");
    // A subject that is nothing but prefixes keeps its original text rather
    // than becoming empty.
    assert_eq!(strip_reply_prefixes("Re:"), "Re:");
}

#[tokio::test]
async fn a_message_with_nothing_in_it_is_dropped() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());
    assert_eq!(
        ing.ingest(message("empty-1", "   ", "  ")).await.unwrap(),
        Ingested::Dropped(DropReason::Empty)
    );
}

#[tokio::test]
async fn a_subjectless_message_still_becomes_a_readable_ticket() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());
    let Ingested::Raised(id) = ing
        .ingest(message("nosub-1", "", "The projector will not turn on."))
        .await
        .unwrap()
    else {
        panic!("expected a ticket");
    };
    assert_eq!(
        repo.get_ticket(&id).await.unwrap().unwrap().subject,
        "(no subject)"
    );
}

/// The service assigns the response target, so mail gets the same deadline as
/// a request typed into the portal. This is the reason the policy is not in
/// the handlers.
#[tokio::test]
async fn mail_gets_the_same_response_target_as_every_other_door() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());
    let Ingested::Raised(id) = ing.ingest(message("sla-1", "Broken", "x")).await.unwrap() else {
        panic!("expected a ticket");
    };
    let t = repo.get_ticket(&id).await.unwrap().unwrap();
    assert!(t.sla_due_at.is_some());
    assert_eq!(t.source, TicketSource::Email);
}

// ---------------------------------------------------------------------------
// The provider adapters
// ---------------------------------------------------------------------------

#[test]
fn providers_are_selected_by_name() {
    assert_eq!(parser_for("postmark").unwrap().name(), "postmark");
    assert_eq!(parser_for("  Postmark ").unwrap().name(), "postmark");
    assert_eq!(parser_for("generic").unwrap().name(), "generic");
    assert!(parser_for("mailgun").is_none());

    // The advertised list must actually resolve, or an operator follows an
    // error message into another error.
    for name in super::providers::PROVIDERS {
        assert!(
            parser_for(name).is_some(),
            "{name} is advertised but absent"
        );
    }
}

#[test]
fn a_postmark_payload_becomes_a_message() {
    let body = br#"{
        "MessageID": "<pm-1@example.com>",
        "From": "Lisa Nowak <lisa@example.edu>",
        "Subject": "Re: [#12] Broken screen",
        "TextBody": "full body with quote",
        "StrippedTextReply": "just the new bit",
        "Headers": [
            {"Name": "In-Reply-To", "Value": "<parent-1@example.com>"},
            {"Name": "References", "Value": "<older@x> <parent-1@example.com>"},
            {"Name": "Received-SPF", "Value": "Pass (sender is authorized)"}
        ],
        "Attachments": [{"Name": "photo.png", "Content": "aGVsbG8="}]
    }"#;

    let m = PostmarkInbound.parse(body).unwrap();
    assert_eq!(m.message_id, "pm-1@example.com", "brackets stripped");
    assert_eq!(
        m.body, "just the new bit",
        "Postmark's own stripping beats ours — it knows the outbound message"
    );
    assert_eq!(
        m.in_reply_to[0], "parent-1@example.com",
        "direct parent first"
    );
    assert!(m.in_reply_to.contains(&"older@x".to_string()));
    assert_eq!(m.authentication, Authentication::Passed);
    assert!(!m.automatic);
    assert_eq!(m.attachments.len(), 1);
    assert_eq!(m.attachments[0].bytes, b"hello");
}

/// A first message has no stripped reply, so the full body must be used or
/// every new ticket would arrive empty.
#[test]
fn a_first_postmark_message_uses_the_full_body() {
    let body = br#"{"MessageID":"pm-2","From":"a@b.c","Subject":"s",
        "TextBody":"the whole thing","StrippedTextReply":""}"#;
    assert_eq!(PostmarkInbound.parse(body).unwrap().body, "the whole thing");
}

/// A forwarded message often fails SPF while keeping a valid DKIM signature.
/// Requiring both would leave everyone behind a forwarder permanently
/// unattributed.
#[test]
fn either_spf_or_dkim_is_enough_to_attribute_a_sender() {
    let spf_only = br#"{"MessageID":"a","From":"a@b.c","Subject":"s","TextBody":"t",
        "Headers":[{"Name":"Received-SPF","Value":"pass"}]}"#;
    let dkim_only = br#"{"MessageID":"a","From":"a@b.c","Subject":"s","TextBody":"t",
        "Headers":[{"Name":"Received-SPF","Value":"fail"},
                   {"Name":"DKIM-Signature","Value":"v=1; a=rsa-sha256;"}]}"#;
    let neither = br#"{"MessageID":"a","From":"a@b.c","Subject":"s","TextBody":"t",
        "Headers":[{"Name":"Received-SPF","Value":"fail"}]}"#;

    assert_eq!(
        PostmarkInbound.parse(spf_only).unwrap().authentication,
        Authentication::Passed
    );
    assert_eq!(
        PostmarkInbound.parse(dkim_only).unwrap().authentication,
        Authentication::Passed
    );
    assert_eq!(
        PostmarkInbound.parse(neither).unwrap().authentication,
        Authentication::Unverified
    );
}

#[test]
fn a_generic_payload_becomes_a_message() {
    let body = br#"{
        "message_id": "g-1",
        "from": "lisa@example.edu",
        "subject": "Broken screen",
        "body": "It is cracked.",
        "in_reply_to": ["<parent@x>"],
        "authenticated": true,
        "attachments": [{"filename": "photo.png", "content_base64": "aGVsbG8="}]
    }"#;

    let m = GenericInbound.parse(body).unwrap();
    assert_eq!(m.message_id, "g-1");
    assert_eq!(m.in_reply_to, vec!["parent@x".to_string()]);
    assert_eq!(m.authentication, Authentication::Passed);
    assert_eq!(m.attachments[0].bytes, b"hello");
}

/// A relay that says nothing about authentication gets the safe answer.
/// Absent must never mean trusted.
#[test]
fn a_generic_payload_defaults_to_unverified() {
    let body = br#"{"message_id":"g-2","from":"a@b.c","subject":"s","body":"t"}"#;
    assert_eq!(
        GenericInbound.parse(body).unwrap().authentication,
        Authentication::Unverified
    );
}

#[test]
fn a_payload_that_is_not_json_is_refused_with_a_useful_message() {
    let err = PostmarkInbound.parse(b"not json at all").unwrap_err();
    assert!(
        err.to_string().contains("Postmark"),
        "the error should say which shape was expected: {err}"
    );
    let err = GenericInbound.parse(b"{").unwrap_err();
    assert!(err.to_string().contains("Chalk inbound"));
}

/// Missing fields must not panic — a provider changing its payload should
/// degrade, not crash the ingest endpoint.
#[test]
fn an_empty_object_parses_into_an_empty_message() {
    let m = PostmarkInbound.parse(b"{}").unwrap();
    assert!(m.message_id.is_empty());
    assert!(m.attachments.is_empty());
    assert_eq!(m.authentication, Authentication::Unverified);
}

/// An attachment whose base64 is corrupt is skipped rather than failing the
/// whole message: the words are usually the important part.
#[test]
fn a_corrupt_attachment_does_not_lose_the_message() {
    let body = br#"{"MessageID":"a","From":"a@b.c","Subject":"s","TextBody":"the text",
        "Attachments":[{"Name":"x.png","Content":"!!!not base64!!!"}]}"#;
    let m = PostmarkInbound.parse(body).unwrap();
    assert_eq!(m.body, "the text");
    assert!(m.attachments.is_empty());
}

/// **The bug live e2e found.** Every unit test above used a bare address, but
/// real mail arrives as `Lisa Nowak <lisa@example.edu>` — and matching the
/// whole string against the roster silently found nobody. The ticket was still
/// created, merely attributed to a string that is not an address, so nothing
/// looked broken until somebody asked why email tickets never link to a person.
#[tokio::test]
async fn a_display_name_from_header_still_matches_the_roster() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());

    let mut m = message("display-1", "Broken screen", "It is cracked.");
    m.from = "Lisa Nowak <Lisa@Example.EDU>".into();

    let Ingested::Raised(id) = ing.ingest(m).await.unwrap() else {
        panic!("expected a ticket");
    };
    let t = repo.get_ticket(&id).await.unwrap().unwrap();
    assert_eq!(
        t.requester_user_sourced_id.as_deref(),
        Some("u-lisa"),
        "the address inside the angle brackets is the identity"
    );
    assert_eq!(
        t.requester_email.as_deref(),
        Some("lisa@example.edu"),
        "and it is stored normalised, not as the whole header"
    );
}

/// A reply from the display-name form records the same normalised address, so
/// the thread attributes it to the person rather than to a header.
#[tokio::test]
async fn a_display_name_reply_is_attributed_to_the_person() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());
    let Ingested::Raised(id) = ing.ingest(message("first-4", "Broken", "x")).await.unwrap() else {
        panic!("expected a ticket");
    };

    let mut reply = message("reply-4", "Re: Broken", "still broken");
    reply.from = "Lisa Nowak <lisa@example.edu>".into();
    reply.in_reply_to = vec!["first-4".into()];
    ing.ingest(reply).await.unwrap();

    let comments = repo.list_comments(&id, true).await.unwrap();
    assert_eq!(
        comments[0].author_user_sourced_id.as_deref(),
        Some("u-lisa")
    );
    assert_eq!(
        comments[0].author_email.as_deref(),
        Some("lisa@example.edu")
    );
}

/// **The second retry bug, found by live e2e.** A redelivered *reply* stores
/// its id on the comment, not the ticket — so checking only the tickets table
/// let the second delivery hit the unique index on
/// `ticket_comments.email_message_id`, error, and be retried forever. The
/// unit tests above only ever redelivered a first message, which is why this
/// survived them.
#[tokio::test]
async fn a_redelivered_reply_is_recognised_rather_than_erroring() {
    let repo = repo().await;
    let ing = ingestor(repo.clone());

    let Ingested::Raised(id) = ing
        .ingest(message("first-5", "Broken", "cracked"))
        .await
        .unwrap()
    else {
        panic!("expected a ticket");
    };

    let mut reply = message("reply-5", "Re: Broken", "still broken");
    reply.in_reply_to = vec!["first-5".into()];

    assert_eq!(
        ing.ingest(reply.clone()).await.unwrap(),
        Ingested::Replied(id.clone())
    );
    assert_eq!(
        ing.ingest(reply).await.unwrap(),
        Ingested::AlreadySeen(id.clone()),
        "the second delivery must be recognised, not an error"
    );
    assert_eq!(
        repo.list_comments(&id, true).await.unwrap().len(),
        1,
        "and it must not have been appended twice"
    );
}
