//! One small adapter per mail provider.
//!
//! Each one does exactly two things: pull the fields out of that provider's
//! JSON, and decide whether the message announced itself as automatic. Every
//! decision after that — threading, deduplication, whether `From:` may be
//! trusted — is shared, so a district on Postmark and a district on its own
//! relay get identical behaviour.
//!
//! Adding a provider is implementing [`InboundEmailParser`] and adding one
//! line to [`parser_for`].

use base64::Engine;
use serde::Deserialize;

use super::{
    auto_submitted_is_automatic, precedence_is_automatic, Authentication, InboundAttachment,
    InboundEmailParser, InboundMessage, AUTOMATIC_HEADERS,
};
use crate::error::{ChalkError, Result};

/// The parser an operator asked for, by the name they put in `provider =`.
pub fn parser_for(name: &str) -> Option<Box<dyn InboundEmailParser>> {
    match name.trim().to_ascii_lowercase().as_str() {
        "postmark" => Some(Box::new(PostmarkInbound)),
        "generic" => Some(Box::new(GenericInbound)),
        _ => None,
    }
}

/// Every provider name Chalk understands, for an error message that tells an
/// operator what they *could* have written.
pub const PROVIDERS: &[&str] = &["postmark", "generic"];

// ---------------------------------------------------------------------------
// Postmark
// ---------------------------------------------------------------------------

/// Postmark's inbound webhook.
///
/// Postmark performs SPF and DKIM checks and reports them in the headers it
/// forwards, which is what lets a message be attributed to a roster user at
/// all. A provider that does not report them leaves every message attributed
/// to its address instead — correct, and visibly worse, which is the right
/// pressure.
pub struct PostmarkInbound;

#[derive(Debug, Deserialize)]
struct PostmarkPayload {
    #[serde(default, rename = "MessageID")]
    message_id: String,
    #[serde(default, rename = "From")]
    from: String,
    #[serde(default, rename = "Subject")]
    subject: String,
    #[serde(default, rename = "TextBody")]
    text_body: String,
    #[serde(default, rename = "StrippedTextReply")]
    stripped_text_reply: String,
    #[serde(default, rename = "Headers")]
    headers: Vec<PostmarkHeader>,
    #[serde(default, rename = "Attachments")]
    attachments: Vec<PostmarkAttachment>,
}

#[derive(Debug, Deserialize)]
struct PostmarkHeader {
    #[serde(default, rename = "Name")]
    name: String,
    #[serde(default, rename = "Value")]
    value: String,
}

#[derive(Debug, Deserialize)]
struct PostmarkAttachment {
    #[serde(default, rename = "Name")]
    name: String,
    #[serde(default, rename = "Content")]
    content: String,
}

impl InboundEmailParser for PostmarkInbound {
    fn name(&self) -> &'static str {
        "postmark"
    }

    fn parse(&self, body: &[u8]) -> Result<InboundMessage> {
        let p: PostmarkPayload = serde_json::from_slice(body)
            .map_err(|e| ChalkError::Validation(format!("not a Postmark inbound payload: {e}")))?;

        let header = |name: &str| {
            p.headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .map(|h| h.value.trim().to_string())
                .unwrap_or_default()
        };

        // Postmark's own reply stripping is better than ours because it knows
        // the original outbound message. Prefer it, and fall back to the full
        // body when it is empty — which it is for a first message.
        let text = if p.stripped_text_reply.trim().is_empty() {
            p.text_body.clone()
        } else {
            p.stripped_text_reply.clone()
        };

        let mut in_reply_to = Vec::new();
        let direct = header("In-Reply-To");
        if !direct.is_empty() {
            in_reply_to.push(clean_message_id(&direct));
        }
        for id in header("References").split_whitespace() {
            let id = clean_message_id(id);
            if !id.is_empty() && !in_reply_to.contains(&id) {
                in_reply_to.push(id);
            }
        }

        let automatic = AUTOMATIC_HEADERS.iter().any(|h| {
            let v = header(h);
            if h.eq_ignore_ascii_case("auto-submitted") {
                auto_submitted_is_automatic(&v)
            } else {
                !v.is_empty()
            }
        }) || precedence_is_automatic(&header("Precedence"));

        Ok(InboundMessage {
            message_id: clean_message_id(&p.message_id),
            from: p.from.clone(),
            in_reply_to,
            subject: p.subject.clone(),
            body: text,
            authentication: postmark_authentication(
                &header("Received-SPF"),
                &header("DKIM-Signature"),
            ),
            automatic,
            attachments: p
                .attachments
                .iter()
                .filter_map(|a| {
                    base64::engine::general_purpose::STANDARD
                        .decode(a.content.as_bytes())
                        .ok()
                        .map(|bytes| InboundAttachment {
                            filename: a.name.clone(),
                            bytes,
                        })
                })
                .collect(),
        })
    }
}

/// SPF or DKIM, either is enough.
///
/// A forwarded message frequently fails SPF while keeping a valid DKIM
/// signature, and requiring both would leave anybody whose mail passes through
/// a forwarder permanently unattributed.
fn postmark_authentication(received_spf: &str, dkim: &str) -> Authentication {
    let spf_passed = received_spf.trim().to_ascii_lowercase().starts_with("pass");
    if spf_passed || !dkim.trim().is_empty() {
        Authentication::Passed
    } else {
        Authentication::Unverified
    }
}

// ---------------------------------------------------------------------------
// Generic
// ---------------------------------------------------------------------------

/// A documented, provider-neutral shape any relay can be made to POST.
///
/// This exists so self-hosting does not require a paid provider: a district
/// already running mail can pipe a message through a dozen lines of script and
/// post this. Field names are lowercase and obvious, because whoever writes
/// that script is doing it once and should not need the source open.
pub struct GenericInbound;

#[derive(Debug, Deserialize)]
struct GenericPayload {
    #[serde(default)]
    message_id: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    in_reply_to: Vec<String>,
    /// `true` only if the relay verified SPF or DKIM. Absent means unverified,
    /// which is the safe default — the message still becomes a ticket, it is
    /// simply attributed to the address rather than to a person.
    #[serde(default)]
    authenticated: bool,
    /// `true` if the relay recognised an auto-reply. A relay that does not
    /// check should leave it out; Chalk also looks at the headers below.
    #[serde(default)]
    automatic: bool,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    attachments: Vec<GenericAttachment>,
}

#[derive(Debug, Deserialize)]
struct GenericAttachment {
    #[serde(default)]
    filename: String,
    /// Base64, so the payload stays JSON.
    #[serde(default)]
    content_base64: String,
}

impl InboundEmailParser for GenericInbound {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn parse(&self, body: &[u8]) -> Result<InboundMessage> {
        let p: GenericPayload = serde_json::from_slice(body)
            .map_err(|e| ChalkError::Validation(format!("not a Chalk inbound payload: {e}")))?;

        let header = |name: &str| {
            p.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default()
        };

        let automatic = p.automatic
            || AUTOMATIC_HEADERS.iter().any(|h| {
                let v = header(h);
                if h.eq_ignore_ascii_case("auto-submitted") {
                    auto_submitted_is_automatic(&v)
                } else {
                    !v.is_empty()
                }
            })
            || precedence_is_automatic(&header("Precedence"));

        Ok(InboundMessage {
            message_id: clean_message_id(&p.message_id),
            from: p.from.clone(),
            in_reply_to: p.in_reply_to.iter().map(|s| clean_message_id(s)).collect(),
            subject: p.subject.clone(),
            body: p.body.clone(),
            authentication: if p.authenticated {
                Authentication::Passed
            } else {
                Authentication::Unverified
            },
            automatic,
            attachments: p
                .attachments
                .iter()
                .filter_map(|a| {
                    base64::engine::general_purpose::STANDARD
                        .decode(a.content_base64.as_bytes())
                        .ok()
                        .map(|bytes| InboundAttachment {
                            filename: a.filename.clone(),
                            bytes,
                        })
                })
                .collect(),
        })
    }
}

/// Strip the angle brackets around a `Message-ID`.
///
/// Providers are inconsistent about whether they include them, and a stored
/// `<abc@x>` will never match an incoming `abc@x` — which silently breaks
/// threading rather than erroring, so it is normalised in one place.
pub fn clean_message_id(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string()
}
