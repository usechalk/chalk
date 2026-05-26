//! Shared helpers for parsing and building LDAP server URIs.
//!
//! Lives in core so both the hosted runtime (which round-trips through the
//! `tenant_config_ad_sync.host`/`port`/`use_tls` columns) and the admin
//! console form handler (which tries to forgive a pasted full URI in the
//! Host field) can agree on the format. The OSS `AdConnectionConfig.server`
//! stores a single URI string; the DB row stores them split.

/// Parse an LDAP server URI of the form `[ldap[s]://]host[:port]` into
/// `(use_tls, host, port)`. Returns `None` for empty input or an empty host.
/// Falls back to `use_tls = true` (LDAPS) when the input has no scheme — that
/// is safer than silently downgrading to plaintext.
pub fn parse_ldap_uri(s: &str) -> Option<(bool, String, Option<u16>)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (use_tls, rest) = if let Some(r) = s.strip_prefix("ldaps://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("ldap://") {
        (false, r)
    } else {
        (true, s)
    };
    // Right-split on `:` so IPv6 literals (which contain colons) aren't
    // mistaken for `host:port`. A bracketed `[…]:port` is a valid IPv6+port
    // form; an unbracketed colon-bearing host is treated as port-less.
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() => match p.parse::<u16>() {
            Ok(port) => (h, Some(port)),
            // Trailing `:` or non-numeric / out-of-range port → fall back to
            // the whole `rest` as the host so the operator at least sees the
            // original input echoed in the URI rather than silently dropping
            // characters.
            Err(_) => (rest, None),
        },
        _ => (rest, None),
    };
    if host.is_empty() {
        return None;
    }
    Some((use_tls, host.to_string(), port))
}

/// Build `[ldap[s]://]host[:port]` from components — inverse of [`parse_ldap_uri`].
pub fn build_ldap_uri(use_tls: bool, host: &str, port: Option<u16>) -> String {
    let scheme = if use_tls { "ldaps" } else { "ldap" };
    match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ldap_uri_handles_scheme_and_port_variants() {
        assert_eq!(
            parse_ldap_uri("ldaps://dc.example.com:636"),
            Some((true, "dc.example.com".into(), Some(636)))
        );
        assert_eq!(
            parse_ldap_uri("ldap://dc.example.com:389"),
            Some((false, "dc.example.com".into(), Some(389)))
        );
        assert_eq!(
            parse_ldap_uri("ldaps://dc.example.com"),
            Some((true, "dc.example.com".into(), None))
        );
        assert_eq!(
            parse_ldap_uri("dc.example.com"),
            Some((true, "dc.example.com".into(), None))
        );
        assert_eq!(
            parse_ldap_uri("ldaps://[::1]:636"),
            Some((true, "[::1]".into(), Some(636)))
        );
        assert_eq!(
            parse_ldap_uri("ldaps://[2001:db8::1]"),
            Some((true, "[2001:db8::1]".into(), None))
        );
        assert_eq!(parse_ldap_uri(""), None);
        assert_eq!(parse_ldap_uri("   "), None);
        assert_eq!(parse_ldap_uri("ldaps://"), None);
        assert_eq!(
            parse_ldap_uri("ldaps://host:"),
            Some((true, "host:".into(), None))
        );
        assert_eq!(
            parse_ldap_uri("ldaps://host:99999"),
            Some((true, "host:99999".into(), None))
        );
        assert_eq!(
            parse_ldap_uri("ldaps://host:-1"),
            Some((true, "host:-1".into(), None))
        );
    }

    #[test]
    fn build_then_parse_ldap_uri_round_trips() {
        for (use_tls, host, port) in [
            (true, "dc.example.com", Some(636)),
            (false, "dc.example.com", Some(389)),
            (true, "dc.example.com", None),
        ] {
            let s = build_ldap_uri(use_tls, host, port);
            assert_eq!(parse_ldap_uri(&s), Some((use_tls, host.into(), port)));
        }
    }
}
