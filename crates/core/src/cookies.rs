//! Set-Cookie header builder shared by the console, IdP, and CSRF middleware.
//!
//! Centralizes the SameSite / HttpOnly / Secure / Path / Max-Age flag matrix
//! so every `Set-Cookie` header in Chalk is built in exactly one place.

use std::fmt::Write;

/// SameSite cookie attribute values.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// Set of attributes for a `Set-Cookie` header.
#[derive(Copy, Clone, Debug)]
pub struct CookieAttrs {
    pub same_site: SameSite,
    pub http_only: bool,
    pub secure: bool,
    pub path: &'static str,
    /// `None` produces a session cookie (no `Max-Age`).
    pub max_age_secs: Option<i64>,
}

impl Default for CookieAttrs {
    fn default() -> Self {
        Self {
            same_site: SameSite::Lax,
            http_only: true,
            secure: false,
            path: "/",
            max_age_secs: None,
        }
    }
}

/// Build a `Set-Cookie` header value of the form `name=value; <attrs...>`.
pub fn set_cookie(name: &str, value: &str, attrs: &CookieAttrs) -> String {
    let mut s = format!(
        "{name}={value}; Path={}; SameSite={}",
        attrs.path,
        attrs.same_site.as_str()
    );
    if attrs.http_only {
        s.push_str("; HttpOnly");
    }
    if attrs.secure {
        s.push_str("; Secure");
    }
    if let Some(age) = attrs.max_age_secs {
        let _ = write!(s, "; Max-Age={age}");
    }
    s
}

/// Build a `Set-Cookie` header that immediately clears `name`.
pub fn clear_cookie(name: &str, attrs: &CookieAttrs) -> String {
    let clear = CookieAttrs {
        max_age_secs: Some(0),
        ..*attrs
    };
    set_cookie(name, "", &clear)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_with_all_flags() {
        let attrs = CookieAttrs {
            same_site: SameSite::Strict,
            http_only: true,
            secure: true,
            path: "/",
            max_age_secs: Some(86400),
        };
        let s = set_cookie("chalk_admin", "abc123", &attrs);
        assert_eq!(
            s,
            "chalk_admin=abc123; Path=/; SameSite=Strict; HttpOnly; Secure; Max-Age=86400"
        );
    }

    #[test]
    fn set_cookie_without_http_only_or_secure() {
        let attrs = CookieAttrs {
            same_site: SameSite::Lax,
            http_only: false,
            secure: false,
            path: "/",
            max_age_secs: Some(60),
        };
        let s = set_cookie("foo", "bar", &attrs);
        assert!(!s.contains("HttpOnly"));
        assert!(!s.contains("Secure"));
        assert!(s.contains("SameSite=Lax"));
        assert!(s.contains("Max-Age=60"));
    }

    #[test]
    fn set_cookie_session_no_max_age() {
        let attrs = CookieAttrs {
            same_site: SameSite::Strict,
            http_only: true,
            secure: false,
            path: "/",
            max_age_secs: None,
        };
        let s = set_cookie("sess", "x", &attrs);
        assert!(!s.contains("Max-Age"));
    }

    #[test]
    fn clear_cookie_zeroes_max_age_and_value() {
        let attrs = CookieAttrs {
            same_site: SameSite::Lax,
            http_only: true,
            secure: true,
            path: "/",
            max_age_secs: Some(28800),
        };
        let s = clear_cookie("chalk_portal", &attrs);
        assert!(s.starts_with("chalk_portal=; "));
        assert!(s.contains("Max-Age=0"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("Secure"));
        assert!(s.contains("SameSite=Lax"));
    }

    #[test]
    fn samesite_none_renders_correctly() {
        let attrs = CookieAttrs {
            same_site: SameSite::None,
            ..CookieAttrs::default()
        };
        let s = set_cookie("x", "y", &attrs);
        assert!(s.contains("SameSite=None"));
    }
}
