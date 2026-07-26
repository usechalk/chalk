//! Static CSS assets, embedded in the binary and served with content-derived
//! cache busting.
//!
//! Follows the same hand-rolled pattern as [`crate::htmx_js`] and
//! [`crate::brand_font`]: `include_str!` at compile time, `Cache-Control:
//! immutable` at request time. There is no rust-embed and no build step, by
//! design — a self-hoster building from source gets the CSS in the binary with
//! nothing else installed.
//!
//! # Why a query string rather than a hashed filename
//!
//! `immutable` plus a stable URL is a trap: an admin who has loaded
//! `/static/css/tokens.css` once will keep the old bytes for a year, so a CSS
//! fix would never reach them. Two ways out:
//!
//! 1. **Hashed filename** (`tokens.9f3a2b1c.css`). Needs either a build script
//!    that rewrites the filename and emits it for the templates, or a wildcard
//!    route that parses the hash back out. Both add a build step or a fallible
//!    parse to a crate that currently has neither.
//! 2. **Content-hash query string** (`tokens.css?v=9f3a2b1c`) — chosen. The
//!    route stays a plain literal path, the hash is computed once at first use
//!    from the very bytes that will be served, and every CDN and browser cache
//!    keys on the full URL including the query.
//!
//! The hash is derived from the file *contents*, not `CONSOLE_VERSION`. A
//! version string only busts on release, so a CSS edit during development (or
//! any patch that changes CSS without bumping the version) would still serve
//! stale bytes to anyone who had already loaded the page — exactly the failure
//! we are trying to avoid. Content hashing cannot get out of sync with what is
//! served, because it *is* what is served.

use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::sync::LazyLock;

const CSS_CONTENT_TYPE: &str = "text/css; charset=utf-8";

/// One year, immutable. Safe because every reference carries a content hash in
/// its query string, so changed bytes are a different URL.
const CSS_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// Length of the hex digest prefix used as the cache-busting token. 8 hex
/// characters is 32 bits: collisions are irrelevant here because a collision
/// only means one client keeps a cached copy it would have re-fetched.
const HASH_LEN: usize = 8;

/// `"{path}?v={sha256(body)[..8]}"`.
fn versioned_href(path: &str, body: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    format!("{path}?v={}", &digest[..HASH_LEN])
}

fn css_response(body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, CSS_CONTENT_TYPE),
            (header::CACHE_CONTROL, CSS_CACHE_CONTROL),
        ],
        body,
    )
        .into_response()
}

/// Declares one stylesheet: its embedded bytes, its route path, the handler
/// that serves it, and a lazily-computed cache-busted href for templates.
macro_rules! css_asset {
    (
        $(#[$meta:meta])*
        $body:ident, $path:ident, $href:ident, $href_fn:ident, $file:literal, $route:literal
    ) => {
        $(#[$meta])*
        pub const $body: &str = include_str!($file);

        /// Route path this stylesheet is served from (no cache-busting query).
        pub const $path: &str = $route;

        static $href: LazyLock<String> = LazyLock::new(|| versioned_href($path, $body));

        /// Cache-busted href for use in templates.
        pub fn $href_fn() -> &'static str {
            &$href
        }
    };
}

css_asset!(
    /// Layer 1 + 2 + 3 design tokens. The source of truth for every colour,
    /// space, radius and z-index in the product.
    TOKENS_CSS,
    TOKENS_CSS_PATH,
    TOKENS_CSS_HREF,
    tokens_css_href,
    "../assets/css/tokens.css",
    "/static/css/tokens.css"
);

css_asset!(
    /// Reset, element defaults, typography, focus ring, `.sr-only`.
    BASE_CSS,
    BASE_CSS_PATH,
    BASE_CSS_HREF,
    base_css_href,
    "../assets/css/base.css",
    "/static/css/base.css"
);

css_asset!(
    /// Reusable UI blocks: buttons, badges, HTMX indicator.
    COMPONENTS_CSS,
    COMPONENTS_CSS_PATH,
    COMPONENTS_CSS_HREF,
    components_css_href,
    "../assets/css/components.css",
    "/static/css/components.css"
);

css_asset!(
    /// Admin-console chrome: sidebar, topbar, content shell, stat grid.
    CONSOLE_CSS,
    CONSOLE_CSS_PATH,
    CONSOLE_CSS_HREF,
    console_css_href,
    "../assets/css/console.css",
    "/static/css/console.css"
);

async fn tokens_css() -> Response {
    css_response(TOKENS_CSS)
}

async fn base_css() -> Response {
    css_response(BASE_CSS)
}

async fn components_css() -> Response {
    css_response(COMPONENTS_CSS)
}

async fn console_css() -> Response {
    css_response(CONSOLE_CSS)
}

/// Routes for the stylesheet bundle, in the documented load order
/// (tokens → base → components → console).
///
/// These sit under `/static/`, which [`crate::auth::PUBLIC_PATHS`] exempts from
/// session auth — the login page needs them before a session exists.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(TOKENS_CSS_PATH, get(tokens_css))
        .route(BASE_CSS_PATH, get(base_css))
        .route(COMPONENTS_CSS_PATH, get(components_css))
        .route(CONSOLE_CSS_PATH, get(console_css))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every stylesheet the console serves: (route, body, href accessor).
    fn all_assets() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            (TOKENS_CSS_PATH, TOKENS_CSS, tokens_css_href()),
            (BASE_CSS_PATH, BASE_CSS, base_css_href()),
            (COMPONENTS_CSS_PATH, COMPONENTS_CSS, components_css_href()),
            (CONSOLE_CSS_PATH, CONSOLE_CSS, console_css_href()),
        ]
    }

    #[test]
    fn every_stylesheet_is_embedded_and_non_empty() {
        for (path, body, _) in all_assets() {
            assert!(!body.is_empty(), "{path} embedded empty");
        }
    }

    #[test]
    fn hrefs_are_the_route_path_plus_a_content_hash() {
        for (path, body, href) in all_assets() {
            let (base, query) = href
                .split_once("?v=")
                .unwrap_or_else(|| panic!("{path} href missing cache-busting query: {href}"));
            assert_eq!(base, path);
            assert_eq!(query.len(), HASH_LEN);
            assert!(
                query.chars().all(|c| c.is_ascii_hexdigit()),
                "{path} hash is not hex: {query}"
            );
            assert_eq!(
                *href,
                versioned_href(path, body),
                "{path} href is not derived from the bytes served"
            );
        }
    }

    #[test]
    fn hrefs_are_distinct_per_stylesheet() {
        let hashes: Vec<&str> = all_assets().iter().map(|(_, _, href)| *href).collect();
        for (i, a) in hashes.iter().enumerate() {
            for b in hashes.iter().skip(i + 1) {
                assert_ne!(a, b, "two stylesheets share an href");
            }
        }
    }

    #[test]
    fn content_hash_changes_when_content_changes() {
        let a = versioned_href("/x.css", ":root { --a: 1; }");
        let b = versioned_href("/x.css", ":root { --a: 2; }");
        assert_ne!(a, b);
    }

    /// The alias layer is what makes the extraction a no-op for the ~30
    /// templates that still write `var(--c-primary)` inline. If a `--c-*` name
    /// stops being defined, those templates silently lose their styling.
    #[test]
    fn legacy_c_aliases_are_all_defined() {
        for name in [
            "--c-primary",
            "--c-primary-hover",
            "--c-primary-light",
            "--c-accent",
            "--c-danger",
            "--c-danger-light",
            "--c-danger-bg",
            "--c-sidebar",
            "--c-sidebar-hover",
            "--c-sidebar-active",
            "--c-bg",
            "--c-surface",
            "--c-border",
            "--c-text",
            "--c-text-muted",
            "--c-text-heading",
            "--c-success",
            "--c-success-bg",
            "--c-warning",
            "--c-warning-bg",
            "--font",
            "--font-display",
            "--shadow-sm",
            "--shadow-md",
            "--shadow-lg",
            "--radius-sm",
            "--radius-md",
            "--radius-lg",
        ] {
            assert!(
                TOKENS_CSS.contains(&format!("\n  {name}:")),
                "tokens.css no longer defines {name}, which shipped templates use"
            );
        }
    }

    /// Drop `/* … */` comments so prose about hex codes doesn't trip the
    /// literal check below. CSS has no nested block comments.
    fn strip_css_comments(css: &str) -> String {
        let mut out = String::with_capacity(css.len());
        let mut rest = css;
        while let Some(open) = rest.find("/*") {
            out.push_str(&rest[..open]);
            match rest[open + 2..].find("*/") {
                Some(close) => rest = &rest[open + 2 + close + 2..],
                None => return out,
            }
        }
        out.push_str(rest);
        out
    }

    /// The declaration is a hex colour if `#` is followed by 3–8 hex digits.
    fn contains_hex_color(code: &str) -> bool {
        code.match_indices('#').any(|(i, _)| {
            let run = code[i + 1..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .count();
            (3..=8).contains(&run)
        })
    }

    /// DESIGN_SYSTEM.md §10.2: components reference semantic tokens, never raw
    /// hex. tokens.css is the one file allowed to hold hex literals — that is
    /// the property that keeps a theme swap a one-file change.
    #[test]
    fn only_tokens_css_contains_hex_literals() {
        for (path, body, _) in all_assets() {
            if path == TOKENS_CSS_PATH {
                continue;
            }
            let code = strip_css_comments(body);
            assert!(
                !contains_hex_color(&code),
                "{path} has a hex literal outside tokens.css"
            );
        }
    }

    #[test]
    fn hex_detection_distinguishes_colors_from_selectors() {
        assert!(contains_hex_color("color: #fff;"));
        assert!(contains_hex_color("color: #4f46e5;"));
        assert!(!contains_hex_color("#announcer { display: none; }"));
        assert!(!contains_hex_color("width: 16px;"));
        assert_eq!(strip_css_comments("a /* #fff */ b"), "a  b");
    }

    /// The accent that D17 locked. A silent change here is a rebrand.
    #[test]
    fn accent_is_indigo_600() {
        assert!(TOKENS_CSS.contains("--indigo-600: #4f46e5;"));
        assert!(TOKENS_CSS.contains("--accent:            var(--indigo-600);"));
    }
}
