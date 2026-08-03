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

/// Progressive-enhancement controller for the dense data table
/// (`DESIGN_SYSTEM.md` §5.3): roving-tabindex row navigation, shift-click
/// ranges, and keeping the bulk bar's selection-scope wording honest.
///
/// Served the same way as the stylesheets — embedded, immutable, cache-busted
/// by a content hash — but kept out of [`all_assets`] because the CSS-only
/// invariants there (no hex outside tokens.css) do not apply to JavaScript.
pub const TABLE_JS: &str = include_str!("../static/table.js");

/// Route path the table controller is served from.
pub const TABLE_JS_PATH: &str = "/static/js/table.js";

static TABLE_JS_HREF: LazyLock<String> = LazyLock::new(|| versioned_href(TABLE_JS_PATH, TABLE_JS));

/// Cache-busted href for the table controller, for use in templates.
pub fn table_js_href() -> &'static str {
    &TABLE_JS_HREF
}

async fn table_js() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, CSS_CACHE_CONTROL),
        ],
        TABLE_JS,
    )
        .into_response()
}

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
        .route(TABLE_JS_PATH, get(table_js))
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
    fn table_js_is_embedded_and_cache_busted() {
        assert!(!TABLE_JS.is_empty());
        let (base, query) = table_js_href().split_once("?v=").expect("no cache buster");
        assert_eq!(base, TABLE_JS_PATH);
        assert_eq!(query.len(), HASH_LEN);
        assert_eq!(*table_js_href(), versioned_href(TABLE_JS_PATH, TABLE_JS));
    }

    /// The table must be usable with scripting off (§5.3: real links, real
    /// form posts, enhanced afterwards). A controller that assumed it owned
    /// selection would break that silently, so it is checked for the shape of
    /// an enhancement rather than a dependency.
    #[test]
    fn table_js_is_an_enhancement_not_a_renderer() {
        assert!(
            TABLE_JS.contains("htmx:afterSwap"),
            "the region is swapped wholesale; the controller must re-init"
        );
        assert!(
            !TABLE_JS.contains("innerHTML ="),
            "the controller must not render rows — the server does that"
        );
        assert!(
            TABLE_JS.contains("data-selection-mode"),
            "the controller owns the selection-mode field"
        );
    }

    /// The APG Grid pattern expects clicking a cell to move grid focus there.
    /// A click on a `<td>` sends focus to `<body>`, not to the `tabindex`
    /// row — so without an explicit move, arrow keys scroll the document
    /// instead of walking rows, and the roving tabindex is keyboard-only.
    #[test]
    fn table_js_moves_grid_focus_on_a_row_click() {
        assert!(
            TABLE_JS.contains("focusRow(table, clickedRow)"),
            "clicking a row must move the roving tabindex to it"
        );
        assert!(
            TABLE_JS.contains(r#"a[href], button, input, select"#),
            "controls and links must keep their own focus"
        );
    }

    /// `hidden` is a user-agent rule and loses to any author `display`.
    /// components.css sets `display: inline-flex` on every `button`, which
    /// silently defeated `<button hidden>` until base.css restored it — a
    /// disabled bulk control stayed on screen with nothing selected.
    #[test]
    fn the_hidden_attribute_survives_the_component_display_rules() {
        assert!(
            BASE_CSS.contains("[hidden] {") && BASE_CSS.contains("display: none !important"),
            "base.css must restore `hidden` over the author display rules"
        );
        assert!(
            COMPONENTS_CSS.contains("display: inline-flex"),
            "the rule that made the override necessary is gone; re-check the need"
        );
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

    /// The inventory's free-text columns hold district data of unbounded
    /// length. With `white-space: nowrap` and no cap, the widest single value
    /// on the page sets the column width, so one long school or org-unit name
    /// pushes the ten-column table past its container and puts a horizontal
    /// scrollbar under every row — the state this table shipped in.
    ///
    /// Each cap must stay paired with `overflow: hidden` and
    /// `text-overflow: ellipsis`: a `max-width` alone clips mid-glyph with no
    /// signal that anything was cut, which is worse than the scrollbar it
    /// replaces. Asserting the trio together is the point of this test.
    #[test]
    fn unbounded_table_columns_are_capped_and_truncate() {
        let css = strip_css_comments(COMPONENTS_CSS);
        for selector in [".col-trunc", ".col-student"] {
            let block = css
                .split_once(selector)
                .and_then(|(_, rest)| rest.split_once('}'))
                .map(|(body, _)| body.to_string())
                .unwrap_or_else(|| panic!("{selector} is gone; the table can overflow again"));
            assert!(
                block.contains("overflow: hidden") && block.contains("text-overflow: ellipsis"),
                "{selector} must clip with an ellipsis, not silently mid-glyph"
            );
        }
        for capped in [".col-model", ".col-school", ".col-ou", ".col-student"] {
            let (_, rest) = css
                .split_once(capped)
                .unwrap_or_else(|| panic!("{capped} lost its width cap"));
            let (block, _) = rest.split_once('}').expect("unterminated rule");
            assert!(
                block.contains("max-width"),
                "{capped} must cap its width or one long value widens the table"
            );
        }
    }

    /// Decorative icons must be hidden from assistive technology.
    ///
    /// Every SVG in the shell sits beside its own text label, so a screen
    /// reader announcing them adds noise between every navigation item. They
    /// were all exposed until the C7 pass — fifteen of them, on every page in
    /// the console.
    #[test]
    fn decorative_icons_are_hidden_from_screen_readers() {
        for (name, html) in ALL_TEMPLATES {
            for svg in html.split("<svg").skip(1) {
                let tag = &svg[..svg.find('>').unwrap_or(svg.len().min(300))];
                assert!(
                    tag.contains("aria-hidden") || tag.contains("role="),
                    "{name}: an <svg{tag}> is exposed to assistive technology. \
                     Decorative icons need aria-hidden=\"true\"."
                );
            }
        }
    }

    /// A control that announces itself as a button must be reachable by
    /// keyboard.
    ///
    /// The sidebar overlay carried `role="button"` and an aria-label with no
    /// tabindex, so it advertised an affordance no keyboard user could operate
    /// — worse than no role at all (WCAG 2.1.1). Native elements are the fix,
    /// and this stops the pattern coming back.
    #[test]
    fn nothing_claims_to_be_a_button_without_being_focusable() {
        for (name, html) in ALL_TEMPLATES {
            for chunk in html.split("role=\"button\"").skip(1) {
                // Look backwards from the role to the start of its tag.
                let before = &html[..html.find(chunk).unwrap_or(0)];
                let tag_start = before.rfind('<').unwrap_or(0);
                let tag = &before[tag_start..];
                let is_native = tag.starts_with("<button") || tag.starts_with("<a ");
                let focusable = tag.contains("tabindex") || chunk.starts_with(" tabindex");
                assert!(
                    is_native || focusable,
                    "{name}: {tag}...role=\"button\" is not focusable. Use a \
                     real <button>, or add tabindex."
                );
            }
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

    /// The three standalone auth documents. They do not extend base.html (no
    /// sidebar, no topbar), so nothing else forces them to keep loading the
    /// served CSS — which is exactly how they each ended up with a private
    /// copy of the palette inline in the first place.
    /// Every template the accessibility guards below scan.
    ///
    /// `base.html` first because it wraps every page — a defect there appears
    /// on all of them, which is exactly how fifteen unlabelled icons reached
    /// every screen in the console.
    const ALL_TEMPLATES: [(&str, &str); 9] = [
        ("base.html", include_str!("../templates/base.html")),
        ("login.html", include_str!("../templates/login.html")),
        (
            "devices/index.html",
            include_str!("../templates/devices/index.html"),
        ),
        (
            "devices/region.html",
            include_str!("../templates/devices/region.html"),
        ),
        (
            "devices/detail.html",
            include_str!("../templates/devices/detail.html"),
        ),
        (
            "devices/connect.html",
            include_str!("../templates/devices/connect.html"),
        ),
        (
            "devices/sync_status.html",
            include_str!("../templates/devices/sync_status.html"),
        ),
        (
            "unmatched/region.html",
            include_str!("../templates/unmatched/region.html"),
        ),
        (
            "history/region.html",
            include_str!("../templates/history/region.html"),
        ),
    ];

    const AUTH_TEMPLATES: [(&str, &str); 3] = [
        ("login.html", include_str!("../templates/login.html")),
        (
            "login_magic.html",
            include_str!("../templates/login_magic.html"),
        ),
        (
            "set_password.html",
            include_str!("../templates/set_password.html"),
        ),
    ];

    #[test]
    fn auth_templates_load_the_served_stylesheets() {
        for (name, body) in AUTH_TEMPLATES {
            for href_fn in [
                "tokens_css_href",
                "base_css_href",
                "components_css_href",
                "console_css_href",
            ] {
                assert!(
                    body.contains(&format!("crate::assets::{href_fn}()")),
                    "{name} does not link {href_fn}"
                );
            }
            assert!(
                body.contains(r#"<body class="auth-body">"#),
                "{name} is not using the shared auth shell"
            );
        }
    }

    /// The regression this whole extraction exists to prevent: a page carrying
    /// its own copy of the design system, drifting from tokens.css unnoticed.
    #[test]
    fn auth_templates_have_no_inline_style_block() {
        for (name, body) in AUTH_TEMPLATES {
            assert!(
                !body.contains("<style"),
                "{name} has an inline <style> block — put the rules in console.css"
            );
            assert!(
                !body.contains("style=\""),
                "{name} has an inline style attribute"
            );
        }
    }

    /// Every rule those inline blocks used to carry now has a home. If one of
    /// these selectors disappears, an auth page silently loses its layout.
    #[test]
    fn console_css_defines_the_auth_shell() {
        for selector in [
            ".auth-body",
            ".auth-card",
            ".auth-card--wide",
            ".auth-brand",
            ".auth-subtitle",
            ".auth-subtitle--tight",
            ".auth-help",
            ".auth-alert",
            ".auth-notice",
            ".auth-form input",
            ".auth-form--tight input",
            ".auth-form button[type=\"submit\"]",
        ] {
            assert!(
                CONSOLE_CSS.contains(selector),
                "console.css no longer defines {selector}"
            );
        }
    }

    /// WCAG 2.1 AA is a build constraint (PRD D10), and the four inks below
    /// are the ones that shipped failing it. `scripts/contrast.py` computes the
    /// ratios and gates CI; this test guards the token *wiring*, which the
    /// ratio check cannot see — it reads hexes, not `var()` indirection.
    #[test]
    fn muted_and_on_dark_inks_are_the_aa_steps() {
        for (token, step) in [
            ("--ink-muted", "var(--slate-500)"),
            ("--sidebar-ink-section", "var(--slate-400)"),
            ("--sidebar-active-ink", "var(--indigo-300)"),
            ("--sidebar-badge-ink", "var(--slate-300)"),
        ] {
            let line = TOKENS_CSS
                .lines()
                .find(|l| l.trim_start().starts_with(&format!("{token}:")))
                .unwrap_or_else(|| panic!("tokens.css no longer defines {token}"));
            assert!(
                line.contains(step),
                "{token} must resolve to {step} to meet AA; found: {}",
                line.trim()
            );
        }
    }

    /// `display: block` on a `<table>` is the old mobile horizontal-scroll
    /// hack, and it stops the table's rows stretching to the table's width.
    /// Every row-level background then ends at *content* width: the sticky
    /// header's grey stops mid-table, and so do the hover state, the
    /// selected-row tint, and the struck-out row in the diff preview. On a
    /// narrow screen the tables look broken, and the state that tells an
    /// operator which rows they picked is the thing that disappears.
    ///
    /// Narrow screens scroll the container instead, which fixes every table at
    /// once — including the nineteen templates whose tables have no
    /// `.table-container` wrapper of their own, and which a wrapper-scoped fix
    /// would have silently missed.
    #[test]
    fn no_stylesheet_lays_a_table_out_as_a_block() {
        // `table { width: 100% }` in base.css is fine and expected. What is
        // never fine is a `display` that takes the element out of table layout,
        // so this reads each bare-`table` rule's body rather than banning the
        // selector.
        for (path, body, _) in all_assets() {
            let mut rest = body;
            while let Some(at) = rest.find("table {") {
                // Only a *bare* `table` selector: `.table-scroll table {` and
                // `.foo-table {` both end in something other than whitespace or
                // a line start.
                let bare = rest[..at]
                    .chars()
                    .next_back()
                    .is_none_or(|c| c == '\n' || c == ' ');
                let preceded_by_selector = rest[..at]
                    .lines()
                    .next_back()
                    .is_some_and(|l| !l.trim().is_empty());
                let decl_end = rest[at..].find('}').map(|e| at + e).unwrap_or(rest.len());
                let decls = &rest[at..decl_end];
                if bare && !preceded_by_selector {
                    assert!(
                        !decls.contains("display: block"),
                        "{path} lays a bare `table` out as a block. Its rows then \
                         stop stretching to the table's width, so every row-level \
                         background — sticky header, hover, selected-row tint, \
                         struck-out preview row — ends at content width instead \
                         of spanning the row. Scroll the container, not the table."
                    );
                }
                rest = &rest[decl_end..];
            }
        }
        assert!(
            CONSOLE_CSS.contains(".content {\n    overflow-x: auto;"),
            "the narrow-screen fallback that replaced it must still be there, \
             or a wide table will push the whole page sideways"
        );
    }

    /// The accent that D17 locked. A silent change here is a rebrand.
    #[test]
    fn accent_is_indigo_600() {
        assert!(TOKENS_CSS.contains("--indigo-600: #4f46e5;"));
        assert!(TOKENS_CSS.contains("--accent:            var(--indigo-600);"));
    }
}

/// The cascade lint.
///
/// Every stylesheet is served as a separate `<link>` in a fixed order
/// (tokens → base → components → console), so two rules at equal specificity
/// are decided by which *file* came last. That makes a BEM modifier written in
/// an earlier file than its base rule silently lose — and lose in the worst
/// way: `.stat-card--alarm { border-left-color: red }` in components.css lost
/// to `.stat-card { border-left: 4px solid indigo }` in console.css, so the
/// most urgent card rendered with no left border at all, neither indigo nor
/// red.
///
/// That has now happened twice (see also `.cell-note` versus
/// `.table--compact tbody td`). A rule someone has to remember is a rule that
/// gets skipped, so it is a test instead.
#[cfg(test)]
mod cascade {
    /// Stylesheets in the order `base.html` links them. Position in this list
    /// *is* the cascade order.
    fn sheets() -> Vec<(&'static str, &'static str)> {
        vec![
            ("tokens.css", super::TOKENS_CSS),
            ("base.css", super::BASE_CSS),
            ("components.css", super::COMPONENTS_CSS),
            ("console.css", super::CONSOLE_CSS),
        ]
    }

    /// One declared rule: the class it targets, the properties it sets, and
    /// where it sits in the cascade as `(sheet index, byte offset)`.
    struct Rule {
        class: String,
        properties: Vec<String>,
        sheet: usize,
        offset: usize,
        in_media: bool,
        /// `(classes+pseudo-classes+attributes, elements)`. Ids never appear
        /// in these sheets. Order only decides a contest between rules of
        /// *equal* specificity, so this is what makes the lint precise rather
        /// than noisy.
        specificity: (u32, u32),
    }

    /// Count the parts of a full selector that contribute specificity.
    fn specificity_of(selector: &str) -> (u32, u32) {
        let b = selector.matches('.').count()
            + selector.matches(':').count()
            + selector.matches('[').count();
        let e = selector
            .split(|c: char| !c.is_alphanumeric() && c != '-')
            .filter(|t| {
                !t.is_empty()
                    && t.chars().next().is_some_and(|c| c.is_alphabetic())
                    && !selector.contains(&format!(".{t}"))
                    && !selector.contains(&format!(":{t}"))
            })
            .count();
        (b as u32, e as u32)
    }

    /// A property name, reduced to the family a shorthand would clobber.
    ///
    /// `border-left: 4px solid indigo` and `border-left-color: red` are
    /// different property names but the same battle — which is exactly the
    /// pair that shipped the invisible card border. Comparing raw names would
    /// have missed it.
    fn family(prop: &str) -> String {
        for root in [
            "border-left",
            "border-right",
            "border-top",
            "border-bottom",
            "border",
            "background",
            "margin",
            "padding",
            "font",
            "grid-template",
            "flex",
            "outline",
        ] {
            if prop == root || prop.starts_with(&format!("{root}-")) {
                return root.to_string();
            }
        }
        prop.to_string()
    }

    /// Every rule in every sheet, in cascade order.
    ///
    /// Only the *last* class of a compound selector is recorded: that is the
    /// element the rule paints, and therefore the one an override contends
    /// for.
    fn rules() -> Vec<Rule> {
        let mut out = Vec::new();
        for (i, (_, css)) in sheets().iter().enumerate() {
            let mut at = 0usize;
            let mut depth = 0i32;
            let mut pending_media = false;
            let parts: Vec<&str> = css.split('{').collect();
            for (k, block) in parts.iter().enumerate() {
                let block_start = at;
                at += block.len() + 1;

                // Splitting on `{` puts a rule's declarations and the *next*
                // rule's selector in the same chunk, separated by `}`. The
                // selector is the tail, and its byte offset is what decides
                // cascade order — using the chunk's start instead compares a
                // selector against the previous rule's declarations and
                // reports neighbouring rules in the wrong order.
                let declarations = match block.rsplit_once('}') {
                    Some((decls, _)) => decls,
                    None => "",
                };
                depth -= declarations.matches('}').count() as i32;
                if depth < 0 {
                    depth = 0;
                }
                let selector = block.rsplit('}').next().unwrap_or(block);
                let offset = block_start + (block.len() - selector.len());
                let selector = strip_comments(selector);
                let selector = selector.trim();

                if selector.starts_with('@') {
                    pending_media = selector.starts_with("@media");
                    depth += 1;
                    continue;
                }
                if selector.is_empty() || k + 1 == parts.len() {
                    continue;
                }

                let properties: Vec<String> = parts
                    .get(k + 1)
                    .map(|next| {
                        let body = next.split('}').next().unwrap_or("");
                        strip_comments(body)
                            .split(';')
                            .filter_map(|d| d.split_once(':'))
                            .map(|(name, _)| family(name.trim()))
                            .collect()
                    })
                    .unwrap_or_default();

                for part in selector.split(',') {
                    let spec = specificity_of(part);
                    if let Some(last) = part.split_whitespace().last() {
                        for class in last.split('.').skip(1) {
                            let name: String = class
                                .chars()
                                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                                .collect();
                            if !name.is_empty() {
                                out.push(Rule {
                                    class: name,
                                    properties: properties.clone(),
                                    sheet: i,
                                    offset,
                                    in_media: pending_media && depth > 0,
                                    specificity: spec,
                                });
                            }
                        }
                    }
                }
            }
        }
        out
    }

    fn strip_comments(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find("/*") {
            out.push_str(&rest[..i]);
            match rest[i..].find("*/") {
                Some(j) => rest = &rest[i + j + 2..],
                None => return out,
            }
        }
        out.push_str(rest);
        out
    }

    /// A `.block--modifier` must be declared after every unconditional
    /// `.block` rule that sets a property it also sets. Otherwise the base
    /// rule wins at equal specificity and the modifier does nothing — or
    /// worse, half of nothing.
    ///
    /// Rules inside `@media` are exempt as *bases*: a breakpoint override is a
    /// deliberate, conditional reassertion, not an accident.
    #[test]
    fn every_modifier_is_declared_after_the_rule_it_modifies() {
        let all = rules();
        let mut problems = Vec::new();

        for m in &all {
            let Some((block, modifier)) = m.class.split_once("--") else {
                continue;
            };
            // `.badge--` with nothing after it is a prose mention in a
            // comment, not a selector.
            if modifier.is_empty() || block.is_empty() {
                continue;
            }

            for base in all.iter().filter(|b| b.class == block && !b.in_media) {
                if (base.sheet, base.offset) <= (m.sheet, m.offset) {
                    continue;
                }
                // A more specific base beats the modifier whatever the order,
                // so this is not an ordering bug. `.page:hover` over
                // `.page--current` is a deliberate hover state, not an
                // accident of file layout.
                if base.specificity > m.specificity {
                    continue;
                }
                let clash: Vec<&String> = m
                    .properties
                    .iter()
                    .filter(|p| base.properties.contains(p))
                    .collect();
                if clash.is_empty() {
                    continue;
                }
                let names = sheets();
                problems.push(format!(
                    ".{} (in {}) sets {:?}, but .{block} in {} is declared later and sets it too —                      at equal specificity the base wins and the modifier is dead",
                    m.class,
                    names[m.sheet].0,
                    clash,
                    names[base.sheet].0,
                ));
            }
        }

        assert!(
            problems.is_empty(),
            "modifier declared before the rule it modifies:\n  {}",
            problems.join("\n  ")
        );
    }
}
