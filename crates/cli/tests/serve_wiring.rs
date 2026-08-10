//! Every `with_*` builder on `AppState` must be called by `chalk serve`.
//!
//! GP-2 shipped its settings pages 404ing in production while every test
//! passed: `wire_all` (the test fixture) had gained `.with_permission_sets`
//! and `serve.rs` had not — the vacuous-fixture bug's mirror image, caught
//! only by live e2e. The builder list is derived from the console source
//! itself, so builder N+1 fails this test until someone wires it or names
//! it as a deliberate exception below.

const SERVE: &str = include_str!("../src/commands/serve.rs");
const CONSOLE_LIB: &str = include_str!("../../console/src/lib.rs");

/// Builders `chalk serve` deliberately does not call, each with the reason.
/// An entry that stops existing in the console source fails the test too —
/// a stale exception is a hand-list rotting.
const EXCEPTIONS: [(&str, &str); 5] = [
    (
        "with_analytics_client_js",
        "the hosted runtime's client instrumentation script; self-host \
         serves an empty file at the same route — same rationale as \
         with_analytics",
    ),
    (
        "with_analytics",
        "product analytics is hosted-only BY THIS OMISSION: wiring it here \
         would put telemetry in every self-hosted district's console",
    ),
    (
        "with_magic_login",
        "selects how the console authenticates; wired only by the hosted \
         runtime, and serve's startup check documents why",
    ),
    (
        "with_sso_invalidator",
        "multi-tenant router-cache hook; only the hosted runtime has a \
         router cache to invalidate",
    ),
    (
        "with_saml_signing_cert",
        "the in-memory cert provisioned at hosted tenant signup; self-host \
         serves the cert from config.idp.saml_cert_path — the fallback the \
         download handler documents",
    ),
];

#[test]
fn serve_calls_every_appstate_builder_or_names_the_exception() {
    let mut missing = Vec::new();
    for line in CONSOLE_LIB.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("pub fn with_") else {
            continue;
        };
        let Some(name_rest) = rest.split('(').next() else {
            continue;
        };
        let name = format!("with_{name_rest}");
        if EXCEPTIONS.iter().any(|(e, _)| *e == name) {
            continue;
        }
        // A real call, not a mention in a comment: ".with_x(".
        if !SERVE.contains(&format!(".{name}(")) {
            missing.push(name);
        }
    }
    assert!(
        missing.is_empty(),
        "AppState builders serve.rs never calls (wire them or add a \
         documented exception): {missing:?}"
    );
    for (e, _) in EXCEPTIONS {
        assert!(
            CONSOLE_LIB.contains(&format!("pub fn {e}(")),
            "exception {e} no longer exists on AppState; remove it"
        );
    }
}

/// The public codebase carries NO analytics implementation: no vendor
/// client, no endpoint, no key handling — only the empty seam. Self-host
/// privacy is structural (nothing to disable because nothing exists), and
/// this test keeps it that way: a vendor string or a `with_analytics` call
/// appearing anywhere in the public crates fails the build.
#[test]
fn the_public_crates_carry_no_analytics_implementation() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let vendors = [
        "posthog",
        "mixpanel",
        "amplitude",
        "segment.io",
        "google-analytics",
    ];
    let mut wired = Vec::new();
    let mut vendor_hits = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                let name = path.file_name().unwrap().to_string_lossy();
                if name != "target" && !name.starts_with('.') {
                    stack.push(path);
                }
            } else if path.ends_with("tests/serve_wiring.rs") {
                // This file names the vendors in order to ban them.
            } else if path.extension().is_some_and(|e| e == "rs" || e == "html") {
                let body = std::fs::read_to_string(&path).unwrap_or_default();
                let lower = body.to_lowercase();
                for v in vendors {
                    if lower.contains(v) {
                        vendor_hits.push(format!("{}: {v}", path.display()));
                    }
                }
                // The seam's definition and its tests are the only allowed
                // mentions of wiring; a call in binary code is a leak.
                let is_definition = path.ends_with("crates/console/src/lib.rs");
                let is_test = path.to_string_lossy().contains("tests")
                    || path.to_string_lossy().contains("authz");
                if !is_definition && !is_test && body.contains(".with_analytics(") {
                    wired.push(path.display().to_string());
                }
            }
        }
    }
    assert!(
        vendor_hits.is_empty(),
        "analytics vendor strings in the public repo: {vendor_hits:?}"
    );
    assert!(
        wired.is_empty(),
        "with_analytics wired outside the seam definition/tests: {wired:?}"
    );
}
