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
const EXCEPTIONS: [(&str, &str); 3] = [
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
