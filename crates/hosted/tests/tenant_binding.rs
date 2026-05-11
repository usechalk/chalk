//! Cross-tenant binding integration tests.
//!
//! These tests verify that authentication artifacts (SAML assertions, OIDC
//! tokens) issued for one tenant cannot be replayed against another tenant in
//! the multi-tenant hosted runtime. Both tests are stubs: real coverage
//! requires a SAML response builder + signer and a running OIDC token issuer
//! per tenant. The OSS `chalk-idp` crate does not currently expose test
//! helpers for either, so this file registers the gap as a tracked,
//! intentionally-`#[ignore]`d test.
//!
//! When the helpers land, remove `#[ignore]` and implement the bodies per
//! the manual test plan in each test's doc comment.

/// Cross-tenant SAML replay test (stub).
///
/// Manual test plan:
/// 1. Spin up Postgres via testcontainers.
/// 2. Boot a `chalk-hosted` instance bound to apex `test.local`.
/// 3. Provision two tenants: `alpha` and `bravo`. Each gets its own SAML
///    keypair (encrypted under the master key in DB).
/// 4. Have `alpha` issue a SAML assertion (signed by alpha's key) for some
///    SP partner.
/// 5. POST that assertion to `bravo.test.local`'s ACS-equivalent endpoint
///    (the IdP/portal endpoint that consumes assertions, e.g.
///    `/idp/saml/acs` once that route exists, or the equivalent under the
///    portal flow).
/// 6. Assert response is 4xx and that no session cookie is issued for
///    bravo.
///
/// Acceptance: cross-tenant assertion is rejected because the signing key
/// does not match bravo's configured signing certificate.
#[tokio::test]
#[ignore = "stub: requires SAML response builder/signer test helpers"]
async fn saml_assertion_signed_by_alpha_is_rejected_by_bravo() {
    // TODO: implement once chalk-idp exposes a `build_signed_response` test
    // helper. See module docs for the manual test plan.
    unimplemented!("see module docs for manual test plan");
}

/// OIDC tenant-scoped issuer test (stub).
///
/// Manual test plan:
/// 1. Provision tenants `alpha` and `bravo`.
/// 2. Drive each tenant through its OIDC issuance path.
/// 3. Decode the issued ID token and assert that the `iss` claim is the
///    per-tenant issuer URL (e.g. `https://alpha.test.local/idp/oidc` and
///    `https://bravo.test.local/idp/oidc` respectively), and is **not** a
///    shared/global issuer.
/// 4. Assert that an ID token with `iss = alpha.test.local/...` fails
///    validation when presented to bravo's OIDC verifier.
///
/// Acceptance: tokens are scoped to their issuing tenant and not
/// interchangeable across tenants.
#[tokio::test]
#[ignore = "stub: requires OIDC token issuance test helpers"]
async fn oidc_id_token_iss_claim_is_per_tenant() {
    // TODO: implement once chalk-idp exposes an OIDC token-issue test
    // helper. See module docs for the manual test plan.
    unimplemented!("see module docs for manual test plan");
}
