# SAML SP roundtrip via SAMLtest.id

Verifies our IDP is a working SAML 2.0 Identity Provider by registering its
metadata at the free SAMLtest.id verifier and walking through an
SP-initiated login.

## What this proves

✅ Our `/idp/saml/metadata` document parses against a real SAMLtest verifier.

✅ The signing certificate embedded in our metadata is valid and matches
   the assertions our `/idp/saml/sso` endpoint emits.

✅ A real (third-party) Service Provider can complete an SP-initiated login
   round trip against our IDP.

## What this does NOT prove

⚠️ End-to-end with **your** target SP. Some SPs do strict attribute-statement
   validation (specific `NameID` formats, required attribute names) that
   SAMLtest is forgiving about.

⚠️ Logout flows. SAMLtest doesn't fully exercise SLO.

## Prerequisites

- The chalk-marketing docker stack running on `localhost:8080` (run
  `../_common/precheck.sh` to confirm).
- An activated tenant whose IDP metadata is reachable. The current default
  used by `run.sh` is `verify21778806025` — override with
  `CHALK_TENANT_SLUG=mytenant ./run.sh` if you've torn it down.
- A web browser. SAMLtest.id is interactive — there's no fully-headless path.

## Run

```bash
./run.sh
```

The script:
1. Pulls our metadata from `http://<slug>.localhost:8080/idp/saml/metadata`.
2. Validates it parses as XML and contains an `<IDPSSODescriptor>` and an
   `<X509Certificate>`.
3. Saves it to `metadata.xml` for inspection.
4. Prints the SAMLtest upload URL with paste-ready instructions.

## SAMLtest steps (manual, ~3 min)

1. Open https://samltest.id/upload.php
2. Upload the `metadata.xml` produced by `run.sh`. Note the entity ID it
   reports back (should match the `entityID` in the file).
3. Open https://samltest.id/start-idp-test/
4. In the entity ID search box, paste your tenant's entity ID
   (`http://<slug>.localhost:8080`).
5. Click **Login**. SAMLtest sends a SAML AuthnRequest to our IDP at
   `/idp/saml/sso`.
6. Complete the login flow on our side (admin password / QR badge /
   picture password — whichever your tenant has enabled).
7. SAMLtest receives the SAML Response, verifies the signature using the
   cert from our metadata, and shows you the parsed assertion.

✅ **PASS:** SAMLtest displays a green "Authentication Successful" page with
   your user attributes.

❌ **FAIL:** SAMLtest shows a red error. Common causes:
   - "Signature verification failed" → cert in metadata doesn't match the
     cert used to sign assertions. Check that the tenant's sealed SAML
     keypair is being unsealed correctly in `crates/hosted/src/context.rs`.
   - "AudienceRestriction mismatch" → SAMLtest's entity ID isn't in the
     allowed audiences. Add SAMLtest as an SP partner in `/sso-partners`.

## Layout

```
saml-sp/
├── README.md
└── run.sh        # fetches + validates metadata, prints next steps
```
