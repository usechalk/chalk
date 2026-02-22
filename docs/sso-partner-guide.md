# SSO Partner Integration Guide

## Overview

Chalk is an open-source K-12 identity and rostering platform that includes a built-in Identity Provider (IDP). Partners (SaaS vendors, learning platforms, assessment tools, etc.) can integrate their applications with Chalk so that school users authenticate once through Chalk and gain seamless access to the partner app.

Chalk supports two industry-standard SSO protocols:

- **SAML 2.0** — Chalk acts as the SAML Identity Provider (IDP); your application is the Service Provider (SP).
- **OpenID Connect (OIDC)** — Chalk acts as the OIDC Provider (OP); your application is the Relying Party (RP).

When a school district configures your application as an SSO partner in Chalk, their users can launch your app from the Chalk portal or navigate directly to your app and be redirected to Chalk for authentication.

---

## SAML 2.0 Integration

### IDP Metadata

Chalk publishes its SAML IDP metadata at:

```
{chalk_url}/idp/saml/metadata
```

This XML document contains the IDP entity ID, SSO endpoint URLs, signing certificate, and supported NameID formats. You can use this URL to auto-configure your SP.

### Configuring Your Service Provider

To integrate your SP with Chalk, you need:

| Setting | Value |
|---|---|
| **IDP Entity ID** | The Chalk instance's `public_url` (e.g., `https://chalk.springfield.k12.us`) |
| **SSO URL (HTTP-Redirect)** | `{chalk_url}/idp/login` |
| **SSO URL (HTTP-POST)** | `{chalk_url}/idp/login` |
| **NameID Format** | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| **Signing Certificate** | Available in the metadata XML, or downloadable from the school admin |

Your SP must provide:

| Setting | Description |
|---|---|
| **SP Entity ID** | A globally unique identifier for your application (e.g., `https://yourapp.com`) |
| **ACS URL** | The Assertion Consumer Service URL where Chalk sends the SAML response (e.g., `https://yourapp.com/saml/consume`) |

### SAML Assertion Format

Chalk issues SAML 2.0 assertions with the following characteristics:

- **NameID**: The user's email address, formatted as `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
- **Issuer**: The Chalk instance's `public_url`
- **Signature**: RSA-SHA256 enveloped signature (when SAML signing is enabled)
- **Assertion validity**: 5 minutes from issue time
- **Session duration**: 8 hours from issue time

### Example SAML Response

Below is a sanitized example of the SAML response Chalk sends to your ACS URL (base64-decoded):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp_a1b2c3d4-e5f6-7890-abcd-ef1234567890"
                Version="2.0"
                IssueInstant="2025-01-15T14:30:00Z"
                Destination="https://yourapp.com/saml/consume"
                InResponseTo="_request_id_from_sp">
  <saml:Issuer>https://chalk.springfield.k12.us</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion Version="2.0"
                  ID="_assert_f1e2d3c4-b5a6-7890-abcd-ef1234567890"
                  IssueInstant="2025-01-15T14:30:00Z">
    <saml:Issuer>https://chalk.springfield.k12.us</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        jsmith@springfield.k12.us
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
          NotOnOrAfter="2025-01-15T14:35:00Z"
          Recipient="https://yourapp.com/saml/consume"
          InResponseTo="_request_id_from_sp"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2025-01-15T14:30:00Z"
                     NotOnOrAfter="2025-01-15T14:35:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://yourapp.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2025-01-15T14:30:00Z"
                         SessionNotOnOrAfter="2025-01-15T22:30:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>
```

### SP-Initiated vs IDP-Initiated Flows

Chalk supports both flows:

**SP-Initiated (recommended):**
1. User navigates to your application
2. Your SP generates a SAML AuthnRequest and redirects the user to Chalk's SSO URL
3. Chalk authenticates the user (login page)
4. Chalk sends a SAML response back to your ACS URL
5. Your SP validates the response and creates a session

**IDP-Initiated:**
1. User logs into the Chalk portal at `{chalk_url}/portal`
2. User clicks your application's tile
3. Chalk generates a SAML response and POSTs it to your ACS URL
4. Your SP validates the response and creates a session

> **Note:** IDP-initiated SSO requires your SP to accept unsolicited SAML responses (responses without a corresponding AuthnRequest). Not all SP implementations support this.

---

## OIDC Integration

### Discovery

Chalk publishes its OIDC configuration at the standard well-known endpoint:

```
{chalk_url}/idp/oidc/.well-known/openid-configuration
```

This document contains all the endpoint URLs, supported scopes, response types, and signing algorithms your client needs.

### Client Registration

OIDC clients are registered by the school administrator in the Chalk admin console or TOML configuration. The administrator provides:

- **Client ID** — A unique identifier for your application
- **Client Secret** — A shared secret for authenticating token requests
- **Redirect URIs** — One or more callback URLs where Chalk sends authorization codes

You should provide these values to the school administrator during setup. The client ID and secret should be generated securely by your application.

### Authorization Code Flow

Chalk supports the standard Authorization Code flow:

**Step 1 — Authorization Request**

Redirect the user's browser to Chalk's authorization endpoint:

```
GET {chalk_url}/idp/oidc/authorize
  ?response_type=code
  &client_id=your-client-id
  &redirect_uri=https://yourapp.com/callback
  &scope=openid profile email
  &state=random-csrf-token
  &nonce=random-nonce-value
```

| Parameter | Required | Description |
|---|---|---|
| `response_type` | Yes | Must be `code` |
| `client_id` | Yes | Your registered client ID |
| `redirect_uri` | Yes | Must match one of your registered redirect URIs |
| `scope` | Yes | Space-separated scopes (see Scopes section below) |
| `state` | Recommended | CSRF protection token, returned unchanged in the callback |
| `nonce` | Recommended | Replay protection value, included in the ID token |

**Step 2 — User Authentication**

Chalk presents its login page. The user authenticates using their password, QR badge, or picture password.

**Step 3 — Authorization Callback**

On successful authentication, Chalk redirects back to your `redirect_uri`:

```
GET https://yourapp.com/callback
  ?code=authorization-code-here
  &state=random-csrf-token
```

**Step 4 — Token Exchange**

Exchange the authorization code for tokens by making a POST request to the token endpoint:

```
POST {chalk_url}/idp/oidc/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=authorization-code-here
&redirect_uri=https://yourapp.com/callback
&client_id=your-client-id
&client_secret=your-client-secret
```

**Example Token Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Step 5 — Validate the ID Token**

The `id_token` is a signed JWT. Validate it by:

1. Fetching Chalk's JWKS from `{chalk_url}/idp/oidc/jwks`
2. Verifying the JWT signature against the published keys
3. Checking that `iss` matches the Chalk instance URL
4. Checking that `aud` contains your `client_id`
5. Checking that `exp` is in the future
6. Checking that `nonce` matches the value you sent (if provided)

### Scopes

| Scope | Description |
|---|---|
| `openid` | Required. Returns the `sub` claim in the ID token |
| `profile` | Adds `name`, `given_name`, `family_name`, and `role` claims |
| `email` | Adds `email` claim |

### UserInfo Endpoint

You can also retrieve user information using the access token:

```
GET {chalk_url}/idp/oidc/userinfo
Authorization: Bearer <access_token>
```

**Example UserInfo Response:**

```json
{
  "sub": "user-sourced-id-001",
  "email": "jsmith@springfield.k12.us",
  "name": "John Smith",
  "given_name": "John",
  "family_name": "Smith",
  "role": "student"
}
```

---

## JWT Claims Reference

The following claims may appear in ID tokens and UserInfo responses, depending on the requested scopes:

| Claim | Type | Scope | Description |
|---|---|---|---|
| `iss` | string | (always) | Issuer: the Chalk instance URL |
| `sub` | string | openid | Subject: the user's unique sourced ID in Chalk |
| `aud` | string | (always) | Audience: your client ID |
| `exp` | number | (always) | Expiration time (Unix timestamp) |
| `iat` | number | (always) | Issued-at time (Unix timestamp) |
| `nonce` | string | (always, if sent) | The nonce value from the authorization request |
| `email` | string | email | The user's email address |
| `name` | string | profile | The user's full display name |
| `given_name` | string | profile | The user's first name |
| `family_name` | string | profile | The user's last name |
| `role` | string | profile | The user's role (e.g., `student`, `teacher`, `administrator`) |

---

## Testing Your Integration

### Setting Up a Test Environment

1. Install Chalk on a test server or local machine
2. Initialize with `chalk init` and configure a test instance
3. Import or sync test users
4. Enable the IDP in `chalk.toml`:

```toml
[idp]
enabled = true
saml_cert_path = "/var/lib/chalk/saml.crt"
saml_key_path = "/var/lib/chalk/saml.key"

[chalk]
public_url = "https://chalk-test.yourcompany.com"
```

5. Add your application as an SSO partner:

**For SAML:**
```toml
[[sso_partners]]
name = "Your App (Test)"
protocol = "saml"
saml_entity_id = "https://yourapp.com"
saml_acs_url = "https://yourapp-staging.com/saml/consume"
```

**For OIDC:**
```toml
[[sso_partners]]
name = "Your App (Test)"
protocol = "oidc"
oidc_client_id = "your-test-client-id"
oidc_client_secret = "your-test-client-secret"
oidc_redirect_uris = ["https://yourapp-staging.com/callback"]
```

6. Start Chalk with `chalk serve`

### Verifying SAML Integration

- Confirm your SP can fetch and parse metadata from `{chalk_url}/idp/saml/metadata`
- Test SP-initiated SSO: trigger a login from your app and verify the full redirect flow
- Test IDP-initiated SSO (if supported): launch your app from the Chalk portal
- Verify the NameID (email) in the assertion matches the expected user
- Test with users in different roles to confirm role-based access filtering

### Verifying OIDC Integration

- Confirm your client can fetch discovery info from `{chalk_url}/idp/oidc/.well-known/openid-configuration`
- Initiate an authorization request and verify you receive a code at your callback
- Exchange the code for tokens and verify the ID token signature
- Call the UserInfo endpoint and verify the returned claims
- Test with invalid redirect URIs and expired codes to confirm proper error handling

---

## Troubleshooting

| Issue | Possible Cause | Solution |
|---|---|---|
| SAML metadata returns 404 | IDP not enabled or no `public_url` | Ensure `idp.enabled = true` and `chalk.public_url` is set |
| "Audience mismatch" error | SP Entity ID does not match `saml_entity_id` in Chalk | Verify the Entity ID configured in Chalk matches your SP exactly |
| SAML assertion expired | Clock skew between Chalk and your server | Sync both servers to NTP; assertions are valid for 5 minutes |
| OIDC token exchange fails | Wrong client secret or mismatched redirect URI | Verify `client_id`, `client_secret`, and `redirect_uri` match exactly |
| ID token signature invalid | Using wrong JWKS keys | Fetch fresh keys from `{chalk_url}/idp/oidc/jwks`; keys may rotate |
| "Invalid redirect_uri" error | Redirect URI not in the registered list | Add the exact URI (including path and query) to `oidc_redirect_uris` |
| Authorization code expired | Code was not exchanged quickly enough | Codes expire after 10 minutes; exchange immediately after receiving |
| User not found after SSO | User not synced in Chalk | Ensure the user exists in Chalk (synced from SIS or imported) |
| Role-based access denied | User's role not in the partner's `roles` list | Ask the school admin to add the appropriate role to the partner config |
