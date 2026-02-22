# Chalk Webhooks Partner Documentation

Chalk webhooks deliver real-time notifications when student information system (SIS) data changes. This guide covers everything you need to receive, verify, and process webhook events.

## Table of Contents

- [Getting Started](#getting-started)
- [Security Modes](#security-modes)
- [HTTP Headers](#http-headers)
- [Envelope Schema](#envelope-schema)
- [Event Types Reference](#event-types-reference)
- [Batched vs Per-Entity Mode](#batched-vs-per-entity-mode)
- [Signature Verification (sign_only)](#signature-verification-sign_only)
- [Payload Decryption (encrypted)](#payload-decryption-encrypted)
- [Entity Schemas](#entity-schemas)
- [Scoping](#scoping)
- [Idempotency](#idempotency)
- [Retry Behavior](#retry-behavior)
- [Error Handling](#error-handling)
- [Marketplace vs Open-Source](#marketplace-vs-open-source)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

---

## Getting Started

To receive webhook events from Chalk, you need:

1. **An HTTPS endpoint** that accepts `POST` requests and returns a `2xx` status code on success.
2. **A shared secret** used to verify the authenticity of webhook deliveries.
3. **Registration** of your endpoint, either through TOML configuration (open-source) or the Chalk Marketplace.

### TOML Configuration (Open-Source)

Add a `[[webhooks]]` section to your `chalk.toml`:

```toml
[[webhooks]]
name = "My Integration"
url = "https://your-app.example.com/webhooks/chalk"
secret = "your-shared-secret-at-least-32-chars"
enabled = true
mode = "batched"              # "batched" or "per_entity"
security_mode = "sign_only"   # "sign_only" or "encrypted"

[webhooks.scoping]
entity_types = ["user", "enrollment"]
org_sourced_ids = ["org-001"]
roles = ["student", "teacher"]
excluded_fields = ["demographics.birthDate"]
```

### Marketplace Registration

If you are integrating via the Chalk Marketplace, endpoint registration is handled through the partner onboarding flow. You will receive your shared secret during the registration process.

---

## Security Modes

Chalk supports two security modes for webhook payloads:

| Mode | Header Value | Description | Use Case |
|------|-------------|-------------|----------|
| **sign_only** | `sign_only` | Payload is sent as plaintext JSON with an HMAC-SHA256 signature | Default. Suitable when transport is HTTPS and payload sensitivity is moderate. |
| **encrypted** | `encrypted` | Payload is encrypted with AES-256-GCM using an HKDF-derived key | Required for sensitive data (PII, demographics) or when regulatory compliance demands encryption at rest and in transit. |

In `sign_only` mode, the JSON body is readable and the `X-Chalk-Signature` header contains the HMAC-SHA256 signature for verification.

In `encrypted` mode, the JSON body contains an `EncryptedPayload` object with base64-encoded `nonce` and `ciphertext` fields. You must decrypt the ciphertext to access the original event JSON.

---

## HTTP Headers

Every webhook delivery includes the following headers:

| Header | Example | Description |
|--------|---------|-------------|
| `Content-Type` | `application/json` | Always JSON |
| `User-Agent` | `Chalk/1.0.0` | Chalk version identifier |
| `X-Chalk-Event-Id` | `evt-a1b2c3d4-e5f6-7890-abcd-ef1234567890` | Unique event identifier for idempotency |
| `X-Chalk-Webhook-Id` | `wh-9876fedc-ba09-8765-4321-0fedcba98765` | The webhook endpoint configuration ID |
| `X-Chalk-Timestamp` | `2025-09-15T14:30:00Z` | ISO 8601 timestamp of when the event was generated |
| `X-Chalk-Security-Mode` | `sign_only` or `encrypted` | Which security mode is active |
| `X-Chalk-Signature` | `sha256=a1b2c3...` | HMAC-SHA256 hex signature (present in both modes) |

---

## Envelope Schema

### sign_only Mode

The request body is a JSON `WebhookEvent`:

```json
{
  "webhook_id": "wh-9876fedc-ba09-8765-4321-0fedcba98765",
  "event_id": "evt-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "event_type": "user.created",
  "timestamp": "2025-09-15T14:30:00Z",
  "tenant_id": "tenant-001",
  "sync_run_id": 42,
  "data": {
    "single": {
      "entity_type": "user",
      "action": "created",
      "sourced_id": "user-001",
      "entity": { ... }
    }
  }
}
```

### encrypted Mode

The request body is an `EncryptedPayload`:

```json
{
  "nonce": "base64-encoded-12-byte-nonce",
  "ciphertext": "base64-encoded-encrypted-data"
}
```

After decryption, the plaintext is the same `WebhookEvent` JSON as in `sign_only` mode.

---

## Event Types Reference

Event types follow the pattern `<entity_type>.<action>`:

| Event Type | Description |
|-----------|-------------|
| `sync.completed` | A full sync run has completed |
| `org.created` | A new organization was created |
| `org.updated` | An organization was updated |
| `org.deleted` | An organization was deleted |
| `academic_session.created` | A new academic session was created |
| `academic_session.updated` | An academic session was updated |
| `academic_session.deleted` | An academic session was deleted |
| `user.created` | A new user was created |
| `user.updated` | A user was updated |
| `user.deleted` | A user was deleted |
| `course.created` | A new course was created |
| `course.updated` | A course was updated |
| `course.deleted` | A course was deleted |
| `class.created` | A new class was created |
| `class.updated` | A class was updated |
| `class.deleted` | A class was deleted |
| `enrollment.created` | A new enrollment was created |
| `enrollment.updated` | An enrollment was updated |
| `enrollment.deleted` | An enrollment was deleted |
| `demographics.created` | Demographics record was created |
| `demographics.updated` | Demographics record was updated |
| `demographics.deleted` | Demographics record was deleted |

### Example: user.created

```json
{
  "webhook_id": "wh-001",
  "event_id": "evt-abc123",
  "event_type": "user.created",
  "timestamp": "2025-09-15T14:30:00Z",
  "tenant_id": "tenant-001",
  "sync_run_id": 42,
  "data": {
    "single": {
      "entity_type": "user",
      "action": "created",
      "sourced_id": "user-001",
      "entity": {
        "sourcedId": "user-001",
        "status": "active",
        "dateLastModified": "2025-09-15T14:30:00Z",
        "username": "jdoe",
        "enabledUser": true,
        "givenName": "John",
        "familyName": "Doe",
        "role": "student",
        "email": "jdoe@example.com",
        "orgs": ["org-001"],
        "grades": ["09"],
        "userIds": [
          { "type": "LDAP", "identifier": "jdoe@example.com" }
        ],
        "agents": ["parent-001"]
      }
    }
  }
}
```

### Example: enrollment.deleted

```json
{
  "webhook_id": "wh-001",
  "event_id": "evt-def456",
  "event_type": "enrollment.deleted",
  "timestamp": "2025-09-15T15:00:00Z",
  "tenant_id": "tenant-001",
  "sync_run_id": 43,
  "data": {
    "single": {
      "entity_type": "enrollment",
      "action": "deleted",
      "sourced_id": "enr-001",
      "entity": {
        "sourcedId": "enr-001",
        "status": "tobedeleted",
        "dateLastModified": "2025-09-15T15:00:00Z",
        "user": "user-001",
        "class": "class-001",
        "school": "org-002",
        "role": "student"
      }
    }
  }
}
```

---

## Batched vs Per-Entity Mode

### Per-Entity Mode (`per_entity`)

Each change is delivered as an individual webhook event with a `single` data variant:

```json
{
  "event_type": "user.created",
  "data": {
    "single": {
      "entity_type": "user",
      "action": "created",
      "sourced_id": "user-001",
      "entity": { ... }
    }
  }
}
```

### Batched Mode (`batched`)

All changes from a sync run are delivered in a single webhook event with a `batch` data variant:

```json
{
  "event_type": "sync.completed",
  "data": {
    "batch": {
      "changes": [
        {
          "entity_type": "user",
          "action": "created",
          "sourced_id": "user-001",
          "entity": { ... }
        },
        {
          "entity_type": "enrollment",
          "action": "created",
          "sourced_id": "enr-001",
          "entity": { ... }
        },
        {
          "entity_type": "class",
          "action": "updated",
          "sourced_id": "class-001",
          "entity": { ... }
        }
      ]
    }
  }
}
```

**Which should I choose?**

- Use **per_entity** when you want to process changes individually and prefer simpler handler logic.
- Use **batched** when you want to process all changes from a sync atomically, or to reduce the number of HTTP requests.

---

## Signature Verification (sign_only)

The `X-Chalk-Signature` header contains `sha256=<hex>`, where `<hex>` is the HMAC-SHA256 of the raw request body using your shared secret as the key.

**Always verify the signature before processing the payload.**

### Python

```python
import hmac
import hashlib

def verify_signature(secret: str, body: bytes, signature_header: str) -> bool:
    expected = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    received = signature_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, received)

# Usage in a Flask handler:
@app.route("/webhooks/chalk", methods=["POST"])
def handle_webhook():
    signature = request.headers.get("X-Chalk-Signature", "")
    if not verify_signature(WEBHOOK_SECRET, request.data, signature):
        return "Invalid signature", 401
    event = request.get_json()
    # Process event...
    return "OK", 200
```

### Node.js

```javascript
const crypto = require("crypto");

function verifySignature(secret, body, signatureHeader) {
  const expected = crypto
    .createHmac("sha256", secret)
    .update(body)
    .digest("hex");
  const received = signatureHeader.replace("sha256=", "");
  return crypto.timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(received, "hex")
  );
}

// Usage in an Express handler:
app.post("/webhooks/chalk", express.raw({ type: "application/json" }), (req, res) => {
  const signature = req.headers["x-chalk-signature"] || "";
  if (!verifySignature(WEBHOOK_SECRET, req.body, signature)) {
    return res.status(401).send("Invalid signature");
  }
  const event = JSON.parse(req.body);
  // Process event...
  res.status(200).send("OK");
});
```

### Ruby

```ruby
require "openssl"

def verify_signature(secret, body, signature_header)
  expected = OpenSSL::HMAC.hexdigest("SHA256", secret, body)
  received = signature_header.delete_prefix("sha256=")
  Rack::Utils.secure_compare(expected, received)
end

# Usage in a Sinatra handler:
post "/webhooks/chalk" do
  body = request.body.read
  signature = request.env["HTTP_X_CHALK_SIGNATURE"] || ""
  halt 401, "Invalid signature" unless verify_signature(WEBHOOK_SECRET, body, signature)
  event = JSON.parse(body)
  # Process event...
  status 200
  "OK"
end
```

### Go

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "net/http"
    "strings"
)

func verifySignature(secret string, body []byte, signatureHeader string) bool {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(body)
    expected := hex.EncodeToString(mac.Sum(nil))
    received := strings.TrimPrefix(signatureHeader, "sha256=")
    return hmac.Equal([]byte(expected), []byte(received))
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Bad request", http.StatusBadRequest)
        return
    }
    signature := r.Header.Get("X-Chalk-Signature")
    if !verifySignature(webhookSecret, body, signature) {
        http.Error(w, "Invalid signature", http.StatusUnauthorized)
        return
    }
    // Process event from body...
    w.WriteHeader(http.StatusOK)
}
```

### Java

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class WebhookVerifier {
    public static boolean verifySignature(String secret, byte[] body, String signatureHeader)
            throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256"));
        byte[] hash = mac.doFinal(body);
        String expected = bytesToHex(hash);
        String received = signatureHeader.replace("sha256=", "");
        return MessageDigest.isEqual(expected.getBytes(), received.getBytes());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
```

---

## Payload Decryption (encrypted)

In `encrypted` mode, the request body is an `EncryptedPayload` JSON object. To decrypt:

1. Derive a 256-bit key from the shared secret using **HKDF-SHA256** with:
   - **Salt**: `chalk-webhook-v1` (literal bytes)
   - **Info**: `webhook-encryption-key` (literal bytes)
2. Base64-decode the `nonce` (12 bytes) and `ciphertext` fields.
3. Decrypt using **AES-256-GCM** with the derived key and nonce.

The decrypted plaintext is the same `WebhookEvent` JSON as in `sign_only` mode.

**Important**: Even in encrypted mode, the `X-Chalk-Signature` header is still present and signs the encrypted payload JSON (not the plaintext). You should verify the signature first, then decrypt.

### Python

```python
import hashlib
import hmac as hmac_mod
import json
from base64 import b64decode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_key(secret: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"chalk-webhook-v1",
        info=b"webhook-encryption-key",
    )
    return hkdf.derive(secret.encode("utf-8"))

def decrypt_payload(secret: str, encrypted_json: dict) -> dict:
    key = derive_key(secret)
    nonce = b64decode(encrypted_json["nonce"])
    ciphertext = b64decode(encrypted_json["ciphertext"])
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext)

# Usage:
@app.route("/webhooks/chalk", methods=["POST"])
def handle_encrypted_webhook():
    # 1. Verify signature on encrypted body
    signature = request.headers.get("X-Chalk-Signature", "")
    if not verify_signature(WEBHOOK_SECRET, request.data, signature):
        return "Invalid signature", 401
    # 2. Decrypt
    encrypted = request.get_json()
    event = decrypt_payload(WEBHOOK_SECRET, encrypted)
    # 3. Process event...
    return "OK", 200
```

### Node.js

```javascript
const crypto = require("crypto");

function deriveKey(secret) {
  const hkdf = crypto.hkdfSync(
    "sha256",
    Buffer.from(secret, "utf-8"),
    Buffer.from("chalk-webhook-v1"),
    Buffer.from("webhook-encryption-key"),
    32
  );
  return Buffer.from(hkdf);
}

function decryptPayload(secret, encryptedJson) {
  const key = deriveKey(secret);
  const nonce = Buffer.from(encryptedJson.nonce, "base64");
  const ciphertext = Buffer.from(encryptedJson.ciphertext, "base64");

  // AES-256-GCM: last 16 bytes are the auth tag
  const authTag = ciphertext.subarray(ciphertext.length - 16);
  const encrypted = ciphertext.subarray(0, ciphertext.length - 16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf-8"));
}
```

### Ruby

```ruby
require "openssl"
require "base64"
require "json"

def derive_key(secret)
  hkdf = OpenSSL::KDF.hkdf(
    secret,
    salt: "chalk-webhook-v1",
    info: "webhook-encryption-key",
    length: 32,
    hash: "SHA256"
  )
end

def decrypt_payload(secret, encrypted_json)
  key = derive_key(secret)
  nonce = Base64.decode64(encrypted_json["nonce"])
  ciphertext = Base64.decode64(encrypted_json["ciphertext"])

  cipher = OpenSSL::Cipher::AES.new(256, :GCM)
  cipher.decrypt
  cipher.key = key
  cipher.iv = nonce

  # AES-GCM: last 16 bytes are the auth tag
  auth_tag = ciphertext[-16..]
  encrypted_data = ciphertext[0...-16]

  cipher.auth_tag = auth_tag
  plaintext = cipher.update(encrypted_data) + cipher.final
  JSON.parse(plaintext)
end
```

### Go

```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "encoding/json"

    "golang.org/x/crypto/hkdf"
    "crypto/sha256"
    "io"
)

func deriveKey(secret string) ([]byte, error) {
    hkdfReader := hkdf.New(sha256.New, []byte(secret), []byte("chalk-webhook-v1"), []byte("webhook-encryption-key"))
    key := make([]byte, 32)
    if _, err := io.ReadFull(hkdfReader, key); err != nil {
        return nil, err
    }
    return key, nil
}

func decryptPayload(secret string, nonce64 string, ciphertext64 string) ([]byte, error) {
    key, err := deriveKey(secret)
    if err != nil {
        return nil, err
    }
    nonce, err := base64.StdEncoding.DecodeString(nonce64)
    if err != nil {
        return nil, err
    }
    ciphertext, err := base64.StdEncoding.DecodeString(ciphertext64)
    if err != nil {
        return nil, err
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    return gcm.Open(nil, nonce, ciphertext, nil)
}
```

### Java

```java
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import java.util.Base64;

// Requires BouncyCastle or a library that supports HKDF.
// Example uses org.bouncycastle.crypto.generators.HKDFBytesGenerator:

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

public class WebhookDecryptor {

    public static byte[] deriveKey(String secret) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(
            secret.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            "chalk-webhook-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8),
            "webhook-encryption-key".getBytes(java.nio.charset.StandardCharsets.UTF_8)
        ));
        byte[] key = new byte[32];
        hkdf.generateBytes(key, 0, 32);
        return key;
    }

    public static byte[] decryptPayload(String secret, String nonce64, String ciphertext64)
            throws Exception {
        byte[] key = deriveKey(secret);
        byte[] nonce = Base64.getDecoder().decode(nonce64);
        byte[] ciphertext = Base64.getDecoder().decode(ciphertext64);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(key, "AES"),
            new GCMParameterSpec(128, nonce)
        );
        return cipher.doFinal(ciphertext);
    }
}
```

---

## Entity Schemas

All entities follow the [OneRoster 1.1 specification](https://www.imsglobal.org/oneroster-v11-final-specification) with camelCase JSON field names.

### Org

```json
{
  "sourcedId": "org-001",
  "status": "active",
  "dateLastModified": "2025-09-15T14:30:00Z",
  "name": "Springfield School District",
  "type": "district",
  "identifier": "SSD001",
  "parent": null,
  "children": ["org-002", "org-003"]
}
```

### AcademicSession

```json
{
  "sourcedId": "term-001",
  "status": "active",
  "dateLastModified": "2025-09-15T14:30:00Z",
  "title": "Fall 2025",
  "startDate": "2025-08-15",
  "endDate": "2025-12-20",
  "type": "term",
  "schoolYear": "2025",
  "parent": null,
  "children": []
}
```

### User

```json
{
  "sourcedId": "user-001",
  "status": "active",
  "dateLastModified": "2025-09-15T14:30:00Z",
  "username": "jdoe",
  "enabledUser": true,
  "givenName": "John",
  "familyName": "Doe",
  "middleName": "M",
  "role": "student",
  "identifier": "STU001",
  "email": "jdoe@example.com",
  "orgs": ["org-001"],
  "grades": ["09"],
  "userIds": [
    { "type": "LDAP", "identifier": "jdoe@example.com" }
  ],
  "agents": ["parent-001"]
}
```

### Course

```json
{
  "sourcedId": "course-001",
  "status": "active",
  "dateLastModified": "2025-09-15T14:30:00Z",
  "title": "Algebra I",
  "courseCode": "ALG1",
  "grades": ["09"],
  "subjects": ["Mathematics"],
  "org": "org-001",
  "schoolYear": "2025"
}
```

### Class

```json
{
  "sourcedId": "class-001",
  "status": "active",
  "dateLastModified": "2025-09-15T14:30:00Z",
  "title": "Algebra I - Period 1",
  "classCode": "ALG1-P1",
  "classType": "scheduled",
  "location": "Room 101",
  "grades": ["09"],
  "subjects": ["Mathematics"],
  "course": "course-001",
  "school": "org-002",
  "terms": ["term-001"],
  "periods": ["1"]
}
```

### Enrollment

```json
{
  "sourcedId": "enr-001",
  "status": "active",
  "dateLastModified": "2025-09-15T14:30:00Z",
  "user": "user-001",
  "class": "class-001",
  "school": "org-002",
  "role": "student",
  "primary": true,
  "beginDate": "2025-08-15",
  "endDate": "2026-06-01"
}
```

### Demographics

```json
{
  "sourcedId": "user-001",
  "status": "active",
  "dateLastModified": "2025-09-15T14:30:00Z",
  "birthDate": "2010-05-15",
  "sex": "male",
  "americanIndianOrAlaskaNative": false,
  "asian": false,
  "blackOrAfricanAmerican": false,
  "nativeHawaiianOrOtherPacificIslander": false,
  "white": true,
  "demographicRaceTwoOrMoreRaces": false,
  "hispanicOrLatinoEthnicity": false
}
```

---

## Scoping

Scoping filters control which changes are delivered to your endpoint. All filters are optional -- omitting a filter means "allow all."

### Entity Type Filter

Only receive changes for specific entity types:

```toml
[webhooks.scoping]
entity_types = ["user", "enrollment", "class"]
```

Valid values: `org`, `academic_session`, `user`, `course`, `class`, `enrollment`, `demographics`.

### Org Filter

Only receive changes associated with specific organizations:

```toml
[webhooks.scoping]
org_sourced_ids = ["org-001", "org-002"]
```

How org association is determined:
- **User**: matches if any value in the `orgs` array is in the filter list
- **Class**: matches if the `school` field is in the filter list
- **Enrollment**: matches if the `school` field is in the filter list
- **Org**: matches if the entity's own `sourcedId` is in the filter list
- **Other types** (Course, AcademicSession, Demographics): always pass the org filter

### Role Filter

Only receive changes for users/enrollments with specific roles:

```toml
[webhooks.scoping]
roles = ["student", "teacher"]
```

- **User**: matches against the `role` field
- **Enrollment**: matches against the `role` field
- **Other types**: always pass the role filter

### Field Exclusions

Remove sensitive fields from entity payloads before delivery:

```toml
[webhooks.scoping]
excluded_fields = ["demographics.birthDate", "email", "phone", "sms"]
```

Fields use dot-path notation for nested objects. For example, `demographics.birthDate` removes the `birthDate` key from a nested `demographics` object.

---

## Idempotency

Every webhook event includes a unique `event_id` (also sent as the `X-Chalk-Event-Id` header). Use this value to deduplicate events in case of retries.

**Recommended approach:**

1. Store processed `event_id` values in a database or cache.
2. Before processing a new event, check if the `event_id` has already been processed.
3. If already processed, return `200 OK` without re-processing.

```python
@app.route("/webhooks/chalk", methods=["POST"])
def handle_webhook():
    event = request.get_json()
    event_id = event["event_id"]

    if already_processed(event_id):
        return "OK", 200  # Idempotent response

    process_event(event)
    mark_processed(event_id)
    return "OK", 200
```

---

## Retry Behavior

If your endpoint does not return a `2xx` response, Chalk will retry delivery with exponential backoff:

| Attempt | Delay After Failure |
|---------|-------------------|
| 1 | Immediate |
| 2 | 1 minute |
| 3 | 5 minutes |
| 4 | 30 minutes |
| 5 | 2 hours |

After 5 failed attempts, the delivery is marked as permanently failed. The maximum retry window is approximately 12 hours from the initial attempt.

**Timeout**: Chalk waits up to **30 seconds** for a response. If your endpoint does not respond within 30 seconds, the delivery is considered failed and will be retried.

---

## Error Handling

Your endpoint should return appropriate HTTP status codes:

| Status Code | Chalk Behavior |
|-------------|---------------|
| `200-299` | **Success** -- delivery marked as delivered |
| `400-499` | **Client error** -- delivery marked as permanently failed, **no retry** (the request is malformed or unauthorized, retrying will not help) |
| `500-599` | **Server error** -- delivery will be **retried** according to the retry schedule |
| Timeout (>30s) | Treated as a server error -- **retried** |
| Connection refused | Treated as a server error -- **retried** |

**Best practice**: Return `200 OK` as quickly as possible. If processing takes time, accept the event, queue it for async processing, and return `200` immediately.

---

## Marketplace vs Open-Source

| Feature | Open-Source | Marketplace |
|---------|-----------|-------------|
| Configuration | `chalk.toml` | Marketplace partner portal |
| Webhook source | `toml` | `marketplace` |
| Tenant ID | Optional | Always populated |
| Secret management | Self-managed | Provisioned by Chalk |
| Monitoring | Self-hosted logs | Chalk dashboard |
| Scoping | TOML configuration | Partner portal UI |

In the Marketplace, the `tenant_id` field identifies which school district the data belongs to. This allows a single webhook endpoint to receive data from multiple districts.

---

## Security Best Practices

1. **Always use HTTPS**. Chalk will only deliver webhooks to HTTPS endpoints. Never expose a plaintext HTTP endpoint.

2. **Always verify signatures**. Before processing any webhook payload, verify the `X-Chalk-Signature` header using the constant-time comparison functions shown in the code samples above.

3. **Use encrypted mode for sensitive data**. If your webhook payloads include demographics, PII, or other sensitive fields, use `encrypted` security mode.

4. **Rotate secrets periodically**. Update your shared secret on a regular schedule. During rotation:
   - Configure the new secret in Chalk.
   - Update your endpoint to accept signatures from both the old and new secrets.
   - Once all deliveries use the new secret, remove the old one.

5. **Validate the timestamp**. Check the `X-Chalk-Timestamp` header and reject events older than a reasonable window (e.g., 5 minutes) to prevent replay attacks.

6. **Respond quickly**. Return `200 OK` immediately and process events asynchronously. This prevents timeouts and reduces retry traffic.

7. **Implement idempotency**. Always deduplicate events using the `event_id` to safely handle retries.

8. **Keep secrets out of logs**. Never log the shared secret or raw decryption keys. If logging payloads, redact sensitive fields.

---

## Troubleshooting

### I am not receiving any webhook events

- Verify the webhook endpoint is **enabled** in your configuration.
- Check that the endpoint URL is reachable from the Chalk server.
- Ensure your scoping filters are not too restrictive -- try removing all scoping to test.
- Check the Chalk logs for delivery errors.

### Signature verification fails

- Ensure you are using the **raw request body** (bytes) for HMAC computation, not a parsed-and-re-serialized JSON string.
- Verify the shared secret matches exactly between Chalk and your endpoint.
- Check that you are using the correct comparison: the signature header format is `sha256=<hex>`.

### Decryption fails

- Verify the HKDF parameters:
  - Algorithm: SHA-256
  - Salt: `chalk-webhook-v1` (literal ASCII bytes)
  - Info: `webhook-encryption-key` (literal ASCII bytes)
  - Output length: 32 bytes
- Ensure you are base64-decoding both `nonce` and `ciphertext` fields.
- The nonce should be exactly 12 bytes after decoding.
- AES-256-GCM ciphertext includes a 16-byte authentication tag appended to the encrypted data.

### I receive duplicate events

This is expected during retries. Implement idempotency using the `event_id` field. See the [Idempotency](#idempotency) section.

### Events are arriving late or out of order

Webhook events may be delivered out of order, especially during retries. Use the `timestamp` field and `sync_run_id` to establish ordering. Do not rely on delivery order.

### My endpoint is timing out

Chalk waits up to 30 seconds for a response. If your processing takes longer:
- Accept the event and return `200 OK` immediately.
- Queue the event for asynchronous processing.
- Consider using batched mode to reduce the number of HTTP requests.

### I see events for entities I did not expect

Check your scoping configuration. Empty filter arrays mean "allow all." If you only want users and enrollments, explicitly set `entity_types = ["user", "enrollment"]`.
