# WS-6 — OAuth verification and CASA filing pack

**Status:** ready to file · July 2026
**Owner:** Lundin Matthews (requires Google Cloud + Workspace super-admin)
**Why now:** verification runs **8–16 weeks elapsed** and gates *hosted* GA entirely. Self-host is unaffected — it uses the customer's own Cloud project and needs no review from us. PRD §8.1: hosted quotes must be quotable by **Jan–Mar 2027** (district budget season for FY2028). Missing that window costs a full year.

**Scope decision (locked):** file **read *and* write scopes together**, in one cycle, now — rather than filing read-only today and re-filing when write-back ships. Verification is per-scope, so a later addition means a second review. See §4 for the consequence this carries.

---

## 1. What to create

A **new, dedicated Cloud project** — not the Chromebook Getter one. D6 is absolute: never touch the verified Chromebook Getter listing's identity or scopes. A hosted server storing restricted-scope data triggers a fresh CASA assessment regardless, so there is nothing to reuse and everything to lose by mixing them.

1. New Google Cloud project, e.g. `chalk-hosted`.
2. Enable **Admin SDK API**.
3. OAuth consent screen: **External**, publishing status **In production**.
4. OAuth client: **Web application**. Redirect URI `https://usechalk.xyz/oauth/google/callback` (the hosted control plane; confirm the final path before filing — a mismatch is a rejection).
5. Submit for verification with the scopes in §2.
6. Engage a **CASA Tier 2** assessor (~$500–1k/yr, recurring).

---

## 2. Scopes, with the justification each one needs

Google asks *per scope*: what the app does with it, and why a narrower scope will not do. Answer in terms of the user's benefit, not the architecture.

| Scope | R/W | Justification |
|---|---|---|
| `admin.directory.device.chromeos.readonly` | R | Read the district's ChromeOS inventory — serial, model, status, OU, auto-update expiration, last sync, recent users — to populate the asset inventory and produce AUE/refresh planning reports. **Narrower will not do:** there is no per-OU or per-device read scope. |
| `admin.directory.device.chromeos` | W | Write back administrator-initiated changes: move devices between OUs, set the annotated user/location/asset-tag fields, and change device status (disable a lost device, deprovision at end of life). Every write is initiated by a signed-in district administrator, previewed before commit, and recorded in an immutable audit trail. **Narrower will not do:** Google offers no field-scoped or action-scoped variant. |
| `admin.directory.orgunit.readonly` | R | Read the OU tree so devices can be grouped by school and building, and so an OU move can be validated against real OUs before it is offered. |
| `admin.directory.orgunit` | W | *Only if* Chalk creates OUs. **Decide before filing** — the ChromeOS path does not need it; the existing user-provisioning path (`google-sync`) does, via `ensure_ou_exists`. If hosted will not create OUs, drop this and file read-only. See §4.2. |
| `admin.directory.user.readonly` | R | Resolve the `annotatedUser` and `recentUsers` fields on a device to a real person in the district's directory, so a Chromebook shows the student holding it. This is the product's core differentiator. |
| `admin.directory.user` | W | *Only if* hosted performs Workspace user provisioning (create/suspend). The ChromeOS device path never writes users. **Decide before filing** — see §4.2. |

**Every scope above is restricted**, so all of them attract CASA.

---

## 3. What reviewers will ask for

- **A demo video** showing each scope in use, from a signed-in admin's perspective — not a code walkthrough. For write scopes this means showing the preview-then-commit flow and the resulting audit record.
- **A privacy policy** covering the data and its retention. `usechalk.xyz/privacy` exists and was updated for devices, tickets and attachments — re-read it against what the reviewer sees.
- **A homepage** that plainly describes the app and matches the OAuth client name.
- **Limited Use compliance**: no transferring restricted-scope data to third parties, no advertising, no human reading except with consent or for security/legal. Chalk's subprocessor list is Postmark + cloud provider + object storage, and telemetry is opt-in and roster-blind.
- **Justification per scope**, as §2.

Supporting material we already have: `plans/ARCHITECTURE.md` §9 (security model — AES-256-GCM at rest, per-tenant schema isolation, scoped revocable tokens, immutable asset audit, role-gated destructive ops with typed confirmation) and §9.4 (FERPA-oriented data minimisation — device and ticket rows hold `sourced_id` references, never copied student PII).

---

## 4. Two risks this filing carries

### 4.1 Write scopes are being requested before write-back exists

Filing read + write in one cycle avoids a second review, which is the reason for the choice. The cost: **the reviewer will ask to see the write flow, and today it does not exist.** B6 is deliberately read-only — `ChromeOsClient` has no write methods, and a test asserts the read-write device scope is not in the requested set.

Mitigations, in order of preference:
1. **Build C4 (diff preview) + write-back before recording the demo video.** The scopes are filed either way; the video is the gate. This keeps the story honest.
2. Record read-only usage now and re-record when write-back ships, if the review timeline allows re-submission without restarting.
3. Be explicit in the justification that write-back is in active development and describe the preview-then-commit design.

**Do not** claim in the video that a feature works when it does not. A rejection for misrepresentation is far more expensive than a second cycle.

### 4.2 Two scopes may not be needed at all

`admin.directory.orgunit` (write) and `admin.directory.user` (write) belong to the **user-provisioning** path, not the device path. If hosted Chalk will not create OUs or provision Workspace users, requesting them weakens the least-privilege story on a restricted-scope review for no benefit. **Settle this before submitting** — it is a product decision, not a technical one.

Minimum viable set for hosted Devices alone:
```
admin.directory.device.chromeos.readonly
admin.directory.device.chromeos            (for write-back)
admin.directory.orgunit.readonly
admin.directory.user.readonly
```

---

## 5. Self-host is not affected

Worth stating in one line because it is the schedule hedge: self-hosters authenticate with **their own** service account in **their own** Cloud project via domain-wide delegation. Restricted-scope review binds to *our* OAuth client, not theirs. So self-host beta ships regardless of this filing, and this document blocks only hosted GA.

---

## 6. Checklist

- [ ] Decide the §4.2 question: are `orgunit` and `user` **write** scopes in scope for hosted?
- [ ] Create the Cloud project + enable Admin SDK
- [ ] Configure the consent screen, confirm the redirect URI matches the hosted callback exactly
- [ ] Write the per-scope justifications from §2
- [ ] Decide the §4.1 demo-video sequencing
- [ ] Submit for verification
- [ ] Engage a CASA Tier 2 assessor
- [ ] Track the elapsed clock against the Jan–Mar 2027 window
