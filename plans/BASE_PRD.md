# Chalk — Product Requirements Document

**Version:** 1.0
**Date:** February 16, 2026
**Status:** Draft
**Author:** Lundin

---

## Executive Summary

Chalk is an open-source identity, rostering, and SIS integration platform purpose-built for K-12 schools. It provides districts with a self-hosted, auditable alternative to proprietary middleware like Clever and ClassLink — giving them full ownership of their student data while adhering to the OneRoster standard.

Chalk ships as a single compiled Rust binary with configurable feature flags. Schools download it, run it, and own it. No vendor lock-in, no opaque data sharing, no per-student fees for schools. An optional AI agent (powered by remix-agent-runtime) enables self-healing SIS sync and guided setup — activated only when the school provides their own LLM API key.

Revenue comes in Phase 2 through a vetted vendor marketplace, a hosted tier for schools that don't want to self-host, and paid support contracts.

---

## Problem Statement

K-12 districts face a broken middleware layer between their Student Information Systems and the ed-tech tools teachers use daily. The current landscape has three core problems:

**Vendor lock-in and opacity.** Clever and ClassLink sit between schools and vendors as proprietary gatekeepers. Districts can't audit how their data flows, can't control the terms, and can't leave without disrupting every downstream integration. Schools have no visibility into what data is shared, when, or with whom.

**Cost passed to both sides.** Clever charges vendors $2-4/student/year for roster integration, costs that get passed back to schools through higher software pricing. Districts are indirectly paying for the privilege of sharing their own data.

**Brittle integrations.** Traditional SIS connectors are hand-coded per platform. When PowerSchool changes an API or a district runs an unusual on-prem configuration, things break and someone files a support ticket. There's no intelligence in the system to adapt.

---

## Vision

Chalk unbundles the core integration layer that Clever monetizes and makes it open source. Schools get a free, self-hosted platform that syncs their SIS data, provides identity services for Chromebook login, and manages user provisioning to Google Workspace — all on infrastructure they control.

The trust equation flips: instead of "trust us with your data," it becomes "audit our code, run it yourself, control everything." Open source earns trust at the district level. Trust creates network effects. Network effects make the Phase 2 marketplace valuable.

---

## Target Users

**Primary: District IT Administrators.** These are the people who manage PowerSchool, configure Chromebooks, provision Google Workspace accounts, and currently wrangle Clever/ClassLink. They are technically competent but time-constrained, skeptical of vendors, and deeply aware of FERPA/COPPA obligations. They want tools that are transparent, reliable, and don't create more work.

**Secondary: School Technology Directors / CTOs.** Decision-makers who approve tools, manage budgets, and care about compliance. They need to justify the choice to school boards and understand the total cost of ownership.

**Phase 2: Ed-Tech Vendors.** Software companies that serve K-12 schools and need roster data and SSO integration. They're currently paying Clever for access and would welcome a lower-cost alternative backed by a growing install base.

---

## Architecture

### Design Philosophy

Chalk follows the Gitea/Pocketbase/Minio model: a single compiled binary that embeds everything a school needs. No Docker orchestration, no microservices, no external databases to manage. Download, configure, run.

### Single Binary, Feature Flags

Chalk compiles to a single Rust binary. Features are toggled via a TOML configuration file:

```toml
[chalk]
instance_name = "Springfield USD"
data_dir = "/var/lib/chalk"
public_url = "https://chalk.springfield.k12.us"  # Public-facing URL for SAML/OIDC endpoints

[chalk.database]
driver = "sqlite"  # "sqlite" (default, self-hosted) or "postgres" (hosted tier)
# SQLite path (used when driver = "sqlite")
path = "/var/lib/chalk/chalk.db"
# Postgres URL (used when driver = "postgres")
# url = "postgres://chalk:password@db.internal:5432/springfield_usd"

[sis]
enabled = true
provider = "powerschool"
base_url = "https://powerschool.springfield.k12.us"
sync_schedule = "0 2 * * *"  # 2 AM daily

[idp]
enabled = true
qr_badge_login = true
picture_passwords = true

# SAML signing certificate (generated on first run via `chalk init`)
saml_cert_path = "/var/lib/chalk/certs/saml.crt"
saml_key_path = "/var/lib/chalk/certs/saml.key"

# Google Workspace SAML integration
[idp.google]
workspace_domain = "springfield.k12.us"
# Google's SAML ACS URL and Entity ID (provided by Google during SAML setup)
google_acs_url = "https://accounts.google.com/samlrp/acs?rpid=XXXXXX"
google_entity_id = "google.com"

[google_sync]
enabled = true
provision_users = true
manage_ous = true
suspend_inactive = true
sync_schedule = "0 3 * * *"  # 3 AM daily, after SIS sync

# Service account for Admin SDK (domain-wide delegation)
service_account_key_path = "/var/lib/chalk/google-sa-key.json"
admin_email = "chalk-admin@springfield.k12.us"  # Admin user to impersonate
workspace_domain = "springfield.k12.us"

# OU mapping rules
[google_sync.ou_mapping]
students = "/Students/{school}/{grade}"
teachers = "/Staff/{school}/Teachers"
staff = "/Staff/{school}/Other"

[agent]
enabled = false
provider = "anthropic"  # or openai, local, etc.
api_key = ""

[chalk.telemetry]
enabled = false  # Opt-in only, disabled by default

[marketplace]
enabled = false
api_endpoint = "https://api.usechalk.com"
instance_id = ""
api_key = ""
```

### Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Language | Rust | Single binary, performance, safety, memory guarantees |
| Database | SQLite (self-hosted), PostgreSQL (hosted) | SQLite: zero infrastructure, embedded, perfect for single-district. PostgreSQL: concurrency, replication, and operational tooling for multi-tenant hosted tier. |
| Web Console | Embedded (served from binary) | No separate frontend deployment |
| Agent Runtime | remix-agent-runtime | Owned infrastructure, LLM-provider agnostic |
| Data Standard | OneRoster 1.1/1.2 | Industry standard, Clever/ClassLink compatible |
| Auth Protocols | SAML 2.0, OIDC | Required for ChromeOS IDP and vendor SSO |

### Monorepo Structure

```
chalk/
├── crates/
│   ├── core/           # SIS engine, OneRoster schema, data normalization
│   ├── idp/            # Identity provider, SAML/OIDC, badge login
│   ├── google-sync/    # Google Workspace user provisioning, OU management
│   ├── console/        # Embedded web admin UI
│   ├── agent/          # Agent skills, sync script generation, recovery
│   ├── marketplace/    # Client-side marketplace integration (Phase 2)
│   └── cli/            # CLI interface, config management
├── skills/             # Agent skill packs per SIS
│   ├── powerschool/
│   ├── infinite-campus/
│   └── skyward/
├── scripts/            # Generated and template sync scripts
├── migrations/         # Database schema migrations (SQLite + Postgres)
├── docs/               # Documentation
├── build/              # Build scripts, release automation
├── Cargo.toml          # Workspace root
└── README.md
```

Each directory under `crates/` is a Rust crate within a Cargo workspace. `cargo build --release` produces one binary.

### Data Flow

**SIS Sync (self-hosted):**

```
PowerSchool API → Chalk Binary → Database (SQLite or Postgres)
                       ↓
              OneRoster normalized data
                       ↓
              Google Workspace sync
```

**Marketplace Vendor Connection (Phase 2, self-hosted):**

```
School Admin approves vendor in Chalk Console
              ↓
Chalk Binary registers approval with Marketplace API
              ↓
Vendor connects directly to school's Chalk instance
              ↓
Scoped OneRoster data flows school → vendor (peer-to-peer)
              ↓
Marketplace API meters the connection (never touches PII)
```

This is a critical architectural decision: for self-hosted schools, student data never touches Chalk's servers. The marketplace API brokers authorization and discovery only. Actual roster data flows directly between the school's Chalk instance and the vendor's system. This dramatically simplifies FERPA compliance and is a major trust differentiator.

For hosted schools (Phase 2), Chalk operates as a data processor with appropriate data processing agreements in place.

---

## Phase 1 Features

Phase 1 is the open-source product. It earns trust, builds the install base, and proves the platform works. No marketplace, no billing, no hosted tier.

### F1: SIS Connectors

**Supported Systems (v1):**

| SIS | US K-12 Market Share | Priority |
|-----|---------------------|----------|
| PowerSchool | ~35% | P0 |
| Infinite Campus | ~20% | P0 |
| Skyward | ~10-15% | P0 |

These three connectors cover approximately 65-70% of US K-12 districts.

**Phase 2 connector candidates:** Aeries (California-heavy), Synergy/Edupoint, FACTS/RenWeb.

**How sync works:**

1. During initial setup, the admin configures their SIS provider and credentials in the Chalk console or config file.
2. If an agent API key is provided, the agent reads the SIS skill pack (documentation, API specs, known edge cases), examines the school's specific configuration, and generates a deterministic sync script tailored to that environment.
3. If no agent API key is provided, Chalk uses a pre-built default sync script for that SIS provider. This works for standard configurations.
4. The sync script runs on a configurable cron schedule. Each run pulls data from the SIS, normalizes it to the OneRoster schema, and writes it to the local database.
5. If a sync fails and an agent is available, the agent diagnoses the failure, examines what changed (API response differences, schema drift, auth errors), and rebuilds the sync script. The failure and resolution are logged for the admin.
6. If a sync fails and no agent is available, the failure is logged with diagnostic information and the admin is notified.

**Data normalized to OneRoster schema:**
- Users (students, teachers, staff)
- Orgs (schools, districts)
- Courses and classes
- Enrollments
- Academic sessions (terms, grading periods)
- Demographics (scoped, privacy-controlled)

### F2: Identity Provider (IDP)

Chalk acts as a SAML 2.0 and OIDC identity provider that integrates with Google Workspace and ChromeOS.

**Authentication methods:**
- Username/password (standard)
- QR code badge login (student holds a printed QR code badge up to the Chromebook camera — no special hardware required, just the built-in camera)
- Picture passwords (grid of images for pre-literate students)
- Google Workspace SSO passthrough

**ChromeOS integration:**
Google Workspace admins configure Chalk as a third-party SAML IDP. Students authenticate through Chalk on their Chromebook login screen. Chalk verifies identity against the local roster database and issues the SAML assertion to Google. The student lands on their Chromebook with the correct profile, apps, and bookmarks provisioned.

**Agent-assisted IDP setup:**
If an agent API key is available, Chalk offers a guided setup flow. The agent walks the admin through Google Workspace SAML configuration, generates the correct metadata XML, and validates the integration with a test authentication. Without the agent, the admin follows manual documentation.

### F3: Google Workspace Sync

Chalk syncs roster data to Google Workspace to automate user lifecycle management.

**Capabilities:**
- Create Google Workspace accounts for new students and staff from SIS data
- Suspend accounts for students/staff who leave or are removed from the SIS
- Manage Organizational Units (OUs) based on school, grade, role
- Assign Google Workspace licenses based on role
- Sync student and staff contact information
- Configurable sync rules (e.g., "only provision students in grades 6-12", "place new teachers in the Staff OU")

**Sync behavior:**
- Runs after SIS sync completes (chained schedule)
- Delta-only sync: Chalk diffs the current roster against the last known state pushed to Google and builds a minimal changeset (creates, suspensions, OU moves, field updates). Only changes are pushed, never a full sync.
- Changes are pushed via the Google Admin SDK batch API (up to 1,000 operations per request), eliminating rate limit concerns. A typical daily sync for a 50K-student district produces 20-50 changes — a single batch request. Even start-of-year mass provisioning fits within 5-10 batch calls.
- Dry-run mode available for preview before applying changes
- Full audit log of all provisioning actions
- Conflict detection (e.g., username collision, existing account with matching email)

### F4: Admin Console

An embedded web UI served directly from the Chalk binary on a configurable port.

**Dashboard:**
- Sync status (last run, next run, success/failure)
- User counts by role (students, teachers, staff)
- Recent activity log
- System health (database size, agent status)

**SIS Management:**
- Configure SIS provider and credentials
- Trigger manual sync
- View sync history and logs
- Preview data before committing
- View/edit OneRoster normalized data

**Identity Management:**
- User directory (search, filter by school/grade/role)
- Authentication method configuration
- QR code badge generation and bulk printing interface
- SAML/OIDC metadata and configuration
- Test authentication flow

**Google Workspace:**
- Configure Google API credentials
- OU mapping rules
- Provisioning rules and filters
- Dry-run preview
- Audit log of all changes pushed to Google

**System Settings:**
- Chalk configuration editor
- Agent API key management
- Backup and restore
- Update notifications

### F5: Agent System (Optional)

The agent is powered by remix-agent-runtime and is entirely optional. Chalk works fully without it. When enabled via an LLM API key, it unlocks three capabilities:

**Agent-Assisted Setup:**
The agent reads the appropriate SIS skill pack and guides the admin through initial configuration. It can inspect the SIS environment, suggest optimal sync settings, and generate the initial sync script. It also assists with IDP configuration by generating SAML metadata and walking through Google Workspace setup.

**Sync Script Generation:**
Rather than using a one-size-fits-all connector, the agent generates a sync script tailored to the school's specific SIS configuration. This handles edge cases like custom fields, non-standard API versions, and unusual data structures.

**Self-Healing Sync:**
When a scheduled sync fails, the agent activates automatically. It examines the error, compares the current SIS response to what the script expects, identifies what changed, and generates a fixed script. The resolution is logged with a full explanation. Over time, the agent's fixes across the install base inform improvements to the default scripts, making the non-agent experience better for everyone.

**LLM Provider Agnostic:**
The agent works with any LLM provider supported by remix-agent-runtime. Schools configure their preferred provider and API key. The agent never sends student PII to the LLM — it sends schema information, error messages, and API documentation only.

### F6: Migration Tooling

To accelerate adoption, Chalk includes migration paths from existing middleware.

**Clever Migration:**
- Import Clever application configurations
- Map Clever roster schemas to Chalk's OneRoster data
- Recreate SSO connections for supported vendors
- Guide admin through cutover steps

**ClassLink Migration:**
- Import ClassLink roster configurations
- Map ClassLink data to OneRoster schema
- Recreate SSO/SAML connections
- Guided cutover workflow

Migration tooling focuses on reducing the switching cost to near zero. A district running Clever should be able to set up Chalk, import their configuration, validate the data, and cut over in a single afternoon.

### F8: Telemetry (Opt-In)

Chalk includes an optional, anonymous telemetry system. It is **disabled by default** and must be explicitly enabled by the admin.

```toml
[chalk.telemetry]
enabled = false  # Must be explicitly set to true
```

**When enabled, telemetry reports:**
- Binary version
- Enabled feature flags (SIS, IDP, Google Sync, Agent)
- SIS provider type (e.g., "powerschool" — not the school's URL)
- Student count range (e.g., "1K-5K" — not exact numbers)
- Sync success/failure rates
- Database driver in use

**Telemetry never reports:**
- School name, district name, or any identifying information
- Student or staff PII
- SIS credentials or API keys
- IP addresses (stripped at collection)

Telemetry data helps the Chalk team prioritize SIS connectors, identify common failure patterns, and understand adoption. It is not required for any functionality.

### F9: Marketplace Pre-Registration

The admin console includes a "Marketplace" button in the navigation from day one. In Phase 1, this leads to a "Coming Soon" page that explains the upcoming vendor marketplace and offers a registration form for early access.

**The page includes:**
- Brief overview of what the marketplace will offer (vetted vendor connections, SSO, rostering)
- A registration form: school name, district, contact email, student count, and which vendors they'd most like to connect with
- Clear messaging: "Chalk is fully functional without the marketplace. This is optional."

**Strategic purpose:**
- Builds a waitlist of engaged districts before marketplace development begins
- Provides demand signal data for vendor recruitment ("150 districts want integration with X")
- Gives a fundraising proof point for Phase 2 product-market fit
- No friction, no nagging — schools discover it when they're ready

### F10: OneRoster Compliance

Chalk implements the OneRoster 1.1 standard (with 1.2 support planned) as both a consumer and provider.

**As a Consumer:**
- Ingests OneRoster CSV exports from any compliant SIS
- Consumes OneRoster REST API endpoints
- Provides a fallback import path for SIS platforms that support OneRoster export but don't have a dedicated Chalk connector

**As a Provider:**
- Exposes OneRoster REST API endpoints from the local Chalk instance
- Enables vendors (Phase 2) to pull roster data using the standard they already support
- Provides OneRoster CSV exports for manual data sharing

---

## Phase 2 Features (Planned)

Phase 2 introduces the monetization layer. It's built as a separate closed-source product that integrates with the open-source Chalk binary.

### Hosted Tier

For schools that don't want to manage their own infrastructure, Chalk offers a hosted version. Identical binary, managed by the Chalk team. Lightweight isolated containers per district on shared infrastructure.

**Pricing:** $500/year per district.

**Includes:** Managed hosting, automatic updates, daily backups, email support.

### Support Tier

For self-hosted schools that want guaranteed support.

**Pricing:** $4,000/year per district.

**Includes:** Dedicated Slack channel with Chalk team members, priority bug fixes, assisted setup and migration, SLA on response time (next business day).

### Vendor Marketplace

A vetted marketplace where ed-tech vendors connect with schools running Chalk.

**School experience:** Browse approved vendors, request a connection, review data sharing scope, approve with one click. Data flows directly from their Chalk instance to the vendor — no data passes through Chalk's servers (self-hosted) or is scoped and governed (hosted).

**Vendor experience:** Apply to join the marketplace, pass vetting (FERPA/COPPA compliance, data processing agreement, security review), get listed, connect with schools.

**Data governance:** Every vendor connection requires explicit school approval, a signed data processing agreement is generated for each connection, schools control exactly which data fields and which student populations are shared, all data sharing is logged and auditable, schools can revoke vendor access at any time with immediate effect.

**Pricing:**
- Vendors pay $1/student/year for roster and SSO integration
- Vendors pay a one-time $2,000 integration/onboarding fee
- Schools pay nothing for marketplace access

### Revenue Model Summary

| Revenue Stream | Price | Payer |
|---------------|-------|-------|
| Self-hosted Chalk | Free | — |
| Hosted Chalk | $500/year per district | School |
| Support contract | $4,000/year per district | School |
| Marketplace integration | $1/student/year | Vendor |
| Vendor onboarding | $2,000 one-time | Vendor |

**Illustrative revenue at modest scale (200 hosted districts, 20 vendors):**

| Stream | Calculation | Annual Revenue |
|--------|------------|---------------|
| Hosted tier | 200 districts × $500 | $100,000 |
| Support contracts | 50 districts × $4,000 | $200,000 |
| Vendor marketplace | 20 vendors × 300K avg students × $1 | $6,000,000 |
| Vendor onboarding | 20 vendors × $2,000 | $40,000 |
| **Total** | | **~$6,340,000** |

The marketplace is the primary revenue driver. Hosted and support tiers cover operational costs and build relationships.

---

## Competitive Landscape

### Clever (acquired by Kahoot, 2023)

**Strengths:** Massive install base (~65% of US K-12 districts), strong brand recognition, established vendor network, badge login widely adopted in elementary schools.

**Weaknesses:** Proprietary and opaque, vendor pricing creates friction, post-acquisition direction uncertain, districts have no data sovereignty.

**Chalk's advantage:** Open source, self-hosted, free for schools. District IT admins can audit the code and control their data. No lock-in.

### ClassLink

**Strengths:** Growing market share, strong SSO product (LaunchPad), good analytics.

**Weaknesses:** Also proprietary, similar vendor lock-in concerns, less established than Clever in rostering.

**Chalk's advantage:** Same as above, plus migration tooling to make switching easy.

### OneRoster Standard (1EdTech)

OneRoster is a standard, not a competitor. Chalk embraces it as the data interchange format. Compliance with OneRoster makes Chalk interoperable with the existing ecosystem and lowers switching costs from Clever/ClassLink, which both support OneRoster.

### Why Open Source Wins

District IT administrators are a community that talks to each other — through state technology conferences, K-12 IT Slack groups, and peer networks. Trust spreads through word of mouth. An open-source tool that a few districts validate and vouch for can spread rapidly through these networks in a way that a new proprietary vendor cannot. The open-source model turns early adopters into evangelists.

---

## Technical Considerations

### Security

- Signed release binaries for every platform (Linux, macOS, Windows)
- Vulnerability disclosure process (security@usechalk.com)
- Third-party security audit before v1.0 GA release
- All auth tokens encrypted at rest in the database
- HTTPS enforced for all web console and API traffic
- Role-based access control in the admin console
- Full audit log of all administrative actions

### Privacy and Compliance

- FERPA: Chalk is a "school official" tool under FERPA's school official exception when self-hosted. For hosted instances, a data processing agreement is provided.
- COPPA: Chalk does not collect data from children directly. It processes data that the school already holds in their SIS. For marketplace connections (Phase 2), vendor COPPA compliance is part of the vetting process.
- State privacy laws: Chalk's architecture (self-hosted, school-controlled) inherently complies with state student privacy laws that require schools to maintain control of student data.

### Offline and Air-Gapped Support

Chalk's core features (SIS sync to local database, IDP, Google Workspace sync) work on any network that can reach the SIS and Google APIs. No internet connectivity to Chalk's servers is required for self-hosted instances unless marketplace features are enabled. For highly restricted networks, Chalk supports SIS sync via OneRoster CSV import as a manual fallback.

### Performance Targets

- Sync 50,000 students in under 5 minutes (limited by SIS API rate limits, not Chalk)
- IDP authentication response in under 200ms
- SQLite handles up to 500,000 student records without performance degradation (self-hosted). Postgres scales beyond that for hosted tier.
- Binary size under 50MB
- Memory usage under 256MB for a typical district

### Update Strategy

- Self-hosted instances: `chalk update` command pulls the latest binary from GitHub releases and replaces the running version. Schools can run this manually or set it on a monthly cron for automatic updates.
- Hosted instances: automatic rolling updates managed by Chalk team
- No breaking configuration changes without a migration path
- Semantic versioning (major.minor.patch)
- Release notes surfaced in the admin console after an update

---

## Go-to-Market Strategy

### Phase 1 Launch

**Target:** 10-20 pilot districts for beta testing, focusing on districts that are already frustrated with Clever/ClassLink or are on PowerSchool, Infinite Campus, or Skyward.

**Channels:**
- K-12 IT community channels (K12SysAdmin subreddit, state tech director associations, ISTE)
- Direct outreach to district IT contacts from AdminRemix's existing network
- GitHub presence and developer community building
- Conference presentations at state ed-tech conferences

**Success metrics:**
- 20 districts running Chalk in production within 6 months of v1.0
- 100 GitHub stars within 3 months
- 3 community-contributed SIS connectors within 12 months
- Zero critical security issues in the first 6 months

### Phase 2 Launch

**Target:** Scale to 200+ districts, launch marketplace with 10-20 initial vendors.

**Vendor recruitment:** Target mid-size ed-tech vendors who are paying significant Clever fees and would benefit from a lower-cost alternative with a growing install base.

---

## Open Source Strategy

### License

AGPLv3. This is a deliberate structural decision. Under AGPL, anyone who forks Chalk and offers it as a hosted service must open-source their entire modified version, including any proprietary additions. This effectively prevents the "AWS problem" — where a cloud provider takes open-source code and builds a competing managed service without contributing back. Companies like MongoDB and Elastic learned this lesson the hard way by starting with permissive licenses and having to relicense retroactively. Chalk avoids this by starting with AGPL from day one. The closed-source marketplace is a separate product, not a derivative work of the AGPL codebase, and is not subject to the open-source license.

### Community

- GitHub Discussions for questions and proposals
- Contributing guide with clear guidelines for PRs
- Code of conduct
- Benevolent dictator governance model initially, evolving as community grows
- Public roadmap maintained in GitHub Projects

### Contributor Experience

- `cargo build --release` produces a working binary from a fresh clone
- Comprehensive developer documentation
- Integration test suite that runs against mock SIS environments
- Clear crate boundaries so contributors can work on IDP without understanding SIS internals

---

## Development Phases and Milestones

### Phase 1a: Foundation (Months 1-3)
- Rust monorepo scaffolding and build pipeline
- Database schema and migration framework (SQLite default, Postgres support)
- OneRoster data model implementation
- PowerSchool connector (default sync script, no agent)
- Basic CLI: `chalk init`, `chalk sync`, `chalk status`, `chalk update`
- CI/CD pipeline with signed releases

### Phase 1b: Core Features (Months 3-6)
- Infinite Campus connector
- Skyward connector
- Embedded admin console (web UI)
- Agent integration via remix-agent-runtime
- Agent-assisted sync script generation and self-healing
- SIS skill packs for all three providers

### Phase 1c: Identity and Provisioning (Months 6-9)
- SAML 2.0 / OIDC identity provider
- Badge login and picture password flows
- Google Workspace sync (user provisioning, OUs)
- Agent-assisted IDP setup flow
- ChromeOS integration testing and documentation

### Phase 1d: Migration and Polish (Months 9-12)
- Clever migration tooling
- ClassLink migration tooling
- OneRoster CSV import/export
- Security audit
- Documentation and contributor guides
- v1.0 GA release

### Phase 2: Monetization (Months 12-18)
- Hosted tier infrastructure and onboarding
- Support tier with Slack integration
- Marketplace API (closed source)
- Vendor onboarding workflow
- Data governance and consent engine
- Billing and metering

---

## Open Questions

1. **Brand finalization:** Working name is Chalk, domain target is usechalk.com. Final brand, logo, and visual identity needed.
2. **Phase 2 SIS connectors:** Aeries and Synergy/Edupoint are candidates. Prioritize based on pilot district feedback.
3. **Agent cost modeling:** What's the typical LLM API cost per sync repair? Need to estimate so schools can budget for BYOK agent usage.
4. **Start-of-year provisioning:** Need to validate the batch Admin SDK approach handles mass provisioning (thousands of new accounts) gracefully during back-to-school season, including username generation rules and conflict resolution.

---

## Appendix: Competitive Pricing Comparison

| | Clever | ClassLink | Chalk (self-hosted) | Chalk (hosted) |
|---|---|---|---|---|
| Cost to school | "Free" (vendor-subsidized) | Per-student licensing | Free | $500/year |
| Cost to vendor | $2-4/student/year | Varies | $1/student/year (Phase 2) | $1/student/year (Phase 2) |
| Data sovereignty | No — data flows through Clever | No — data flows through ClassLink | Yes — fully self-hosted | Partial — Chalk hosts |
| Open source | No | No | Yes | Yes (same binary) |
| Code auditable | No | No | Yes | Yes |
| Self-hostable | No | No | Yes | N/A |
| SIS support | Broad | Broad | PowerSchool, IC, Skyward (v1) | Same |
| OneRoster compliant | Yes | Yes | Yes | Yes |