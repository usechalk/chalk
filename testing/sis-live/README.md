# Live SIS sync (PowerSchool / Skyward / Infinite Campus)

**No docker container. No `run.sh`.** Each of these connectors talks to a
real SIS instance and we don't have a sandboxed one we can stand up.

This README documents how to test for real, when you have credentials.

## Prerequisites by vendor

### PowerSchool

- A district with the **Chalk plugin** installed in PowerSchool's plugin
  framework (or any OneRoster-1.1-compatible plugin with the standard
  endpoints under `/ws/v1/...`).
- OAuth credentials: `client_id`, `client_secret`. PowerSchool surfaces
  these in the plugin's configuration page after you upload the plugin
  XML.
- The plugin's base URL (typically `https://<district>.powerschool.com`).
- A small test cohort — ask the district admin to scope the plugin to
  one school or one grade so you don't pull a 50 000-row roster on every
  test.

### Skyward

- District-issued **API client_id + client_secret** (Skyward calls these
  "Vendor Credentials" — they're issued by the district's Skyward admin
  through the District Configuration → Software Authorization page).
- The token URL — district-specific, looks like
  `https://skyward.iscorp.com/scripts/wsisaapi.dll/<DISTRICT>/oauth2/token`.
- The base URL for the OneRoster endpoint (also district-specific).
- `[sis] provider = "skyward"` plus `token_url = ...` in chalk.toml
  (Skyward needs explicit token URL — PowerSchool auto-derives from base).

### Infinite Campus

- District-issued **OAuth credentials** + token URL. Infinite Campus
  exposes OAuth via an admin-installed module; the district's IC admin
  enables the OneRoster API and generates client credentials.
- Base URL of the IC instance (`https://<district>.infinitecampus.org`).
- `[sis] provider = "infinite_campus"` plus `token_url = ...` in
  chalk.toml.

## How to run

Once credentials are in `chalk.toml`:

```bash
chalk --config /path/to/chalk.toml sync          # one-shot sync
chalk --config /path/to/chalk.toml status        # see counts
```

## What to look for

- `chalk sync` exits 0.
- Counts in `chalk status` match what the SIS shows for the same scope.
- Spot-check a few users via the admin console at `/users`.
- Trigger a second sync — incremental should be a no-op
  (`Users updated: 0`) if nothing changed in the SIS between runs.

## What we can fake locally instead

The OneRoster CSV scenario at `../oneroster-csv/` gives you the same
roster shape (and exercises the same `SyncEngine.run()` path) without
needing real SIS credentials. It's the closest local proxy.
