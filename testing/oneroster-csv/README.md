# OneRoster CSV import scenario

Synthetic OneRoster 1.1 CSV bundle + parser-correctness test for the
`chalk_core::oneroster_csv::read_oneroster_csv` function.

## What this proves

✅ `read_oneroster_csv(dir)` parses a real-world OneRoster 1.1 bundle into
   a fully-populated `SyncPayload` (orgs, users, classes, enrollments).

✅ The reader/writer roundtrip is loss-free — a payload written and re-read
   matches the original by record count + key fields.

## What this does NOT prove

⚠️ That CSV files **work as a SIS sync source in production.** As of
   2026-05-15 there is no `CsvConnector` implementing `SisConnector` —
   only PowerSchool, Skyward, and Infinite Campus connectors are wired.
   The parser exists; the connector doesn't.

   **Follow-up:** add `crates/core/src/connectors/oneroster_csv/mod.rs`
   implementing `SisConnector` with a `path: PathBuf` config, and
   register `provider = "oneroster_csv"` in the connector factory.
   Once wired, this scenario becomes testable end-to-end via
   `/sync/trigger`.

⚠️ That QR badge / picture password login work against synced students.
   Same blocker — without a CsvConnector the synthetic users never reach
   the tenant DB through the production sync path.

## Run

```bash
./run.sh
```

The script invokes `cargo test -p chalk-core oneroster_csv::reader` plus
the bundled `parser-test/` integration test that loads the synthetic
bundle from `data/`, asserts the parsed counts, and runs a roundtrip.

## Layout

```
oneroster-csv/
├── README.md
├── data/                 # synthetic OneRoster 1.1 bundle
│   ├── manifest.csv
│   ├── orgs.csv
│   ├── academicSessions.csv
│   ├── users.csv
│   ├── courses.csv
│   ├── classes.csv
│   └── enrollments.csv
└── run.sh                # cargo test + custom assertions
```
