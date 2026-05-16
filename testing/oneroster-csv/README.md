# OneRoster CSV import scenario

Synthetic OneRoster 1.1 CSV bundle + parser-correctness test for the
`chalk_core::oneroster_csv::read_oneroster_csv` function.

## What this proves

✅ The `OneRosterCsvConnector` (in `crates/core/src/connectors/oneroster_csv/`)
   reads a real-world OneRoster 1.1 bundle and exposes it through the
   standard `SisConnector` trait, so `chalk sync` can use a CSV directory
   as a first-class SIS source.

✅ End-to-end through the production sync path: connector → `SyncEngine.run()`
   → repo persists into SQLite → `chalk status` confirms the counts.

✅ `provider = "oneroster_csv"` is accepted by the config validator and
   wires up correctly in the connector factory.

## What this does NOT prove

⚠️ That this works inside a hosted multi-tenant runtime. `chalk-hosted`
   doesn't currently invoke the connector factory from `/sync/trigger`
   — that handler still records a stub completed run without actually
   syncing. (Tracked as a separate bug.)

## Run

```bash
./run.sh
```

The script:
1. Builds `chalk` (release; cargo cache reused after first run).
2. Generates a temp `chalk.toml` with `provider = "oneroster_csv"` and
   `csv_dir` pointed at `data/`.
3. Runs `chalk sync` — invokes the new connector against the bundle.
4. Asserts the printed counts match the CSV contents.
5. Runs `chalk status` and confirms the user count is in the DB.
6. Cleans up the temp dir.

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
