# Migration from Clever

Chalk supports migrating roster data and application configurations from Clever.

## Prerequisites

1. Export your data from Clever in OneRoster CSV format
2. Export your application configurations (optional)
3. Have Chalk initialized (`chalk init`)

## Export from Clever

1. Log into your Clever dashboard
2. Navigate to **Data** > **Export**
3. Select **OneRoster CSV** format
4. Download the export ZIP file
5. Extract to a local directory

The export directory should contain:
```
clever-export/
├── users.csv
├── orgs.csv
├── courses.csv
├── classes.csv
├── enrollments.csv
├── academicSessions.csv
├── demographics.csv
└── apps.json (optional)
```

## CLI Migration

```bash
chalk migrate --from clever --path /path/to/clever-export --config chalk.toml
```

This will:
1. Parse the Clever export directory
2. Display a summary of data to be imported
3. Import roster data into the Chalk database
4. Display cutover steps

## Console Migration

1. Navigate to **Migration** in the admin console
2. Select **Clever**
3. Enter the path to your Clever export directory
4. Review the parsed data summary
5. Follow the cutover checklist

## Cutover Steps

Chalk supports a gradual, low-risk migration from Clever. Rather than a weekend
big-bang switchover, migrate one application at a time so that every step is
independently rollback-able.

### Phase 1: Parallel Operation

1. Install Chalk alongside your existing Clever deployment
2. Import your Clever data using the CLI or console migration above
3. Verify record counts match between Clever and Chalk (users, orgs, classes, enrollments)
4. Enable Chalk SIS sync and confirm ongoing data stays in sync

### Phase 2: First App Migration

1. Pick one low-risk application (e.g. a non-critical internal tool)
2. Change that application's OAuth base URL from Clever to your Chalk instance
3. Verify SSO login works end-to-end for a pilot group of users
4. Monitor logs for authentication errors over 24-48 hours

### Phase 3: Gradual Rollout

1. Migrate remaining applications one-by-one, starting with the lowest risk
2. For each app, update its OAuth base URL to point at Chalk
3. Verify SSO and roster data after each change
4. If any app has issues, roll back by reverting its OAuth URL to Clever

### Phase 4: Decommission

1. After all applications have been stable on Chalk for 2+ weeks, disable Clever sync
2. Decommission your Clever instance
3. Remove any remaining Clever-specific DNS records or redirect URLs

## Data Mapping

| Clever Entity | Chalk Entity |
|---------------|--------------|
| Students | Users (role: student) |
| Teachers | Users (role: teacher) |
| Schools | Orgs (type: school) |
| Districts | Orgs (type: district) |
| Sections | Classes |
| Courses | Courses |
| Enrollments | Enrollments |
| Terms | AcademicSessions |
