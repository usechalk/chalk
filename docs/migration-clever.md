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

After importing data:

1. Verify user counts match between Clever and Chalk
2. Test SAML SSO with a pilot group
3. Update DNS or redirect URLs as needed
4. Disable Clever sync
5. Enable Chalk SIS sync
6. Monitor for 24-48 hours

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
