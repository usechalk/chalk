PRAGMA foreign_keys = ON;

-- Organizations
CREATE TABLE IF NOT EXISTS orgs (
    sourced_id TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL,
    date_last_modified TEXT NOT NULL,
    metadata TEXT,
    name TEXT NOT NULL,
    org_type TEXT NOT NULL,
    identifier TEXT,
    parent_sourced_id TEXT
);

-- Academic Sessions
CREATE TABLE IF NOT EXISTS academic_sessions (
    sourced_id TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL,
    date_last_modified TEXT NOT NULL,
    metadata TEXT,
    title TEXT NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    session_type TEXT NOT NULL,
    parent_sourced_id TEXT,
    school_year TEXT NOT NULL
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    sourced_id TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL,
    date_last_modified TEXT NOT NULL,
    metadata TEXT,
    username TEXT NOT NULL,
    enabled_user INTEGER NOT NULL DEFAULT 1,
    given_name TEXT NOT NULL,
    family_name TEXT NOT NULL,
    middle_name TEXT,
    role TEXT NOT NULL,
    identifier TEXT,
    email TEXT,
    sms TEXT,
    phone TEXT
);

-- User <-> Org junction
CREATE TABLE IF NOT EXISTS user_orgs (
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    org_sourced_id TEXT NOT NULL REFERENCES orgs(sourced_id) ON DELETE CASCADE,
    PRIMARY KEY (user_sourced_id, org_sourced_id)
);

-- User <-> Agent junction
CREATE TABLE IF NOT EXISTS user_agents (
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    agent_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    PRIMARY KEY (user_sourced_id, agent_sourced_id)
);

-- User identifiers
CREATE TABLE IF NOT EXISTS user_identifiers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    identifier TEXT NOT NULL
);

-- User grades junction
CREATE TABLE IF NOT EXISTS user_grades (
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id) ON DELETE CASCADE,
    grade TEXT NOT NULL,
    PRIMARY KEY (user_sourced_id, grade)
);

-- Courses
CREATE TABLE IF NOT EXISTS courses (
    sourced_id TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL,
    date_last_modified TEXT NOT NULL,
    metadata TEXT,
    title TEXT NOT NULL,
    school_year TEXT,
    course_code TEXT,
    org_sourced_id TEXT NOT NULL REFERENCES orgs(sourced_id)
);

-- Course grades junction
CREATE TABLE IF NOT EXISTS course_grades (
    course_sourced_id TEXT NOT NULL REFERENCES courses(sourced_id) ON DELETE CASCADE,
    grade TEXT NOT NULL,
    PRIMARY KEY (course_sourced_id, grade)
);

-- Course subjects junction
CREATE TABLE IF NOT EXISTS course_subjects (
    course_sourced_id TEXT NOT NULL REFERENCES courses(sourced_id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    PRIMARY KEY (course_sourced_id, subject)
);

-- Classes
CREATE TABLE IF NOT EXISTS classes (
    sourced_id TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL,
    date_last_modified TEXT NOT NULL,
    metadata TEXT,
    title TEXT NOT NULL,
    class_code TEXT,
    class_type TEXT NOT NULL,
    location TEXT,
    course_sourced_id TEXT NOT NULL REFERENCES courses(sourced_id),
    school_sourced_id TEXT NOT NULL REFERENCES orgs(sourced_id)
);

-- Class <-> AcademicSession junction
CREATE TABLE IF NOT EXISTS class_terms (
    class_sourced_id TEXT NOT NULL REFERENCES classes(sourced_id) ON DELETE CASCADE,
    academic_session_sourced_id TEXT NOT NULL REFERENCES academic_sessions(sourced_id) ON DELETE CASCADE,
    PRIMARY KEY (class_sourced_id, academic_session_sourced_id)
);

-- Class grades junction
CREATE TABLE IF NOT EXISTS class_grades (
    class_sourced_id TEXT NOT NULL REFERENCES classes(sourced_id) ON DELETE CASCADE,
    grade TEXT NOT NULL,
    PRIMARY KEY (class_sourced_id, grade)
);

-- Class subjects junction
CREATE TABLE IF NOT EXISTS class_subjects (
    class_sourced_id TEXT NOT NULL REFERENCES classes(sourced_id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    PRIMARY KEY (class_sourced_id, subject)
);

-- Class periods junction
CREATE TABLE IF NOT EXISTS class_periods (
    class_sourced_id TEXT NOT NULL REFERENCES classes(sourced_id) ON DELETE CASCADE,
    period TEXT NOT NULL,
    PRIMARY KEY (class_sourced_id, period)
);

-- Enrollments
CREATE TABLE IF NOT EXISTS enrollments (
    sourced_id TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL,
    date_last_modified TEXT NOT NULL,
    metadata TEXT,
    user_sourced_id TEXT NOT NULL REFERENCES users(sourced_id),
    class_sourced_id TEXT NOT NULL REFERENCES classes(sourced_id),
    school_sourced_id TEXT NOT NULL REFERENCES orgs(sourced_id),
    role TEXT NOT NULL,
    is_primary INTEGER,
    begin_date TEXT,
    end_date TEXT
);

-- Demographics (sourced_id is FK to users)
CREATE TABLE IF NOT EXISTS demographics (
    sourced_id TEXT PRIMARY KEY NOT NULL REFERENCES users(sourced_id),
    status TEXT NOT NULL,
    date_last_modified TEXT NOT NULL,
    metadata TEXT,
    birth_date TEXT,
    sex TEXT,
    american_indian_or_alaska_native INTEGER,
    asian INTEGER,
    black_or_african_american INTEGER,
    native_hawaiian_or_other_pacific_islander INTEGER,
    white INTEGER,
    demographic_race_two_or_more_races INTEGER,
    hispanic_or_latino_ethnicity INTEGER,
    country_of_birth_code TEXT,
    state_of_birth_abbreviation TEXT,
    city_of_birth TEXT,
    public_school_residence_status TEXT
);

-- Sync runs
CREATE TABLE IF NOT EXISTS sync_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error_message TEXT,
    users_synced INTEGER NOT NULL DEFAULT 0,
    orgs_synced INTEGER NOT NULL DEFAULT 0,
    courses_synced INTEGER NOT NULL DEFAULT 0,
    classes_synced INTEGER NOT NULL DEFAULT 0,
    enrollments_synced INTEGER NOT NULL DEFAULT 0
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_enrollments_user ON enrollments(user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_enrollments_class ON enrollments(class_sourced_id);
CREATE INDEX IF NOT EXISTS idx_classes_school ON classes(school_sourced_id);
CREATE INDEX IF NOT EXISTS idx_sync_runs_provider ON sync_runs(provider);
