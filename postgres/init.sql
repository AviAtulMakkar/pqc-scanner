-- =============================================================
-- PQC CBOM Scanner — PostgreSQL initialisation script
-- Runs once automatically on first `docker compose up`
-- (Postgres mounts /docker-entrypoint-initdb.d/*.sql on init)
-- =============================================================

-- ── ENUM types ────────────────────────────────────────────────

CREATE TYPE scanstatus  AS ENUM ('queued', 'running', 'complete', 'error');
CREATE TYPE jobtype     AS ENUM ('scheduled', 'frequency');
CREATE TYPE jobstatus   AS ENUM ('active', 'cancelled', 'completed');
CREATE TYPE reportformat AS ENUM ('html', 'json', 'cbom', 'pdf');

-- ── users ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id               VARCHAR PRIMARY KEY,
    email            VARCHAR NOT NULL UNIQUE,
    username         VARCHAR NOT NULL UNIQUE,
    hashed_password  VARCHAR NOT NULL,
    full_name        VARCHAR NOT NULL DEFAULT '',
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,
    is_admin         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_users_email    ON users (email);
CREATE INDEX IF NOT EXISTS ix_users_username ON users (username);

-- ── scans ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scans (
    id           VARCHAR PRIMARY KEY,
    user_id      VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain       VARCHAR NOT NULL,
    status       scanstatus NOT NULL DEFAULT 'queued',
    progress     INTEGER NOT NULL DEFAULT 0,
    message      TEXT NOT NULL DEFAULT '',
    ports_config VARCHAR NOT NULL DEFAULT 'top',
    threads      INTEGER NOT NULL DEFAULT 100,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    elapsed      FLOAT,
    error_msg    TEXT,
    summary      JSONB NOT NULL DEFAULT '{}',
    events       JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS ix_scans_user_domain ON scans (user_id, domain);
CREATE INDEX IF NOT EXISTS ix_scans_started_at  ON scans (started_at);

-- ── scan_hosts ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scan_hosts (
    id         VARCHAR PRIMARY KEY,
    scan_id    VARCHAR NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    hostname   VARCHAR NOT NULL,
    ip         VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data       JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS ix_scan_hosts_scan_id ON scan_hosts (scan_id);

-- ── scheduled_jobs ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id             VARCHAR PRIMARY KEY,
    user_id        VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label          VARCHAR NOT NULL DEFAULT '',
    job_type       jobtype NOT NULL,
    status         jobstatus NOT NULL DEFAULT 'active',
    domain         VARCHAR NOT NULL,
    ports_config   VARCHAR NOT NULL DEFAULT 'top',
    report_format  reportformat NOT NULL DEFAULT 'html',
    email_to       JSONB NOT NULL DEFAULT '[]',
    send_email     BOOLEAN NOT NULL DEFAULT FALSE,
    run_at         TIMESTAMPTZ,
    interval_value INTEGER,
    interval_unit  VARCHAR,
    max_runs       INTEGER,
    run_count      INTEGER NOT NULL DEFAULT 0,
    last_run_at    TIMESTAMPTZ,
    next_run_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── reports ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS reports (
    id           VARCHAR PRIMARY KEY,
    user_id      VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_id      VARCHAR REFERENCES scans(id) ON DELETE SET NULL,
    report_type  VARCHAR NOT NULL DEFAULT 'on-demand',
    format       reportformat NOT NULL DEFAULT 'html',
    status       VARCHAR NOT NULL DEFAULT 'generating',
    file_path    VARCHAR,
    file_name    VARCHAR,
    emailed_to   JSONB NOT NULL DEFAULT '[]',
    email_status VARCHAR,
    notes        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_reports_user_id ON reports (user_id);
