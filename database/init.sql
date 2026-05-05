-- CloudTrap Database Schema
-- This file runs automatically when the PostgreSQL container starts for the first time.

CREATE TABLE IF NOT EXISTS events (
    id             SERIAL PRIMARY KEY,
    timestamp      TIMESTAMPTZ,
    service        TEXT,
    source_ip      TEXT,
    method         TEXT,
    path           TEXT,
    action         TEXT,
    command        TEXT,
    attack_type    TEXT,
    severity       TEXT,
    cloud_provider TEXT,
    raw            JSONB,
    inserted_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attacker_profiles (
    source_ip    TEXT PRIMARY KEY,
    event_count  INT DEFAULT 0,
    threat_score INT DEFAULT 0,
    top_severity TEXT,
    attack_types TEXT[],
    first_seen   TIMESTAMPTZ,
    last_seen    TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_source_ip   ON events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity    ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_attack_type ON events (attack_type);