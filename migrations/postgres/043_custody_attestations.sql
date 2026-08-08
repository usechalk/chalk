-- Custody self-attestation campaigns (SS-2)
-- One row per ask: "do you still have this device, and what shape is it in"
-- The token is the whole credential for the public answer link, like CSAT

CREATE TABLE IF NOT EXISTS custody_attestations (
    id TEXT PRIMARY KEY,
    custody_id TEXT NOT NULL REFERENCES custody_records(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    requested_at TIMESTAMPTZ NOT NULL,
    responded_at TIMESTAMPTZ,
    has_item BOOLEAN,
    condition TEXT,
    note TEXT,
    actor TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attest_custody ON custody_attestations(custody_id);
CREATE INDEX IF NOT EXISTS idx_attest_open ON custody_attestations(responded_at);
