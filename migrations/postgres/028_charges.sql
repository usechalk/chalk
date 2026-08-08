-- Fees and fines assessed against a device or the student who holds it (F3).
-- See the SQLite copy for the full rationale. Assessment and record only — no
-- payment rows, no gateway (D14/D22). Amounts are integer cents.

CREATE TABLE IF NOT EXISTS charges (
    id TEXT PRIMARY KEY,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    ticket_id TEXT REFERENCES tickets(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    amount_cents BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'assessed',
    insurance_applied BOOLEAN NOT NULL DEFAULT FALSE,
    reason TEXT,
    actor TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_charges_user ON charges (user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_charges_asset ON charges (asset_id);
CREATE INDEX IF NOT EXISTS idx_charges_status ON charges (status);

ALTER TABLE assets ADD COLUMN IF NOT EXISTS protection_plan BOOLEAN NOT NULL DEFAULT FALSE;
