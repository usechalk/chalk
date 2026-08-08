-- Resolution SLA (WS-11). See the SQLite copy for rationale: the second SLA
-- the PRD promised, computed from priority like the first-response target.

ALTER TABLE tickets ADD COLUMN IF NOT EXISTS resolution_due_at TIMESTAMPTZ;
