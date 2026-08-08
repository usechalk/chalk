-- Resolution SLA (WS-11).
--
-- The ticket shipped with sla_due_at, a first-response target only. The PRD
-- promised both a first-response and a resolution SLA — this adds the second.
-- resolution_due_at is computed from the priority at creation and recomputed
-- when the priority changes, exactly like sla_due_at.
--
-- Re-runnable: ALTER ADD COLUMN raises "duplicate column" on a second run,
-- which the migration runner swallows.

ALTER TABLE tickets ADD COLUMN resolution_due_at TEXT;
