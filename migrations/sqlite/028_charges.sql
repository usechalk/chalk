-- Fees and fines assessed against a device or the student who holds it (F3).
--
-- The 1:1 device programs every district runs need to record what a family
-- owes: a cracked-screen repair, a lost-charger fine, a replacement for a
-- device never returned. This is *assessment and record only* — there is no
-- payment row, no gateway, no card handling (decision D14/D22). "Settled" means
-- recorded-as-paid-somewhere-else. Collection stays in the district's existing
-- system, and the published "Chalk does not take payment-card details" claim
-- stays true.
--
-- Amounts are integer cents (`amount_cents`), matching `assets.purchase_cost_cents`
-- — money is never a float here.
--
-- Re-runnable per the SQLITE_MIGRATIONS contract: CREATE ... IF NOT EXISTS only,
-- no semicolons inside comments.

CREATE TABLE IF NOT EXISTS charges (
    id TEXT PRIMARY KEY,
    -- The device the charge is about. Nullable so a general fine can exist, and
    -- ON DELETE SET NULL because a retired device must not erase the money owed.
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    -- Who owes it, from the roster the SIS already populates.
    user_sourced_id TEXT REFERENCES users(sourced_id) ON DELETE SET NULL,
    -- The repair/damage ticket that spawned it, if any.
    ticket_id TEXT REFERENCES tickets(id) ON DELETE SET NULL,
    -- repair_fee | damage_fine | loss_replacement | other
    kind TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    -- assessed | waived | settled_externally
    status TEXT NOT NULL DEFAULT 'assessed',
    -- Whether a protection plan reduced or removed this charge. Recorded for the
    -- audit, so "why is this $0" has an answer.
    insurance_applied INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    -- Who assessed it (a console Actor's audit string).
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_charges_user ON charges (user_sourced_id);
CREATE INDEX IF NOT EXISTS idx_charges_asset ON charges (asset_id);
CREATE INDEX IF NOT EXISTS idx_charges_status ON charges (status);

-- Whether the student who holds a device has a protection plan, so fee rules
-- can read it. A plain flag for v1 — the tiered-plan model can come when a
-- district asks for one.
ALTER TABLE assets ADD COLUMN protection_plan INTEGER NOT NULL DEFAULT 0;
