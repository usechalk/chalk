-- Canned responses (reply macros) for the help desk (WS-11).
--
-- A technician answers the same handful of questions all day — "have you tried
-- a hard reset", "your device is ready for pickup". A saved response is a title
-- and a body the reply box can be filled from, so the wording stays consistent
-- and the typing stops. District-wide, not per-technician: the value is a shared
-- voice, and a per-user library is a later refinement if anyone asks.
--
-- Re-runnable via IF NOT EXISTS. No semicolons inside comments — the SQLite
-- migration runner splits naively on the statement separator.

CREATE TABLE IF NOT EXISTS canned_responses (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
