-- Ingestion audit: occurred_at is asserted by the reporting client and is
-- therefore attacker-influenced. received_at is the server clock, so a
-- backdated or post-dated event can be detected after the fact.

ALTER TABLE events
    ADD COLUMN received_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX events_received_at_idx ON events (received_at DESC);

-- Keyset pagination orders by (occurred_at DESC, id DESC); the existing
-- single-column index is a strict prefix of this one, so it would only add
-- write cost on the highest-volume table.
CREATE INDEX events_keyset_idx ON events (occurred_at DESC, id DESC);
DROP INDEX events_occurred_at_idx;
