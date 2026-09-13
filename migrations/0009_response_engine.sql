-- Automated response. The responses table already exists from migration 0003
-- with (incident_id, action, result, occurred_at) and has never been written to
-- by application code; this extends it rather than building a parallel audit
-- system alongside it.

-- The existing vocabulary already covers executed (succeeded) and failed. Only
-- the repeat case has no value: an action that was not re-executed because it
-- was already in effect. 'skipped' would lose that distinction.
ALTER TYPE response_result ADD VALUE IF NOT EXISTS 'already_applied';

ALTER TABLE responses
    -- The threat whose arrival triggered this plan, when there was one. The
    -- incident is the subject of the response; the threat is the trigger.
    ADD COLUMN threat_id bigint REFERENCES threats (id) ON DELETE SET NULL,
    ADD COLUMN policy    text,
    ADD COLUMN reason    text,
    -- Which entities the action actually touched, so the record answers what
    -- was done, why, and to what.
    ADD COLUMN evidence  jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Who ran it: the engine itself, or the credential that asked.
    ADD COLUMN actor     text,

    ADD CONSTRAINT responses_evidence_is_object CHECK (jsonb_typeof(evidence) = 'object');

-- The idempotency key. One logical action per action type per incident,
-- enforced by PostgreSQL rather than by an exists() check that two concurrent
-- workers could both pass. Re-processing revises a row instead of adding one.
ALTER TABLE responses
    ADD CONSTRAINT responses_incident_action_key UNIQUE (incident_id, action);

-- Containment state. Each lives on the entity it describes so there is exactly
-- one authoritative answer to "is this contained?"; the responses rows carry
-- the why and the when.
ALTER TABLE users
    ADD COLUMN contained boolean NOT NULL DEFAULT false;

ALTER TABLE devices
    ADD COLUMN isolated boolean NOT NULL DEFAULT false;

-- No entity table exists for addresses, so containment needs its own. The block
-- outlives its incident: ON DELETE SET NULL keeps the address contained even if
-- the incident is removed, which fails closed.
CREATE TABLE blocked_sources (
    source_ip   inet        PRIMARY KEY,
    incident_id bigint      REFERENCES incidents (id) ON DELETE SET NULL,
    reason      text        NOT NULL,
    blocked_at  timestamptz NOT NULL DEFAULT now()
);

-- Containment lookups are per-entity: users and devices by primary key, and
-- blocked_sources by its own primary key. No additional index is warranted.
