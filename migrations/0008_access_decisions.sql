-- Zero-trust access decisions. A separate table from responses: that records
-- actions taken against an incident, whereas this records an authorization
-- verdict. Conflating them would mix two different audit questions.

CREATE TYPE access_decision AS ENUM ('allow', 'step_up', 'deny');

CREATE TABLE access_decisions (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    decided_at  timestamptz     NOT NULL DEFAULT now(),

    -- Who asked. The credential is trusted to name the subject, so recording
    -- which one asked is part of the audit trail.
    api_key     text            NOT NULL,

    -- Subject context, snapshotted. The role and device trust are stored as
    -- values rather than only as references so a historical decision still
    -- explains itself after the user is re-roled, the device is re-scored, or
    -- the record is deleted.
    subject_user_id bigint      REFERENCES users (id) ON DELETE SET NULL,
    subject_username text,
    subject_role    text,
    authenticated   boolean     NOT NULL,

    device_fingerprint text,
    device_state    text        NOT NULL,
    device_trust    numeric(5, 2),

    source_ip       inet,
    resource        text        NOT NULL,
    sensitivity     text        NOT NULL,

    decision        access_decision NOT NULL,
    policy          text        NOT NULL,
    reason          text        NOT NULL,

    -- Snapshot of the threat and incident context the verdict was based on,
    -- plus the per-category factors behind it.
    factors         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    max_threat_risk integer,
    incident_id     bigint      REFERENCES incidents (id) ON DELETE SET NULL,
    incident_risk   integer,

    CONSTRAINT access_decisions_factors_is_object CHECK (jsonb_typeof(factors) = 'object'),
    CONSTRAINT access_decisions_resource_nonblank CHECK (length(btrim(resource)) > 0),
    CONSTRAINT access_decisions_threat_risk_range
        CHECK (max_threat_risk IS NULL OR (max_threat_risk >= 0 AND max_threat_risk <= 100)),
    CONSTRAINT access_decisions_incident_risk_range
        CHECK (incident_risk IS NULL OR (incident_risk >= 0 AND incident_risk <= 100))
);

-- Records are append-only by construction: nothing in the application updates
-- them, so a decision cannot be rewritten after the fact.
--
-- Only one index: the audit log is listed newest-first by id, which the primary
-- key already serves, so a second index on decided_at would never be read. This
-- one backs the per-subject audit query ("every decision made about this user").
CREATE INDEX access_decisions_subject_idx ON access_decisions (subject_user_id, id DESC);
