-- Raw telemetry and the detections derived from it.

CREATE TYPE severity_level AS ENUM ('info', 'low', 'medium', 'high', 'critical');

CREATE TABLE events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_type  text        NOT NULL,
    -- Nullable: pre-authentication and infrastructure events have no principal.
    user_id     bigint      REFERENCES users (id) ON DELETE SET NULL,
    source_ip   inet,
    occurred_at timestamptz NOT NULL,
    metadata    jsonb       NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT events_metadata_is_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX events_occurred_at_idx      ON events (occurred_at DESC);
CREATE INDEX events_user_occurred_at_idx ON events (user_id, occurred_at DESC);
CREATE INDEX events_type_occurred_at_idx ON events (event_type, occurred_at DESC);
CREATE INDEX events_source_ip_idx        ON events (source_ip);
CREATE INDEX events_metadata_idx         ON events USING gin (metadata jsonb_path_ops);

CREATE TABLE threats (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id    bigint         NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    threat_type text           NOT NULL,
    severity    severity_level NOT NULL,
    confidence  numeric(4, 3)  NOT NULL,

    -- One detection per rule per event; re-running a rule updates in place.
    CONSTRAINT threats_event_type_key    UNIQUE (event_id, threat_type),
    CONSTRAINT threats_confidence_range  CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX threats_event_id_idx ON threats (event_id);
CREATE INDEX threats_triage_idx   ON threats (severity DESC, confidence DESC);
