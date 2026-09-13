-- Incidents correlate threats; responses record what was done about them.

CREATE TYPE incident_status AS ENUM ('open', 'investigating', 'contained', 'resolved', 'false_positive');
CREATE TYPE response_result AS ENUM ('pending', 'succeeded', 'failed', 'skipped');

CREATE TABLE incidents (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title      text            NOT NULL,
    severity   severity_level  NOT NULL,
    risk_score numeric(5, 2)   NOT NULL,
    status     incident_status NOT NULL DEFAULT 'open',
    created_at timestamptz     NOT NULL DEFAULT now(),

    CONSTRAINT incidents_title_nonblank   CHECK (length(btrim(title)) > 0),
    CONSTRAINT incidents_risk_score_range CHECK (risk_score >= 0 AND risk_score <= 100)
);

CREATE INDEX incidents_queue_idx    ON incidents (status, created_at DESC);
CREATE INDEX incidents_severity_idx ON incidents (severity DESC, risk_score DESC);

-- Without this the incident tables are unreachable from the detections that
-- justify them. Nullable: a threat is correlated into an incident only once it
-- clears triage.
ALTER TABLE threats
    ADD COLUMN incident_id bigint REFERENCES incidents (id) ON DELETE SET NULL;

CREATE INDEX threats_incident_id_idx ON threats (incident_id) WHERE incident_id IS NOT NULL;

CREATE TABLE responses (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id bigint          NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    action      text            NOT NULL,
    result      response_result NOT NULL DEFAULT 'pending',
    occurred_at timestamptz     NOT NULL DEFAULT now()
);

CREATE INDEX responses_incident_idx ON responses (incident_id, occurred_at DESC);
