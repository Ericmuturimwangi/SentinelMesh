-- Correlation state on incidents. title, severity, risk_score, status and
-- created_at already exist and are reused: severity holds the band of the
-- incident risk score, risk_score holds the campaign score.

ALTER TABLE incidents
    -- Campaign identity ("ip:203.0.113.44"). Used for the candidate lookup, the
    -- advisory lock, and the uniqueness guarantee below.
    ADD COLUMN correlation_key text,
    -- Whether this incident still accumulates new threats. Deliberately NOT the
    -- same as status: an incident whose correlation window has lapsed stops
    -- correlating but stays open for triage. Nothing here closes an incident.
    ADD COLUMN correlating boolean NOT NULL DEFAULT true,
    -- Which attack this campaign represents, derived from member threat types.
    ADD COLUMN classification text,
    -- Confidence that the members belong to ONE campaign. Unrelated to any
    -- rule's detection confidence, which measures something else entirely.
    ADD COLUMN correlation_confidence numeric(4, 3),
    -- Structured correlation signals plus a human-readable explanation.
    ADD COLUMN correlation_factors jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Structured breakdown behind risk_score, mirroring threats.risk_factors.
    ADD COLUMN risk_factors jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Last time a threat joined. The correlation window slides from here, so a
    -- sustained campaign extends rather than expiring at a fixed offset.
    ADD COLUMN last_activity_at timestamptz;

-- Incidents predating the engine (the development seed) were written by hand.
UPDATE incidents
SET correlation_key = 'legacy:' || id,
    classification  = COALESCE(classification, 'unclassified'),
    last_activity_at = COALESCE(last_activity_at, created_at),
    correlating     = false
WHERE correlation_key IS NULL;

ALTER TABLE incidents
    ALTER COLUMN correlation_key SET NOT NULL,
    ALTER COLUMN classification SET NOT NULL,
    ALTER COLUMN last_activity_at SET NOT NULL,
    ADD CONSTRAINT incidents_correlation_confidence_range
        CHECK (correlation_confidence IS NULL
               OR (correlation_confidence >= 0 AND correlation_confidence <= 1)),
    ADD CONSTRAINT incidents_correlation_factors_is_object
        CHECK (jsonb_typeof(correlation_factors) = 'object'),
    ADD CONSTRAINT incidents_risk_factors_is_object
        CHECK (jsonb_typeof(risk_factors) = 'object');

-- The durable guarantee against duplicate campaigns: at most one accumulating
-- incident per correlation key, enforced by PostgreSQL rather than by an
-- application-side existence check that two concurrent ingests could both pass.
-- It also serves the candidate lookup, so no separate index is needed.
CREATE UNIQUE INDEX incidents_active_correlation_key_idx
    ON incidents (correlation_key) WHERE correlating;
