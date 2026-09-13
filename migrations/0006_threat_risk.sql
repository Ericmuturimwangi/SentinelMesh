-- Threat-level risk. incidents.risk_score already exists and stays untouched:
-- that is campaign risk, aggregated in a later phase from these per-threat
-- values. Columns are nullable because threats written before the risk engine
-- (the development seed) were never scored, and inventing a score for them
-- would be worse than recording that none exists.

ALTER TABLE threats
    -- numeric(5,2) matches incidents.risk_score so the two are comparable
    -- without a cast. Values are whole numbers; the scale is for compatibility.
    ADD COLUMN risk_score        numeric(5, 2),
    -- Derived from risk_score, but persisted so triage queues can filter and
    -- index by band without scattering the threshold definitions into SQL.
    ADD COLUMN risk_level        severity_level,
    -- The per-factor breakdown behind the score. Kept separate from evidence:
    -- evidence is the detection's reasoning and is fixed once observed, while
    -- this is the scoring model's reasoning and is replaced on every rescore.
    ADD COLUMN risk_factors      jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Diverges from detected_at as soon as a threat is rescored under a newer
    -- model version, which is what makes a rescore auditable.
    ADD COLUMN risk_calculated_at timestamptz;

ALTER TABLE threats
    ADD CONSTRAINT threats_risk_score_range
        CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)),
    ADD CONSTRAINT threats_risk_factors_is_object
        CHECK (jsonb_typeof(risk_factors) = 'object'),
    -- A score without a band, or a band without a score, is a half-written row.
    ADD CONSTRAINT threats_risk_complete
        CHECK ((risk_score IS NULL) = (risk_level IS NULL));

CREATE INDEX threats_risk_idx ON threats (risk_level, risk_score DESC);
