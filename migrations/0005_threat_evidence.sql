-- A detection has to be able to answer "why did this fire?". threat_type,
-- severity and confidence record the verdict but not the reasoning, so the
-- rule that fired and the evidence it saw had nowhere to live.

ALTER TABLE threats
    ADD COLUMN rule_id     text,
    ADD COLUMN evidence    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN detected_at timestamptz NOT NULL DEFAULT now();

-- Rows that predate the detection engine (the development seed) were written
-- by hand rather than by a rule.
UPDATE threats SET rule_id = 'seed.manual' WHERE rule_id IS NULL;

ALTER TABLE threats
    ALTER COLUMN rule_id SET NOT NULL,
    ADD CONSTRAINT threats_evidence_is_object CHECK (jsonb_typeof(evidence) = 'object');

CREATE INDEX threats_rule_id_idx     ON threats (rule_id);
CREATE INDEX threats_detected_at_idx ON threats (detected_at DESC);
