-- Development fixture: one credible intrusion from first failed login to
-- containment, plus enough benign traffic that queries return a realistic mix.
-- Intended for a fresh database; run once.

BEGIN;

INSERT INTO users (username, role) VALUES
    ('a.okafor',  'analyst'),
    ('r.mensah',  'responder'),
    ('t.devries', 'viewer'),
    ('svc.backup', 'viewer'),
    ('m.acheampong', 'admin');

INSERT INTO devices (user_id, device_fingerprint, trust_score)
SELECT u.id, d.fingerprint, d.trust_score
FROM (VALUES
    ('a.okafor',     'fp-9c2e-thinkpad-t14',   92.50),
    ('r.mensah',     'fp-41ab-macbook-pro',    88.00),
    ('t.devries',    'fp-7f10-ipad-air',       74.25),
    ('svc.backup',   'fp-0000-headless-agent', 55.00),
    ('m.acheampong', 'fp-b38d-thinkpad-x1',    95.75),
    -- Unrecognised hardware presenting m.acheampong's credentials.
    ('m.acheampong', 'fp-dead-unknown-vm',      4.00)
) AS d(username, fingerprint, trust_score)
JOIN users u ON u.username = d.username;

INSERT INTO events (event_type, user_id, source_ip, occurred_at, metadata)
SELECT e.event_type, u.id, e.source_ip::inet, e.occurred_at::timestamptz, e.metadata::jsonb
FROM (VALUES
    ('auth.login.success', 'a.okafor',     '10.14.3.22',     '2026-09-12 08:02:11+00', '{"seed_ref": "benign-1", "mfa": true}'),
    ('auth.login.success', 'r.mensah',     '10.14.3.87',     '2026-09-12 08:31:40+00', '{"seed_ref": "benign-2", "mfa": true}'),
    ('file.read',          't.devries',    '10.14.9.5',      '2026-09-12 09:15:02+00', '{"seed_ref": "benign-3", "path": "/reports/q3.pdf"}'),
    ('auth.login.failure', 'm.acheampong', '203.0.113.44',   '2026-09-12 23:41:08+00', '{"seed_ref": "attack-1", "attempts": 14, "reason": "bad_password"}'),
    ('auth.login.success', 'm.acheampong', '203.0.113.44',   '2026-09-12 23:44:52+00', '{"seed_ref": "attack-2", "mfa": false, "new_device": true}'),
    ('privilege.escalate', 'm.acheampong', '203.0.113.44',   '2026-09-12 23:52:19+00', '{"seed_ref": "attack-3", "from": "admin", "to": "root"}'),
    ('data.egress',        'm.acheampong', '203.0.113.44',   '2026-09-13 00:07:33+00', '{"seed_ref": "attack-4", "bytes": 2147483648, "destination": "198.51.100.9"}')
) AS e(event_type, username, source_ip, occurred_at, metadata)
LEFT JOIN users u ON u.username = e.username;

INSERT INTO threats (event_id, threat_type, severity, confidence)
SELECT ev.id, t.threat_type, t.severity::severity_level, t.confidence
FROM (VALUES
    ('attack-1', 'credential.bruteforce',    'medium',   0.780),
    ('attack-2', 'impossible.travel',        'high',     0.910),
    ('attack-2', 'untrusted.device',         'high',     0.865),
    ('attack-3', 'privilege.escalation',     'critical', 0.940),
    ('attack-4', 'data.exfiltration',        'critical', 0.975)
) AS t(seed_ref, threat_type, severity, confidence)
JOIN events ev ON ev.metadata ->> 'seed_ref' = t.seed_ref;

INSERT INTO incidents (title, severity, risk_score, status, created_at) VALUES
    ('Admin account takeover from 203.0.113.44', 'critical', 96.50, 'contained', '2026-09-12 23:53:00+00'),
    ('Repeated failed logins against service accounts', 'low', 21.00, 'false_positive', '2026-09-11 14:20:00+00');

UPDATE threats
SET incident_id = (SELECT id FROM incidents WHERE title = 'Admin account takeover from 203.0.113.44')
WHERE threat_type IN ('impossible.travel', 'untrusted.device', 'privilege.escalation', 'data.exfiltration');

INSERT INTO responses (incident_id, action, result, occurred_at)
SELECT i.id, r.action, r.result::response_result, r.occurred_at::timestamptz
FROM (VALUES
    ('Admin account takeover from 203.0.113.44', 'session.revoke',     'succeeded', '2026-09-12 23:54:10+00'),
    ('Admin account takeover from 203.0.113.44', 'account.disable',    'succeeded', '2026-09-12 23:54:44+00'),
    ('Admin account takeover from 203.0.113.44', 'network.block_ip',   'succeeded', '2026-09-12 23:56:02+00'),
    ('Admin account takeover from 203.0.113.44', 'forensics.snapshot', 'failed',    '2026-09-13 00:12:47+00'),
    ('Admin account takeover from 203.0.113.44', 'notify.oncall',      'pending',   '2026-09-13 00:13:00+00')
) AS r(title, action, result, occurred_at)
JOIN incidents i ON i.title = r.title;

COMMIT;
