-- Core identity: principals and the devices they authenticate from.

CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'responder', 'viewer');

CREATE TABLE users (
    id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username text      NOT NULL,
    role     user_role NOT NULL,

    CONSTRAINT users_username_key    UNIQUE (username),
    CONSTRAINT users_username_nonblank CHECK (length(btrim(username)) > 0)
);

CREATE TABLE devices (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id            bigint        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_fingerprint text          NOT NULL,
    trust_score        numeric(5, 2) NOT NULL,

    -- A shared workstation can legitimately appear under several users, so the
    -- fingerprint is unique per user rather than globally.
    CONSTRAINT devices_user_fingerprint_key UNIQUE (user_id, device_fingerprint),
    CONSTRAINT devices_trust_score_range    CHECK (trust_score >= 0 AND trust_score <= 100)
);

CREATE INDEX devices_user_id_idx     ON devices (user_id);
CREATE INDEX devices_fingerprint_idx ON devices (device_fingerprint);
