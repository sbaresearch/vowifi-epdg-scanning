-- Required for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- ENUM: ike_result
-- ============================================================

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_type
    WHERE typname = 'ike_result'
  ) THEN
    CREATE TYPE ike_result AS ENUM (
      'SUCCESS',
      'NO_RESPONSE',
      'NO_PROPOSAL_CHOSEN',
      'NO_SUCCESS',
      'UNDEFINED'
    );
  END IF;
END
$$;

-- ============================================================
-- TABLE: epdg_server
-- ============================================================

CREATE TABLE IF NOT EXISTS epdg_server (
  id          uuid        NOT NULL DEFAULT gen_random_uuid(),
  inserted_at timestamptz NOT NULL DEFAULT now(),
  epdg_domain text        NOT NULL,
  target_ip   inet        NOT NULL,
  mcc         character(3),
  mnc         character(3),
  country     text,
  iso3        character(3),
  network     text,
  operator    text,
  itu_region  text,
  CONSTRAINT epdg_target_pkey PRIMARY KEY (id),
  CONSTRAINT epdg_target_epdg_domain_target_ip_key
    UNIQUE (epdg_domain, target_ip)
);

CREATE INDEX IF NOT EXISTS epdg_target_domain_idx
  ON epdg_server USING btree (epdg_domain);

CREATE INDEX IF NOT EXISTS epdg_target_ip_idx
  ON epdg_server USING btree (target_ip);

CREATE INDEX IF NOT EXISTS epdg_target_mcc_mnc_idx
  ON epdg_server USING btree (mcc, mnc);

CREATE INDEX IF NOT EXISTS epdg_target_country_idx
  ON epdg_server USING btree (country);

CREATE INDEX IF NOT EXISTS epdg_target_iso3_idx
  ON epdg_server USING btree (iso3);

CREATE INDEX IF NOT EXISTS epdg_target_provider_idx
  ON epdg_server USING btree (network);

CREATE INDEX IF NOT EXISTS epdg_target_operator_idx
  ON epdg_server USING btree (operator);

-- ============================================================
-- TABLE: scan
-- ============================================================

CREATE TABLE IF NOT EXISTS scan (
  id          uuid        NOT NULL DEFAULT gen_random_uuid(),
  inserted_at timestamptz NOT NULL DEFAULT now(),
  dh_variant  text        NOT NULL,
  header_text text,
  source_file text,
  CONSTRAINT test_run_pkey PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS test_run_inserted_at_idx
  ON scan USING btree (inserted_at);

CREATE INDEX IF NOT EXISTS test_run_dh_variant_idx
  ON scan USING btree (dh_variant);

-- ============================================================
-- TABLE: epdg_result
-- ============================================================

CREATE TABLE IF NOT EXISTS epdg_result (
  id           uuid        NOT NULL DEFAULT gen_random_uuid(),
  inserted_at  timestamptz NOT NULL DEFAULT now(),
  scan_id      uuid        NOT NULL,
  server_id    uuid        NOT NULL,
  observed_at  timestamptz,
  raw_state    text,
  result       ike_result  NOT NULL,
  dh_group     integer,
  encr_id      integer,
  encr_key_len integer,
  integ_id     integer,
  prf_id       integer,
  key_hex      text,
  nonce_hex    text,
  CONSTRAINT epdg_result_pkey PRIMARY KEY (id),
  CONSTRAINT epdg_result_test_run_id_target_id_key
    UNIQUE (scan_id, server_id),
  CONSTRAINT epdg_result_target_id_fkey
    FOREIGN KEY (server_id)
    REFERENCES epdg_server(id)
    ON DELETE CASCADE,
  CONSTRAINT epdg_result_test_run_id_fkey
    FOREIGN KEY (scan_id)
    REFERENCES scan(id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS epdg_result_run_idx
  ON epdg_result USING btree (scan_id);

CREATE INDEX IF NOT EXISTS epdg_result_target_idx
  ON epdg_result USING btree (server_id);

CREATE INDEX IF NOT EXISTS epdg_result_result_idx
  ON epdg_result USING btree (result);

CREATE INDEX IF NOT EXISTS epdg_result_observed_at_idx
  ON epdg_result USING btree (observed_at);

CREATE INDEX IF NOT EXISTS epdg_result_dh_group_idx
  ON epdg_result USING btree (dh_group);

-- ============================================================
-- TABLE: latest_epdg_result
-- ============================================================

CREATE TABLE IF NOT EXISTS latest_epdg_result (
  server_id   uuid        NOT NULL,
  dh_variant  text        NOT NULL,
  scan_id     uuid        NOT NULL,
  observed_at timestamptz,
  inserted_at timestamptz NOT NULL DEFAULT now(),
  result      ike_result  NOT NULL,
  raw_state   text,
  dh_group     integer,
  encr_id      integer,
  encr_key_len integer,
  integ_id     integer,
  prf_id       integer,
  key_hex      text,
  nonce_hex    text,
  CONSTRAINT latest_epdg_result_pkey
    PRIMARY KEY (server_id, dh_variant),
  CONSTRAINT latest_epdg_result_target_id_fkey
    FOREIGN KEY (server_id)
    REFERENCES epdg_server(id)
    ON DELETE CASCADE,
  CONSTRAINT latest_epdg_result_test_run_id_fkey
    FOREIGN KEY (scan_id)
    REFERENCES scan(id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS latest_epdg_result_variant_idx
  ON latest_epdg_result USING btree (dh_variant, result);

CREATE INDEX IF NOT EXISTS latest_epdg_result_observed_idx
  ON latest_epdg_result USING btree (observed_at);

-- ============================================================
-- MAPLIEBRE API SNAPSHOT VIEW (materialized view)
-- ============================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS country_operator_snapshot AS
WITH per_operator_variant AS (
  SELECT
    NULLIF(btrim(s.country), '')  AS country,
    NULLIF(btrim(s.iso3), '')     AS iso3,
    s.mcc,
    s.mnc,
    NULLIF(btrim(s.operator), '') AS operator,        -- main key
    max(NULLIF(btrim(s.network), '')) AS network,     -- metadata
    r.dh_variant,

    -- if any NO_PROPOSAL_CHOSEN appears -> NOT_SUPPORTED
    -- else if at least one SUCCESS appears -> SUPPORTED
    -- else if all results are NO_SUCCESS -> NO_SUCCESS
    -- else if all results are NO_RESPONSE -> NO_RESPONSE
    -- else -> UNKNOWN

    CASE
      WHEN bool_or(r.result = 'NO_PROPOSAL_CHOSEN') THEN 'NOT_SUPPORTED'
      WHEN bool_or(r.result = 'SUCCESS') THEN 'SUPPORTED'
      WHEN bool_and(r.result = 'NO_SUCCESS') THEN 'NO_SUCCESS'
      WHEN bool_and(r.result = 'NO_RESPONSE') THEN 'NO_RESPONSE'
      ELSE 'UNKNOWN'
    END AS support_state,

    count(*)           AS server_count,
    max(r.observed_at) AS last_observed_at
  FROM latest_epdg_result r
  JOIN epdg_server s ON s.id = r.server_id
  WHERE NULLIF(btrim(s.country), '')  IS NOT NULL
    AND NULLIF(btrim(s.operator), '') IS NOT NULL
  GROUP BY
    NULLIF(btrim(s.country), ''),
    NULLIF(btrim(s.iso3), ''),
    s.mcc,
    s.mnc,
    NULLIF(btrim(s.operator), ''),
    r.dh_variant
),
per_operator AS (
  SELECT
    country,
    iso3,
    operator,
    max(mcc) AS mcc,
    max(mnc) AS mnc,
    max(network) AS network,
    sum(server_count) AS server_count,
    max(last_observed_at) AS last_observed_at,

    jsonb_agg(dh_variant ORDER BY dh_variant)
      FILTER (WHERE support_state = 'SUPPORTED') AS supported,
    jsonb_agg(dh_variant ORDER BY dh_variant)
      FILTER (WHERE support_state = 'NOT_SUPPORTED') AS not_supported,
    jsonb_agg(dh_variant ORDER BY dh_variant)
      FILTER (WHERE support_state = 'NO_SUCCESS') AS no_success,
    jsonb_agg(dh_variant ORDER BY dh_variant)
      FILTER (WHERE support_state = 'NO_RESPONSE') AS no_response,
    jsonb_agg(dh_variant ORDER BY dh_variant)
      FILTER (WHERE support_state = 'UNKNOWN') AS unknown,

    jsonb_object_agg(dh_variant, support_state ORDER BY dh_variant) AS variants
  FROM per_operator_variant
  GROUP BY country, iso3, operator
)
SELECT
  country,
  iso3,
  jsonb_agg(
    jsonb_build_object(
      'operator', operator,
      'mcc', mcc,
      'mnc', mnc,
      'network', network,
      'server_count', server_count,
      'last_observed_at', last_observed_at,
      'supported',     COALESCE(supported,     '[]'::jsonb),
      'not_supported', COALESCE(not_supported, '[]'::jsonb),
      'no_success',    COALESCE(no_success,    '[]'::jsonb),
      'no_response',   COALESCE(no_response,   '[]'::jsonb),
      'unknown',       COALESCE(unknown,       '[]'::jsonb),
      'variants', variants
    )
    ORDER BY operator
  ) AS operators
FROM per_operator
GROUP BY country, iso3;

-- ============================================================
-- TABLE: collision_keys
-- ============================================================

CREATE TABLE IF NOT EXISTS collision_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key         TEXT NOT NULL UNIQUE,
    usage_count INTEGER NOT NULL DEFAULT 0,
    dh_variant  TEXT,
    operators   TEXT[],
    server_ids  UUID[],
    inserted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);


-- unique index required for REFRESH MATERIALIZED VIEW
CREATE UNIQUE INDEX IF NOT EXISTS country_operator_snapshot_country_iso3_uq
  ON country_operator_snapshot(country, iso3);

-- helper index for frequent queries filtering by country
CREATE INDEX IF NOT EXISTS country_operator_snapshot_country_idx
  ON country_operator_snapshot(country);

CREATE INDEX IF NOT EXISTS country_operator_snapshot_iso3_idx
  ON country_operator_snapshot(iso3);


CREATE INDEX IF NOT EXISTS latest_epdg_result_inserted_server_variant_idx
  ON latest_epdg_result (inserted_at DESC, server_id, dh_variant);

CREATE INDEX IF NOT EXISTS latest_epdg_result_result_dh_variant_idx
  ON latest_epdg_result (result, dh_variant);
