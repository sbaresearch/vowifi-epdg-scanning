-- ============================================================
-- Schema on top of 001/002; replaces 003, 005, 007-011 (see archive/).
-- Convergent: safe on a fresh, part-migrated or current database (then a no-op).
-- One transaction. Apply with ON_ERROR_STOP, WITHOUT --single-transaction:
--   psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 \
--        -f db/migrations/003_schema.sql
-- ============================================================

-- outside the transaction: a new enum value can't be used before commit (see the view).
ALTER TYPE ike_result ADD VALUE IF NOT EXISTS 'NO_SUCCESS';

BEGIN;

-- ============================================================
-- epdg_server: ISO3 alongside the country name  (was 003)
-- ============================================================

ALTER TABLE epdg_server
  ADD COLUMN IF NOT EXISTS iso3 character(3);

CREATE INDEX IF NOT EXISTS epdg_target_iso3_idx
  ON epdg_server USING btree (iso3);

-- same mapping as ingest (scanner/ingest/data/db_to_iso3.json); backfills old rows.
WITH country_iso3 AS (
  SELECT
    key AS country,
    NULLIF(UPPER(value), '')::character(3) AS iso3
  FROM jsonb_each_text(
    $json$
{
  "Albania": "ALB",
  "Andorra": "AND",
  "Anguilla": "AIA",
  "Antigua and Barbuda": "ATG",
  "Argentina": "ARG",
  "Armenia": "ARM",
  "Australia": "AUS",
  "Austria": "AUT",
  "Azerbaijan": "AZE",
  "Bahamas": "BHS",
  "Bahrain": "BHR",
  "Bangladesh": "BGD",
  "Barbados": "BRB",
  "Belarus": "BLR",
  "Belgium": "BEL",
  "Bermuda": "BMU",
  "Brazil": "BRA",
  "British Virgin Islands": "VGB",
  "Bulgaria": "BGR",
  "Cambodia": "KHM",
  "Canada": "CAN",
  "Cayman Islands": "CYM",
  "Chile": "CHL",
  "Colombia": "COL",
  "Cook Islands": "COK",
  "Costa Rica": "CRI",
  "Croatia": "HRV",
  "Cyprus": "CYP",
  "Czech Republic": "CZE",
  "Denmark": "DNK",
  "Dominica": "DMA",
  "Dominican Republic": "DOM",
  "Ecuador": "ECU",
  "Egypt": "EGY",
  "Estonia": "EST",
  "Ethiopia": "ETH",
  "Faroe Islands": "FRO",
  "Finland": "FIN",
  "France": "FRA",
  "French Departments and Territories in the Indian Ocean": "ATF",
  "French Guiana": "GUF",
  "French Polynesia": "PYF",
  "Germany": "DEU",
  "Ghana": "GHA",
  "Greece": "GRC",
  "Grenada": "GRD",
  "Hong Kong": "HKG",
  "Hungary": "HUN",
  "Iceland": "ISL",
  "India": "IND",
  "Indonesia": "IDN",
  "Iraq": "IRQ",
  "Ireland": "IRL",
  "Israel": "ISR",
  "Italy": "ITA",
  "Jamaica": "JAM",
  "Japan": "JPN",
  "Jordan": "JOR",
  "Kazakhstan": "KAZ",
  "Kenya": "KEN",
  "Kiribati": "KIR",
  "Kuwait": "KWT",
  "Kyrgyzstan": "KGZ",
  "Latvia": "LVA",
  "Lesotho": "LSO",
  "Libya": "LBY",
  "Liechtenstein": "LIE",
  "Lithuania": "LTU",
  "Luxembourg": "LUX",
  "Malaysia": "MYS",
  "Maldives": "MDV",
  "Malta": "MLT",
  "Mauritius": "MUS",
  "Mexico": "MEX",
  "Moldova": "MDA",
  "Monaco": "MCO",
  "Mongolia": "MNG",
  "Montenegro": "MNE",
  "Montserrat": "MSR",
  "Morocco": "MAR",
  "Myanmar": "MMR",
  "Namibia": "NAM",
  "Nepal": "NPL",
  "Netherlands": "NLD",
  "New Zealand": "NZL",
  "Norway": "NOR",
  "Oman": "OMN",
  "Pakistan": "PAK",
  "Panama": "PAN",
  "Paraguay": "PRY",
  "Peru": "PER",
  "Philippines": "PHL",
  "Poland": "POL",
  "Portugal": "PRT",
  "Puerto Rico": "PRI",
  "Qatar": "QAT",
  "Romania": "ROU",
  "Russian Federation": "RUS",
  "Saint Kitts and Nevis": "KNA",
  "Saint Lucia": "LCA",
  "Saint Vincent and the Grenadines": "VCT",
  "Saudi Arabia": "SAU",
  "Singapore": "SGP",
  "Slovakia": "SVK",
  "Slovenia": "SVN",
  "South Africa": "ZAF",
  "Spain": "ESP",
  "Sri Lanka": "LKA",
  "Sudan": "SDN",
  "Sweden": "SWE",
  "Switzerland": "CHE",
  "Taiwan": "TWN",
  "Tajikistan": "TJK",
  "Tanzania": "TZA",
  "Thailand": "THA",
  "Trinidad and Tobago": "TTO",
  "Turkey": "TUR",
  "Turks and Caicos Islands": "TCA",
  "Ukraine": "UKR",
  "United Arab Emirates": "ARE",
  "United Kingdom": "GBR",
  "United States Virgin Islands": "VIR",
  "United States of America": "USA",
  "Uruguay": "URY",
  "Uzbekistan": "UZB",
  "Venezuela": "VEN",
  "Vietnam": "VNM",
  "Zimbabwe": "ZWE"
}
    $json$::jsonb
  )
)
UPDATE epdg_server s
SET iso3 = m.iso3
FROM country_iso3 m
WHERE NULLIF(btrim(s.country), '') IS NOT NULL
  AND btrim(s.country) = m.country
  AND s.iso3 IS DISTINCT FROM m.iso3;

-- ============================================================
-- vantage_point: WHERE a scan was run from  (was 005 + 007 + 008 + 010 + 011)
-- `label` is the logical vantage point; each (label, exit_ip, warp_ip) is a row.
-- Filter scan history by label, not vantage_id.
-- ============================================================

CREATE TABLE IF NOT EXISTS vantage_point (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  label             text        NOT NULL,  -- 'austria', 'surfshark-de', 'nord-in'
  provider          text        NOT NULL,  -- 'none' | 'surfshark' | 'nordvpn' | ...
  vpn_type          text,                  -- 'openvpn' | 'wireguard' | NULL for direct
  requested_country text,                  -- what we asked gluetun for
  iso3              character(3),
  server_location   boolean     NOT NULL DEFAULT false,
  first_seen        timestamptz NOT NULL DEFAULT now(),
  last_seen         timestamptz NOT NULL DEFAULT now(),
  -- last, as in upgraded databases.
  exit_ip           inet,                  -- the VPN exit, or the host's own address
  exit_country      text,
  warp_ip           inet,                  -- Cloudflare WARP hop, NULL without one
  warp_country      text
);

-- 005 named the host flag is_reference.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name   = 'vantage_point'
       AND column_name  = 'is_reference'
  ) THEN
    ALTER TABLE vantage_point RENAME COLUMN is_reference TO server_location;
  END IF;

  -- RENAME COLUMN keeps the NOT NULL constraint's old name.
  IF EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'vantage_point_is_reference_not_null'
       AND conrelid = 'vantage_point'::regclass
  ) THEN
    ALTER TABLE vantage_point
      RENAME CONSTRAINT vantage_point_is_reference_not_null
                     TO vantage_point_server_location_not_null;
  END IF;
END $$;

-- columns added later; nullable/defaulted, so no table rewrite.
ALTER TABLE vantage_point
  ADD COLUMN IF NOT EXISTS server_location boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS exit_ip         inet,
  ADD COLUMN IF NOT EXISTS exit_country    text,
  ADD COLUMN IF NOT EXISTS warp_ip         inet,
  ADD COLUMN IF NOT EXISTS warp_country    text;

-- old identity keys; dropped before the WARP conversion (full and WARP runs share exits).
ALTER TABLE vantage_point DROP CONSTRAINT IF EXISTS vantage_point_label_key;
DROP INDEX IF EXISTS vantage_point_reference_uq;
DROP INDEX IF EXISTS vantage_point_server_location_uq;
DROP INDEX IF EXISTS vantage_point_label_exit_uq;
DROP INDEX IF EXISTS vantage_point_via_ip_idx;

-- the host's own scan, named after where it sits. No ON CONFLICT: label isn't unique.
INSERT INTO vantage_point (label, provider, requested_country, iso3, server_location)
SELECT 'austria', 'none', 'Austria', 'AUT', true
 WHERE NOT EXISTS (SELECT 1 FROM vantage_point WHERE label = 'austria');

-- ============================================================
-- scan: vantage, hops and mode  (was 005 + 009 + 011)
--   full         zdns discovery in the tunnel, all testcases, via the VPN exit
--   full_warp    domains from epdg_server, all testcases, VPN exit -> WARP
--   dh2048_warp  domains from epdg_server, DH2048 only, VPN exit -> WARP
--   local        the host's own untunnelled rounds
-- ============================================================

ALTER TABLE scan
  ADD COLUMN IF NOT EXISTS vantage_id   uuid REFERENCES vantage_point(id),
  ADD COLUMN IF NOT EXISTS exit_ip      inet,
  ADD COLUMN IF NOT EXISTS exit_country text,
  ADD COLUMN IF NOT EXISTS mode         text NOT NULL DEFAULT 'full',
  ADD COLUMN IF NOT EXISTS warp_ip      inet,
  ADD COLUMN IF NOT EXISTS warp_country text;

-- older scans ran from the host; LIMIT 1: 'austria' has a row per host address.
UPDATE scan
   SET vantage_id = (SELECT id FROM vantage_point
                      WHERE label = 'austria'
                      ORDER BY first_seen LIMIT 1)
 WHERE vantage_id IS NULL;

ALTER TABLE scan ALTER COLUMN vantage_id SET NOT NULL;

-- pre-`mode` host rounds become 'local'; only default ('full') rows change.
UPDATE scan s
   SET mode = 'local'
  FROM vantage_point v
 WHERE v.id = s.vantage_id
   AND v.server_location
   AND s.mode = 'full';

CREATE INDEX IF NOT EXISTS scan_vantage_idx
  ON scan USING btree (vantage_id, dh_variant, inserted_at DESC);

CREATE INDEX IF NOT EXISTS scan_mode_idx
  ON scan USING btree (mode, dh_variant, inserted_at DESC);

-- ============================================================
-- latest_epdg_result: vantage and mode join the key  (was 005 + 009)
-- else vantage points and modes overwrite each other's results.
-- ============================================================

ALTER TABLE latest_epdg_result
  ADD COLUMN IF NOT EXISTS vantage_id uuid REFERENCES vantage_point(id),
  ADD COLUMN IF NOT EXISTS mode       text NOT NULL DEFAULT 'full';

UPDATE latest_epdg_result l
   SET vantage_id = s.vantage_id
  FROM scan s
 WHERE s.id = l.scan_id
   AND l.vantage_id IS NULL;

ALTER TABLE latest_epdg_result ALTER COLUMN vantage_id SET NOT NULL;

UPDATE latest_epdg_result l
   SET mode = s.mode
  FROM scan s
 WHERE s.id = l.scan_id
   AND l.mode IS DISTINCT FROM s.mode;

-- upgrades the 2- or 3-column key; no-op once it has 4.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'latest_epdg_result_pkey'
       AND conrelid = 'latest_epdg_result'::regclass
       AND array_length(conkey, 1) = 4
  ) THEN
    ALTER TABLE latest_epdg_result DROP CONSTRAINT IF EXISTS latest_epdg_result_pkey;
    ALTER TABLE latest_epdg_result
      ADD CONSTRAINT latest_epdg_result_pkey
      PRIMARY KEY (server_id, dh_variant, vantage_id, mode);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS latest_epdg_result_vantage_idx
  ON latest_epdg_result USING btree (vantage_id, dh_variant, result);

CREATE INDEX IF NOT EXISTS latest_epdg_result_mode_idx
  ON latest_epdg_result USING btree (mode, dh_variant, result);

-- ============================================================
-- Name the two hops  (was 010 + 011)
--   exit_ip / exit_country   VPN exit, or the host's address on a local run
--   warp_ip / warp_country   Cloudflare WARP hop, NULL without one
-- Old WARP rows had the WARP address in exit_ip: values are swapped. Runs only
-- while scan.via_ip (009-010) still exists.
-- ============================================================

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'scan' AND column_name = 'via_ip'
  ) THEN

    -- exit from `scan`: covers databases stopped at 009 or 010 alike.
    UPDATE vantage_point v
       SET warp_ip      = v.exit_ip,
           warp_country = v.exit_country,
           exit_ip      = s.via_ip,
           exit_country = s.via_country
      FROM (
        SELECT DISTINCT ON (vantage_id) vantage_id, via_ip, via_country
          FROM scan
         WHERE via_ip IS NOT NULL
         ORDER BY vantage_id, inserted_at DESC
      ) s
     WHERE s.vantage_id = v.id
       AND v.warp_ip IS NULL;

    -- WARP rows from before 009: the VPN exit is unknown, so NULL.
    UPDATE vantage_point v
       SET warp_ip      = v.exit_ip,
           warp_country = v.exit_country,
           exit_ip      = NULL,
           exit_country = NULL
     WHERE v.warp_ip IS NULL
       AND EXISTS (SELECT 1 FROM scan s
                    WHERE s.vantage_id = v.id AND s.mode LIKE '%warp');

    -- one statement: SET reads old values, so this swaps.
    UPDATE scan
       SET warp_ip      = exit_ip,
           warp_country = exit_country,
           exit_ip      = via_ip,
           exit_country = via_country
     WHERE via_ip IS NOT NULL;

    UPDATE scan
       SET warp_ip      = exit_ip,
           warp_country = exit_country,
           exit_ip      = NULL,
           exit_country = NULL
     WHERE via_ip IS NULL AND warp_ip IS NULL AND mode LIKE '%warp';

    ALTER TABLE scan DROP COLUMN via_ip, DROP COLUMN via_country;
  END IF;
END $$;

ALTER TABLE vantage_point
  DROP COLUMN IF EXISTS via_ip,
  DROP COLUMN IF EXISTS via_country;

-- WARP rows without scans (missed above): recognised by Cloudflare's ranges, which
-- no VPN exits from. Unconditional: such rows survive a finished conversion.
UPDATE vantage_point
   SET warp_ip      = exit_ip,
       warp_country = exit_country,
       exit_ip      = NULL,
       exit_country = NULL
 WHERE warp_ip IS NULL
   AND (exit_ip <<= '104.16.0.0/12' OR exit_ip <<= '172.64.0.0/13');

-- ============================================================
-- vantage_point: the final index set
-- ============================================================

-- one row per (label, exit, WARP hop); NULLS NOT DISTINCT, or a failed IP
-- lookup would add a row every round.
CREATE UNIQUE INDEX IF NOT EXISTS vantage_point_label_exit_warp_uq
  ON vantage_point (label, exit_ip, warp_ip) NULLS NOT DISTINCT;

-- label lookups: a logical vantage point to all its exits.
CREATE INDEX IF NOT EXISTS vantage_point_label_idx
  ON vantage_point USING btree (label);

CREATE INDEX IF NOT EXISTS vantage_point_provider_idx
  ON vantage_point USING btree (provider);

-- not unique: the host gets a row per public IP, all flagged.
CREATE INDEX IF NOT EXISTS vantage_point_server_location_idx
  ON vantage_point (server_location) WHERE server_location;

-- vantage points behind a WARP egress.
CREATE INDEX IF NOT EXISTS vantage_point_warp_ip_idx
  ON vantage_point USING btree (warp_ip) WHERE warp_ip IS NOT NULL;

-- ============================================================
-- FUNCTION: refresh_latest_snapshot -- supersede by (label, mode, variant)
-- not by vantage_id (one per exit) nor label alone (modes would erase each other).
-- ============================================================

CREATE OR REPLACE FUNCTION refresh_latest_snapshot(p_run_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  v_variant text;
  v_label   text;
  v_mode    text;
BEGIN
  SELECT sc.dh_variant, v.label, sc.mode
    INTO v_variant, v_label, v_mode
    FROM scan sc
    JOIN vantage_point v ON v.id = sc.vantage_id
   WHERE sc.id = p_run_id;

  IF v_variant IS NULL THEN
    RAISE EXCEPTION 'scan % not found', p_run_id;
  END IF;

  -- replace this variant's rows for this label and mode, across all exits.
  DELETE FROM latest_epdg_result l
   USING vantage_point v
   WHERE l.vantage_id = v.id
     AND l.dh_variant = v_variant
     AND l.mode       = v_mode
     AND v.label      = v_label;

  INSERT INTO latest_epdg_result (
    server_id, dh_variant, vantage_id, mode, scan_id, observed_at, result,
    raw_state, dh_group, encr_id, encr_key_len, integ_id, prf_id, key_hex, nonce_hex
  )
  SELECT
    res.server_id,
    tr.dh_variant,
    tr.vantage_id,
    tr.mode,
    res.scan_id,
    res.observed_at,
    res.result,
    res.raw_state,
    res.dh_group,
    res.encr_id,
    res.encr_key_len,
    res.integ_id,
    res.prf_id,
    res.key_hex,
    res.nonce_hex
  FROM epdg_result res
  JOIN scan tr ON tr.id = res.scan_id
  WHERE res.scan_id = p_run_id;
END $$;

-- ============================================================
-- FUNCTION: refresh_collision_keys -- the host's own ('local') rounds only
-- GeoDNS gives other vantage points other IPs for one ePDG, which would read as
-- collisions. IN: the host has a row per address.
-- ============================================================

CREATE OR REPLACE FUNCTION refresh_collision_keys()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  WITH distinct_combos AS (
    SELECT DISTINCT
      r.key_hex,
      r.server_id,
      r.dh_variant,
      s.operator,
      s.target_ip
    FROM latest_epdg_result r
    JOIN epdg_server s ON s.id = r.server_id
    WHERE r.key_hex IS NOT NULL
    AND r.dh_variant NOT IN ('DOWNGRADE_DH2048', 'TOLERATE_DH1024', 'UNKNOWN')
    AND r.mode = 'local'
    AND r.vantage_id IN (SELECT id FROM vantage_point WHERE server_location)
  ),
  collisions AS (
    SELECT
      key_hex,
      COUNT(DISTINCT server_id) AS server_count,
      MIN(dh_variant) AS dh_variant,
      array_agg(DISTINCT operator) AS operators,
      array_agg(DISTINCT server_id) AS server_ids
    FROM distinct_combos
    GROUP BY key_hex
    HAVING COUNT(DISTINCT server_id) > 1
    AND    COUNT(DISTINCT target_ip) > 1
  )
  INSERT INTO collision_keys (key, usage_count, dh_variant, operators, server_ids)
  SELECT key_hex, server_count, dh_variant, operators, server_ids FROM collisions
  ON CONFLICT (key) DO UPDATE
    SET usage_count = collision_keys.usage_count + EXCLUDED.usage_count,
        dh_variant  = EXCLUDED.dh_variant,
        operators   = ARRAY(SELECT DISTINCT unnest(collision_keys.operators || EXCLUDED.operators)),
        server_ids  = ARRAY(SELECT DISTINCT unnest(collision_keys.server_ids || EXCLUDED.server_ids)),
        updated_at  = now();
END $$;

-- ============================================================
-- MATERIALIZED VIEW: country_operator_snapshot
--   one row per (label, mode, country), grouped by label (it spans exits), plus
--   merged rows (mode 'all') per vantage country ('DEU') and overall ('all'):
--   per server and DH group the latest valid answer, else the latest non-answer.
-- Rebuilt every run (ACCESS EXCLUSIVE): stop the scanner and orchestrator first.
-- ============================================================

DROP MATERIALIZED VIEW IF EXISTS country_operator_snapshot;

CREATE MATERIALIZED VIEW country_operator_snapshot AS
WITH results AS (
  SELECT v.label AS vantage_label, r.mode, r.server_id, r.dh_variant, r.result, r.observed_at
    FROM latest_epdg_result r
    JOIN vantage_point v ON v.id = r.vantage_id
  UNION ALL
  (SELECT DISTINCT ON (COALESCE(v.iso3, v.label), r.server_id, r.dh_variant)
          COALESCE(v.iso3, v.label), 'all', r.server_id, r.dh_variant, r.result, r.observed_at
     FROM latest_epdg_result r
     JOIN vantage_point v ON v.id = r.vantage_id
    ORDER BY COALESCE(v.iso3, v.label), r.server_id, r.dh_variant,
             r.result IN ('SUCCESS', 'NO_PROPOSAL_CHOSEN', 'NO_SUCCESS') DESC,
             r.observed_at DESC)
  UNION ALL
  (SELECT DISTINCT ON (r.server_id, r.dh_variant)
          'all', 'all', r.server_id, r.dh_variant, r.result, r.observed_at
     FROM latest_epdg_result r
    ORDER BY r.server_id, r.dh_variant,
             r.result IN ('SUCCESS', 'NO_PROPOSAL_CHOSEN', 'NO_SUCCESS') DESC,
             r.observed_at DESC)
),
per_operator_variant AS (
  SELECT
    r.vantage_label,
    r.mode,
    NULLIF(btrim(s.country), '')  AS country,
    NULLIF(btrim(s.iso3), '')     AS iso3,
    s.mcc,
    s.mnc,
    NULLIF(btrim(s.operator), '') AS operator,
    max(NULLIF(btrim(s.network), '')) AS network,
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
  FROM results r
  JOIN epdg_server s ON s.id = r.server_id
  WHERE NULLIF(btrim(s.country), '')  IS NOT NULL
    AND NULLIF(btrim(s.operator), '') IS NOT NULL
  GROUP BY
    r.vantage_label,
    r.mode,
    NULLIF(btrim(s.country), ''),
    NULLIF(btrim(s.iso3), ''),
    s.mcc,
    s.mnc,
    NULLIF(btrim(s.operator), ''),
    r.dh_variant
),
per_operator AS (
  SELECT
    vantage_label,
    mode,
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
  GROUP BY vantage_label, mode, country, iso3, operator
)
SELECT
  p.vantage_label,
  p.mode,
  p.country,
  p.iso3,
  jsonb_agg(
    jsonb_build_object(
      'operator', p.operator,
      'mcc', p.mcc,
      'mnc', p.mnc,
      'network', p.network,
      'server_count', p.server_count,
      'last_observed_at', p.last_observed_at,
      'supported',     COALESCE(p.supported,     '[]'::jsonb),
      'not_supported', COALESCE(p.not_supported, '[]'::jsonb),
      'no_success',    COALESCE(p.no_success,    '[]'::jsonb),
      'no_response',   COALESCE(p.no_response,   '[]'::jsonb),
      'unknown',       COALESCE(p.unknown,       '[]'::jsonb),
      'variants', p.variants
    )
    ORDER BY p.operator
  ) AS operators
FROM per_operator p
GROUP BY p.vantage_label, p.mode, p.country, p.iso3;

-- unique index required for REFRESH MATERIALIZED VIEW CONCURRENTLY
CREATE UNIQUE INDEX IF NOT EXISTS country_operator_snapshot_label_mode_country_uq
  ON country_operator_snapshot(vantage_label, mode, country, iso3);

CREATE INDEX IF NOT EXISTS country_operator_snapshot_country_idx
  ON country_operator_snapshot(country);

CREATE INDEX IF NOT EXISTS country_operator_snapshot_iso3_idx
  ON country_operator_snapshot(iso3);

COMMIT;
