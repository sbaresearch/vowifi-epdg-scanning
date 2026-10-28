-- ============================================================
-- Geoblocking: from which vantage countries each operator's ePDGs answer.
-- Adds one materialized view and extends refresh_country_operator_snapshot();
-- touches no existing rows. Idempotent. Apply with:
--   psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 \
--        -f db/migrations/004_geoblocking.sql
-- ============================================================

BEGIN;

-- ============================================================
-- MATERIALIZED VIEW: operator_reachability
--   one row per (operator, vantage country), from the latest round of each
--   vantage label and mode (a probe). Rule as in MobiSys'24 sec. 4.2: any IKE
--   answer counts, NO_PROPOSAL_CHOSEN included; the operator blocks a country
--   whose answer rate is below 10% of the home country's, from one probe on.
--   state: 'answers' | 'blocks' | 'no_answers' (never answered anywhere).
--   vpn_answered: answered probes through a VPN or WARP exit (every mode but 'local').
--   seen_from: where the probe exits, not the requested country (VPN virtual
--   locations sit elsewhere); the requested one only when the exit is unknown.
-- ============================================================

DROP MATERIALIZED VIEW IF EXISTS operator_reachability;

CREATE MATERIALIZED VIEW operator_reachability AS
WITH country_name AS (
  -- names to ISO3 as ingest maps them (db_to_iso3.json), read back from the rows it wrote.
  SELECT DISTINCT ON (name) name, iso3
  FROM (
    SELECT lower(btrim(country)) AS name, iso3 FROM epdg_server WHERE iso3 IS NOT NULL
    UNION ALL
    SELECT lower(btrim(requested_country)), iso3 FROM vantage_point WHERE iso3 IS NOT NULL
  ) n
  ORDER BY name, iso3
),
obs AS (
  SELECT
    NULLIF(btrim(s.country), '')  AS country,
    NULLIF(btrim(s.iso3), '')     AS iso3,
    NULLIF(btrim(s.operator), '') AS operator,
    s.epdg_domain,
    v.label,
    -- where the ePDG saw the probe: WARP egress, else VPN exit, else the requested country.
    COALESCE(w.iso3, e.iso3, v.iso3) AS seen_from,
    r.mode,
    r.dh_variant,
    -- 'unknown payload' is a notify such as INVALID_KE: an answer too.
    (r.result IN ('SUCCESS', 'NO_PROPOSAL_CHOSEN', 'NO_SUCCESS')
      OR r.raw_state LIKE 'unknown payload%') AS answered
  FROM latest_epdg_result r
  JOIN epdg_server s   ON s.id = r.server_id
  JOIN vantage_point v ON v.id = r.vantage_id
  -- warp_country is set on WARP runs only.
  LEFT JOIN country_name w ON w.name = lower(btrim(v.warp_country))
  LEFT JOIN country_name e ON e.name = lower(btrim(v.exit_country))
  WHERE COALESCE(w.iso3, e.iso3, v.iso3) IS NOT NULL
    AND NULLIF(btrim(s.country), '')  IS NOT NULL
    AND NULLIF(btrim(s.operator), '') IS NOT NULL
    -- leaves out 'exception occured': neither answer nor silence.
    AND (r.result IN ('SUCCESS', 'NO_PROPOSAL_CHOSEN', 'NO_SUCCESS', 'NO_RESPONSE')
      OR r.raw_state LIKE 'unknown payload%')
),
live AS (
  -- silence on a DH group the domain answers nowhere is no evidence of blocking.
  SELECT
    o.*,
    bool_or(o.answered) OVER (PARTITION BY o.epdg_domain, o.dh_variant) AS group_live,
    bool_or(o.answered) OVER (PARTITION BY o.epdg_domain)               AS domain_live
  FROM obs o
),
probe AS (
  -- a round's testcases share one exit, so they count once.
  SELECT country, iso3, operator, seen_from, label, mode, bool_or(answered) AS answered
  FROM live
  WHERE group_live OR NOT domain_live
  GROUP BY country, iso3, operator, seen_from, label, mode
),
per_country AS (
  SELECT
    country, iso3, operator, seen_from,
    count(*)                                            AS probes,
    count(*) FILTER (WHERE answered)                    AS answered,
    count(*) FILTER (WHERE answered AND mode <> 'local') AS vpn_answered
  FROM probe
  GROUP BY country, iso3, operator, seen_from
),
rated AS (
  SELECT
    p.*,
    p.answered::numeric / p.probes AS rate,
    max(p.answered::numeric / p.probes) OVER w AS best,
    -- home rate, else the best anywhere: a silent home's 0 would clear every block.
    COALESCE(
      NULLIF(max(p.answered::numeric / p.probes) FILTER (WHERE p.seen_from = p.iso3) OVER w, 0),
      max(p.answered::numeric / p.probes) OVER w
    ) AS baseline
  FROM per_country p
  WINDOW w AS (PARTITION BY p.country, p.iso3, p.operator)
)
SELECT
  country,
  iso3,
  operator,
  seen_from,
  probes,
  answered,
  vpn_answered,
  CASE
    WHEN best = 0              THEN 'no_answers'
    WHEN rate < 0.1 * baseline THEN 'blocks'
    ELSE 'answers'
  END AS state
FROM rated;

-- unique index required for REFRESH MATERIALIZED VIEW CONCURRENTLY
CREATE UNIQUE INDEX IF NOT EXISTS operator_reachability_uq
  ON operator_reachability(country, iso3, operator, seen_from);

-- ============================================================
-- FUNCTION: refresh_country_operator_snapshot -- now refreshes both views
-- Same inputs and call sites, so neither scanner nor orchestrator changes.
-- ============================================================

CREATE OR REPLACE FUNCTION refresh_country_operator_snapshot()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY country_operator_snapshot;
  REFRESH MATERIALIZED VIEW CONCURRENTLY operator_reachability;
END $$;

COMMIT;
