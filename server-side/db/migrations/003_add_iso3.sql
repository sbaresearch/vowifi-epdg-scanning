ALTER TABLE epdg_server
  ADD COLUMN IF NOT EXISTS iso3 character(3);

CREATE INDEX IF NOT EXISTS epdg_target_iso3_idx
  ON epdg_server USING btree (iso3);

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

DROP INDEX IF EXISTS country_operator_snapshot_country_uq;
DROP INDEX IF EXISTS country_operator_snapshot_country_idx;
DROP MATERIALIZED VIEW IF EXISTS country_operator_snapshot;

CREATE MATERIALIZED VIEW country_operator_snapshot AS
WITH per_operator_variant AS (
  SELECT
    NULLIF(btrim(s.country), '')  AS country,
    NULLIF(btrim(s.iso3), '')     AS iso3,
    s.mcc,
    s.mnc,
    NULLIF(btrim(s.operator), '') AS operator,
    max(NULLIF(btrim(s.network), '')) AS network,
    r.dh_variant,
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

CREATE UNIQUE INDEX IF NOT EXISTS country_operator_snapshot_country_iso3_uq
  ON country_operator_snapshot(country, iso3);

CREATE INDEX IF NOT EXISTS country_operator_snapshot_country_idx
  ON country_operator_snapshot(country);

CREATE INDEX IF NOT EXISTS country_operator_snapshot_iso3_idx
  ON country_operator_snapshot(iso3);
