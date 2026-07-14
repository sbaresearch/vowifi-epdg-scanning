-- this function looks for newer results, if they are present old ones in the latest_epdg_results table will be replaced by the new ones.
-- if no new results or they are identical, old ones are kept.
create or replace function refresh_latest_snapshot(p_run_id uuid)
returns void
language plpgsql
as $$
declare
  v_variant text;
begin
  select dh_variant into v_variant
  from scan
  where id = p_run_id;

  if v_variant is null then
    raise exception 'scan % not found', p_run_id;
  end if;

  -- replace the snapshot for this DH variant specifically.
  delete from latest_epdg_result
  where dh_variant = v_variant;

  insert into latest_epdg_result (
    server_id, dh_variant, scan_id, observed_at, result, raw_state,
    dh_group, encr_id, encr_key_len, integ_id, prf_id, key_hex, nonce_hex
  )
  select
    res.server_id,
    tr.dh_variant,
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
  from epdg_result res
  join scan tr on tr.id = res.scan_id
  where res.scan_id = p_run_id;
end $$;



-- refresh function that refreshes country_operator_snapshot view (including iso3) with data from latest_epdg_result/epdg_server.
-- call after the above refresh_latest_snapshot.
CREATE OR REPLACE FUNCTION refresh_country_operator_snapshot()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY country_operator_snapshot;
END $$;


-- Queries latest_epdg_result for keys that collide. For each key, increment usage_count
-- in collision_keys by the number of servers using it in the current latest_epdg_result table.
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
