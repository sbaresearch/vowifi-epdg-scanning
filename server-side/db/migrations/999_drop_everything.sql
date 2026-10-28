-- !!! ATTENTION: This drops EVERYTHING from the Database. !!!
-- Use with caution.

-- a materialized view, so `drop table` below misses it.
drop materialized view if exists country_operator_snapshot cascade;
drop materialized view if exists operator_reachability cascade;

drop table if exists
  latest_epdg_result,
  epdg_result,
  epdg_server,
  scan,
  -- dropped after scan, which references it.
  vantage_point,
  collision_keys
cascade;

drop function if exists refresh_latest_snapshot(uuid);
drop function if exists refresh_country_operator_snapshot();
drop function if exists refresh_collision_keys();

drop type if exists ike_result;