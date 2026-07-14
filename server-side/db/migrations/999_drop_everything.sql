-- !!! ATTENTION: This drops EVERYTHING from the Database. !!!
-- Use with caution.

drop table if exists
  latest_epdg_result,
  epdg_result,
  epdg_server,
  scan,
  country_operator_snapshot,
  collision_keys
cascade;

drop function if exists refresh_latest_snapshot(uuid);
drop function if exists refresh_country_operator_snapshot();
drop function if exists refresh_collision_keys();

drop type if exists ike_result;