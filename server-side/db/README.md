# Database

The PostgreSQL schema shared by the scanner, the vantage orchestrator, the API and the Zulip bot.

```
migrations/          the schema, applied on the database's first start
migrations/archive/  earlier migrations, replaced by 003_schema.sql
analysis/            a one-off analysis script, not part of the schema
schema/              the ER diagram below
```

![Database model](schema/database_diagram.png)

## Migrations

`compose.yaml` mounts the first four files into the Postgres container's `/docker-entrypoint-initdb.d/`. Postgres runs them in order when it starts with an empty data directory (`./epdg-container/postgres`) and never again after that.

| File | Contents |
|---|---|
| `001_create_tables.sql` | the `ike_result` enum, `epdg_server`, `scan`, `epdg_result`, `latest_epdg_result`, `collision_keys` |
| `002_create_functions.sql` | the refresh functions |
| `003_schema.sql` | ISO3 country codes, the `vantage_point` table, vantage point and scan mode on `scan` and `latest_epdg_result`, and the current versions of the refresh functions and `country_operator_snapshot` |
| `004_geoblocking.sql` | the `operator_reachability` view, and a `refresh_country_operator_snapshot()` that refreshes both views |

`003_schema.sql` replaces seven earlier migrations, which are kept in [migrations/archive/](migrations/archive/). It always leads to the same schema, whether it runs on a new database or one built from those earlier files, and running it a second time changes nothing.

> [!CAUTION]
> `999_drop_everything.sql` deletes every table, view, function and the enum, along with all data. It isn't mounted and never runs on its own.

## Tables

| Table | One row per | Contents |
|---|---|---|
| `epdg_server` | ePDG domain and IP | MCC/MNC, country, ISO3 code, network, operator, ITU region |
| `vantage_point` | vantage point and network path | label, VPN provider and type, requested country, VPN exit and WARP hop with their countries, first and last seen |
| `scan` | test run of one DH variant | vantage point, scan mode, VPN exit and WARP hop |
| `epdg_result` | test case against one server | IKE outcome, raw state, negotiated DH group and algorithms, key and nonce |
| `latest_epdg_result` | server, DH variant, vantage point and mode | the newest result for that combination |
| `collision_keys` | IKE key used by more than one server | usage count, DH variant, operators and server IDs |

`ike_result` is an enum with the values `SUCCESS`, `NO_RESPONSE`, `NO_PROPOSAL_CHOSEN`, `NO_SUCCESS` and `UNDEFINED`.

**Vantage points.** The `label` is the vantage point as the website shows it, for example `austria` or `surfshark-japan`. It gets a new row whenever its VPN exit or WARP hop changes, so one label can have several rows. Scan history belongs to the label, not to a single row. `server_location` marks the rows of the scanning host itself.

**Exit and WARP hop.** `scan` and `vantage_point` both record two hops:

- `exit_ip`, `exit_country`: the VPN exit, or the host's own address for `local` scans
- `warp_ip`, `warp_country`: the Cloudflare WARP hop in front of the exit. Null for modes without one

**Scan modes.** `scan.mode` is `local`, `full`, `full_warp` or `dh2048_warp`. See [Scan modes](../README.md#scan-modes) in the main README.

## Materialized views

**`country_operator_snapshot`** is the data behind the map. It has one row per vantage label, mode and ePDG country, with a JSON list of that country's operators. For each operator the list sorts the DH variants into supported, not supported, no success, no response and unknown. There are also merged rows with `mode = 'all'`:

- `vantage_label` set to an ISO3 code: every vantage point in that country, all modes
- `vantage_label = 'all'`: every vantage point and mode

Merged rows use the latest valid answer per server and DH variant. If a server never gave a valid answer, they use its latest result.

**`operator_reachability`** is the data behind the map's geoblocking view. It has one row per operator and vantage country. `seen_from` is the country a probe actually came out of: the WARP hop's country, otherwise the VPN exit's, otherwise the country that was requested. Each row has the number of probes and answers, the answers that came through a VPN or WARP (`vpn_answered`), and a `state`:

- `answers`
- `blocks`: the answer rate is below 10% of the rate from the operator's home country (the rule from MobiSys '24, section 4.2)
- `no_answers`: the operator never answered from anywhere

Any IKE reply counts as an answer, `NO_PROPOSAL_CHOSEN` included. Silence on a DH group that an ePDG doesn't answer from any country isn't counted as blocking.

## Functions

The scanner and orchestrator call these after each ingest. There are no triggers.

| Function | What it does |
|---|---|
| `refresh_latest_snapshot(scan_id)` | replaces the rows in `latest_epdg_result` for the scan's vantage label, mode and DH variant with the scan's results |
| `refresh_collision_keys()` | finds keys used by more than one server (on more than one IP) in `latest_epdg_result` and adds them to `collision_keys` or raises their usage count. Only the host's own `local` scans count, because GeoDNS gives the same ePDG different IPs in different countries |
| `refresh_country_operator_snapshot()` | refreshes `country_operator_snapshot` and `operator_reachability` |

## Analysis

`analysis/006_one_time_manual_key_count_analysis.sql` filled `collision_keys.usage_count` once from the full `epdg_result` history. It isn't a migration. Running it again counts the same keys a second time and inflates the numbers on the collisions page and in the Zulip bot.
