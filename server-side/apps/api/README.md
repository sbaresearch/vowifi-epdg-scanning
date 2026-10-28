# Backend API

The FastAPI service that serves the scan data to the website, the Zulip bot and anyone downloading the dataset. It runs as `api-backend` on `127.0.0.1:8000`. On the public site, nginx forwards `/api/` to it.

All responses are JSON, apart from the takeout downloads. The API only reads from the database.

## Access

- **API key:** if `API_KEY` (or `API_KEY_FILE`) is set, every route under `/api/v1` needs it, either in the `X-API-Key` header or as the `api_key` query parameter. `/health` and `/ready` are always open.
- **Rate limit:** by default 120 requests per minute per client IP, 300 for `/dh-history`. A client over the limit gets `429` with a `Retry-After` header and is blocked for 60 seconds.
- **Pagination:** list routes take `offset` and `limit` (default 50, at most 200).
- **Docs:** with `ENABLE_DOCS=true` the OpenAPI docs are at `/docs` and `/redoc`.

The settings are listed under [Configuration](../../README.md#configuration) in the main README.

## Vantage points and modes

Most results depend on where they were measured from and how. Routes that need one picture take two parameters:

- `vantage`: a vantage point's label (`austria`, `surfshark-japan`) or the UUID of one of its rows. Defaults to the scanning host.
- `mode`: `full` (default), `full_warp`, `dh2048_warp` or `local`. See [Scan modes](../../README.md#scan-modes).

List routes like `/scans` and `/latest-results` return every vantage point and mode unless you filter by them.

## Endpoints

| Route | Returns | Used by |
|---|---|---|
| `GET /health` | liveness check | |
| `GET /ready` | readiness, including the database connection | |
| `GET /api/v1/servers` | discovered ePDGs | |
| `GET /api/v1/servers/{server_id}` | one ePDG | |
| `GET /api/v1/vantage-points` | one entry per vantage point, with its newest exit, scan count and modes | map, DH history |
| `GET /api/v1/vantage-points/{vantage}` | one vantage point, by label or UUID | |
| `GET /api/v1/vantage-points/{vantage}/exits` | every exit a vantage point has used, newest first | |
| `GET /api/v1/scans` | scan runs, filterable by `vantage` and `mode` | |
| `GET /api/v1/scans/{scan_id}` | one scan run | |
| `GET /api/v1/results` | raw test results, filterable by `scan_id`, `server_id`, `key_hex` and `result` | collisions |
| `GET /api/v1/results/{result_id}` | one test result | |
| `GET /api/v1/latest-results` | the newest result per server, DH variant, vantage point and mode | table, collisions |
| `GET /api/v1/latest-results/{server_id}/{dh_variant}` | one of those, for a given `vantage` and `mode` | |
| `GET /api/v1/all-results` | every result ever recorded | table |
| `GET /api/v1/map` | per country: its operators and which DH variants they support | map |
| `GET /api/v1/map/{country}` | the same for one country, by name | |
| `GET /api/v1/geoblocking` | per country and operator: `geoblocking`, `open`, `home_only` or `no_answers`, plus the blocked countries | map |
| `GET /api/v1/geoblocking/reach` | probes and answers per vantage country for one operator (`country`, `operator`) | map |
| `GET /api/v1/dh-history/operators` | operators with history data | map, DH history |
| `GET /api/v1/dh-history/servers` | an operator's servers (`mcc`, `mnc`) | DH history |
| `GET /api/v1/dh-history` | an operator's DH group support over time (`mcc`, `mnc`, optional `server_id`, `vantage`, `mode`, `observed_from`, `observed_to`) | DH history |
| `GET /api/v1/collision-keys` | IKE keys used by more than one server, by usage count | collisions |
| `GET /api/v1/collisions-latest` | key collisions in the current latest results, with the servers that share each key | Zulip bot |
| `GET /api/v1/takeout/csv` | every table as CSV, zipped | download |
| `GET /api/v1/takeout/sql` | a gzipped `pg_dump` of the database | download |

The takeout files are built after each scan cycle. Until the first one finishes, these routes return `503`.

### Filters on `/latest-results` and `/all-results`

Both take `server_id`, `vantage`, `mode`, `country`, `operator`, `network`, `mcc`, `mnc`, `ip`, `dh_variant`, `exclude_dh_variant`, `result`, `dh_group`, `key_hex`, `observed_from`, `observed_to`, `sort_by` and `sort_dir`. `/latest-results` also takes `iso3`, and `/all-results` takes `scan_id`.

- `ip` matches a complete address exactly and a partial one as a prefix (`212.95.`).
- `vantage` matches a known label or UUID exactly and anything else as part of a label.
- `/map` takes `vantage=all` for every vantage point and mode merged, and `mode=all` for everything measured from the vantage point's country.
