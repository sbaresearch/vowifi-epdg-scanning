# Backend API (FastAPI)

## Endpoints

- `GET /health` (liveness)
- `GET /ready` (readiness, checks DB connectivity)
- `GET /api/v1/servers`
- `GET /api/v1/servers/{server_id}`
- `GET /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `GET /api/v1/results`
- `GET /api/v1/results/{result_id}`
- `GET /api/v1/latest-results`
- `GET /api/v1/latest-results/{server_id}/{dh_variant}`
- `GET /api/v1/map`
- `GET /api/v1/map/{country}`