# Database

The core schema is applied automatically on first startup: `compose.yaml` mounts these files into the postgres container's `/docker-entrypoint-initdb.d/`, where they run in order when the data directory (`./epdg-container/postgres`) is still empty:

1. `db/migrations/001_create_tables.sql`
2. `db/migrations/002_create_functions.sql`
3. `db/migrations/003_add_iso3.sql`

Once the database exists, the init scripts never run again. Schema changes against an existing database must be applied manually.

Reset helper (never runs automatically):

- `db/migrations/999_drop_everything.sql`

![Model of the postgres database.](schema/database_diagram.png)
