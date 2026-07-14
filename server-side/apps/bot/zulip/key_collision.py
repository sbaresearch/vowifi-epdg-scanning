import json, os, urllib.request

import psycopg2
import psycopg2.extras


def fetch_key_collisions() -> list[dict]:
    base_url = os.environ["API_ORIGIN"].rstrip("/")
    api_key = os.environ["API_KEY"]
    url = f"{base_url}/api/v1/collisions-latest?limit=200"
    req = urllib.request.Request(url, headers={"X-API-Key": api_key})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def fetch_all_key_collisions() -> list[dict]:
    conn = psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "postgres"),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        options="-c statement_timeout=0",
    )
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                WITH distinct_combos AS (
                    SELECT DISTINCT
                        r.key_hex,
                        r.server_id,
                        s.target_ip,
                        s.operator,
                        s.country,
                        sc.dh_variant
                    FROM epdg_result r
                    JOIN scan sc ON sc.id = r.scan_id
                    JOIN epdg_server s ON s.id = r.server_id
                    WHERE r.key_hex IS NOT NULL
                    AND sc.dh_variant NOT IN ('DOWNGRADE_DH2048', 'TOLERATE_DH1024', 'UNKNOWN')
                )
                SELECT
                    key_hex,
                    COUNT(DISTINCT server_id) AS server_count,
                    COUNT(DISTINCT target_ip) AS ip_count,
                    jsonb_agg(
                        jsonb_build_object(
                            'server_id',  server_id,
                            'target_ip',  target_ip,
                            'operator',   operator,
                            'country',    country,
                            'dh_variant', dh_variant
                        )
                        ORDER BY country, operator
                    ) AS servers
                FROM distinct_combos
                GROUP BY key_hex
                HAVING COUNT(DISTINCT server_id) > 1
                AND COUNT(DISTINCT target_ip) > 1
                ORDER BY server_count DESC
            """)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def fetch_top_collision_keys(limit: int) -> list[dict]:
    conn = psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "postgres"),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        options="-c statement_timeout=0",
    )
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT key, usage_count, inserted_at, updated_at
                FROM collision_keys
                ORDER BY usage_count DESC
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def format_collisions(collisions: list[dict]) -> str:
    if not collisions:
        return "No key_hex collisions found."

    lines = [f"**{len(collisions)} key_hex collisions detected**\n"]
    for row in collisions:
        lines.append(f"**Key:** `{row['key_hex']}`")
        lines.append(f"Shared across **{row['server_count']} servers:**")
        lines.append("")
        for s in row["servers"]:
            lines.append(
                f"  - `{s['target_ip']}` | {s['operator']} | {s['country']} | `{s['dh_variant']}`"
            )
        lines.append("")

    return "\n".join(lines)


def format_operators(collisions: list[dict]) -> str:
    if not collisions:
        return "No key_hex collisions found."

    operators: dict[tuple, set] = {}
    for row in collisions:
        for s in row["servers"]:
            key = (s["operator"], s["country"])
            if key not in operators:
                operators[key] = set()
            operators[key].add((s["target_ip"], s["dh_variant"]))

    lines = [
        f"**{len(operators)} unique operators that had key collisions since start of data collection**\n"
    ]
    for (operator, country), ips in sorted(operators.items()):
        ip_parts = ", ".join(f"`{ip}` ({dh})" for ip, dh in sorted(ips))
        lines.append(f"```spoiler **{operator}** ({country})\n{ip_parts}\n```")

    return "\n".join(lines)


def format_top_collision_keys(rows: list[dict], limit: int) -> str:
    if not rows:
        return "No collision keys recorded yet."

    lines = [f"**Top {limit} collision keys by usage**\n"]
    for i, row in enumerate(rows, 1):
        inserted = row["inserted_at"].strftime("%Y-%m-%d %H:%M UTC")
        updated = row["updated_at"].strftime("%Y-%m-%d %H:%M UTC")
        lines.append(
            f"{i}. `{row['key']}` — used **{row['usage_count']}** times | "
            f"first seen {inserted} | last seen {updated}"
        )

    return "\n".join(lines)


def get_collision_message() -> str:
    collisions = fetch_key_collisions()
    return format_collisions(collisions)


def get_all_collision_message() -> str:
    collisions = fetch_all_key_collisions()
    return format_collisions(collisions)


def get_all_operators_message() -> str:
    collisions = fetch_all_key_collisions()
    return format_operators(collisions)


def get_top_collision_keys_message(limit: int = 10) -> str:
    rows = fetch_top_collision_keys(limit)
    return format_top_collision_keys(rows, limit)
