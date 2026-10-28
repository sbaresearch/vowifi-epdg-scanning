"""`ip` query filter: a full address matches exactly, a partial one as prefix ('212.95.')."""

from ipaddress import ip_address


# (condition, bind value) for inet `column`, bound as :ip.
def ip_condition(column: str, value: str) -> tuple[str, str]:
    value = value.strip()
    try:
        return f"{column} = CAST(:ip AS inet)", str(ip_address(value))
    except ValueError:
        # host(): address as text, IPv6 in lower-case hex.
        return f"host({column}) ILIKE :ip", f"{value}%"
