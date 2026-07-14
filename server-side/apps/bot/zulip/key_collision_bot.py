import logging, os, sys, zulip
from key_collision import (
    get_all_collision_message,
    get_all_operators_message,
    get_collision_message,
    get_top_collision_keys_message,
)

logger = logging.getLogger(__name__)


def configure_logging(fmt: str) -> None:
    level = logging.getLevelNamesMapping().get(
        os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO
    )
    logging.basicConfig(level=level, format=fmt)


COMMANDS: dict = {}


# selects command functions.
def command(name: str):
    def decorator(fn):
        COMMANDS[name.lower()] = fn
        return fn

    return decorator


# command funtions.


@command("help")
def cmd_help(args, message, client):
    lines = ["**Available commands:**"]
    DESCRIPTIONS = {
        "collisions latest": "`collisions latest` — show key collisions of the LATEST scan results",
        "collisions all": "`collisions all` — show all key collisions over ALL scan results ever recorded",
        "collisions operators": "`collisions operators` — show unique operators that had key collisions over ALL scan results ever recorded",
        "top collision keys": "`top collision keys <n>` — top n keys by usage count (default: 10)",
    }
    for name in sorted(COMMANDS):
        lines.append(f"- {DESCRIPTIONS.get(name, f'`{name}`')}")
    return "\n".join(lines)


@command("ping")
def cmd_ping(args, message, client):
    return "pong"


@command("collisions latest")
def cmd_collisions(args, message, client):
    logger.info("Fetching key collisions...")
    return get_collision_message()


@command("collisions all")
def cmd_collisions(args, message, client):
    logger.info("Fetching all key collisions ever recorded (might take some time)...")
    return get_all_collision_message()


@command("collisions operators")
def cmd_collisions_operators(args, message, client):
    logger.info("Fetching unique operators from all key collisions...")
    return get_all_operators_message()


@command("top collision keys")
def cmd_collisions_top(args, message, client):
    try:
        limit = int(args[0]) if args else 10
    except ValueError:
        return "Usage: `top collision keys <number>` (e.g. `top collision keys 20`)"
    logger.info("Fetching top %d collision keys...", limit)
    return get_top_collision_keys_message(limit)


# watches for messages, runs command functions and sends (chunked) replies.
def handle_message(message: dict, client: zulip.Client) -> None:
    if message.get("type") != "stream":
        return

    bot_email = client.get_profile()["email"]
    content: str = message.get("content", "")

    mention = f"@**{client.get_profile()['full_name']}**"
    if mention in content:
        content = content.replace(mention, "").strip()
    elif f"@{bot_email}" in content:
        content = content.replace(f"@{bot_email}", "").strip()
    else:
        return

    parts = content.split()
    if not parts:
        reply = f"Available commands: {', '.join(sorted(COMMANDS))}."
    else:
        candidates = [" ".join(parts[:i]).lower() for i in range(len(parts), 0, -1)]
        cmd = next((c for c in candidates if c in COMMANDS), None)
        args = parts[len(cmd.split()) :] if cmd else []
        handler = COMMANDS.get(cmd) if cmd else None
        if handler:
            logger.info(
                "Command '%s' from %s (%s)",
                cmd,
                message.get("sender_email"),
                message.get("sender_full_name"),
            )
            reply = handler(args, message, client)
        else:
            logger.warning(
                "Unknown command '%s' from %s",
                cmd,
                message.get("sender_email"),
                message.get("sender_full_name"),
            )
            reply = f"Unknown command: `{cmd}`. Try `help`."

    base = {
        "type": "stream",
        "to": message["display_recipient"],
        "subject": message["subject"],
    }
    chunks = [reply[i : i + 10000] for i in range(0, len(reply), 10000)]
    for i, chunk in enumerate(chunks):
        client.send_message({**base, "content": chunk})
        if len(chunks) > 1:
            logger.debug("Sent chunk %d/%d", i + 1, len(chunks))


if __name__ == "__main__":
    configure_logging("%(asctime)s [%(levelname)s]: %(message)s")

    email = os.getenv("ZULIP_BOT_EMAIL", "").strip()
    api_key = os.getenv("ZULIP_BOT_API_KEY", "").strip()
    site = os.getenv("ZULIP_SERVER_URL", "").strip()

    if not (email and api_key and site):
        logger.warning(
            "Zulip bot is not configured (ZULIP_BOT_EMAIL / ZULIP_BOT_API_KEY / "
            "ZULIP_SERVER_URL are unset); exiting. Set these in .env.secrets and restart the container "
            "to enable it."
        )
        sys.exit(0)

    client = zulip.Client(email=email, api_key=api_key, site=site)
    profile = client.get_profile()
    logger.info("Bot running as: %s", profile["email"])

    client.call_on_each_message(lambda msg: handle_message(msg, client))
