import json, logging, re
from pathlib import Path
from scanner.common.logging_config import configure_logging

log = logging.getLogger(__name__)
MCC = re.compile(r"\bmcc(\d{3})\b")
MNC = re.compile(r"\bmnc(\d{3})\b")


def normalize(e):
    if not isinstance(e, dict):
        return None

    d = e.get("domain") or ""
    r = e.get("response") or {}
    if not isinstance(r, dict):
        r = {"state": str(r)}

    mcc = MCC.search(d)
    mnc = MNC.search(d)

    out = {
        "timestamp": e.get("timestamp"),
        "domain": d,
        "ip": e.get("ip"),
        "mcc": mcc.group(1) if mcc else None,
        "mnc": mnc.group(1) if mnc else None,
        "state": r.get("state"),
    }
    out.update(r)
    return out


def analyzer(path: Path):
    for i, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        try:
            rec = normalize(json.loads(line))
            if rec:
                log.debug("=== %d ===\n%s", i, json.dumps(rec, indent=2))
        except json.JSONDecodeError:
            log.warning("bad json line %d", i)


if __name__ == "__main__":
    configure_logging("%(message)s")
    analyzer(
        Path(
            "/home/johannes/VoWiFi Project/vowifi-scan-automation/testdata/SUPPORT_DH_768MODP_2026-02-02T15:38:53Z.json"
        )
    )
