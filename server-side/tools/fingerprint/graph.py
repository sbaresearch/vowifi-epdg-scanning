#!/usr/bin/env python3

import _csv as csv
import argparse
import json
from datetime import date
from pathlib import Path

from enrich import fetch_all, fetch_asns

SCRIPT_DIR = Path(__file__).parent
CSV_DIR = SCRIPT_DIR / "csv"

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fingerprint Clusters</title>
<style>
:root {
  color-scheme: light;
  --page: #f9f9f7; --surface: #fcfcfb;
  --text-primary: #0b0b0b; --text-secondary: #52514e; --muted: #898781;
  --border: rgba(11,11,11,0.10); --accent: #2a78d6;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --page: #0d0d0d; --surface: #1a1a19;
    --text-primary: #f0efec; --text-secondary: #c3c2b7; --muted: #898781;
    --border: rgba(255,255,255,0.10); --accent: #3987e5;
  }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px 16px; background: var(--page); color: var(--text-primary);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 20px; font-weight: 600; margin: 0 0 4px; }
.sub { color: var(--text-secondary); margin: 0 0 16px; max-width: 75ch; }
.sub b { color: var(--text-primary); font-weight: 600; }
.sub code { font: 12px ui-monospace, Menlo, monospace; }
.note { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
p.sub { margin-bottom: 8px; }
summary { cursor: pointer; color: var(--accent); }
.sub ol { margin: 6px 0 0; padding-left: 20px; }
.sub li + li { margin-top: 4px; }
figure { margin: 0; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px; }
.bar { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; margin: 0 0 8px; }
.bar label { display: flex; gap: 4px; align-items: center; color: var(--text-secondary); font-size: 13px; }
.bar input[type=search] { font: inherit; width: 260px; max-width: 100%; padding: 4px 8px; color: var(--text-primary);
  background: var(--page); border: 1px solid var(--border); border-radius: 6px; }
.hint { color: var(--muted); font-size: 12px; margin: 0 0 0 auto; }
svg { display: block; width: 100%; height: auto; max-height: 85vh; cursor: grab; touch-action: none; }
.fp { fill: var(--text-secondary); fill-opacity: .06; stroke: var(--accent); stroke-width: 1.5; }
.op { fill: none; stroke: var(--muted); stroke-dasharray: 3 2; pointer-events: none; }
.ip { fill: var(--muted); stroke: var(--surface); stroke-width: 1.5; cursor: pointer; }
.ip.hl { fill: var(--accent); }
.fp:hover, .ip:hover { stroke: var(--text-primary); stroke-width: 2; }
.label { font-size: 11px; fill: var(--text-secondary); text-anchor: middle; pointer-events: none;
  paint-order: stroke; stroke: var(--surface); stroke-width: 3px; stroke-linejoin: round; }
.tip { position: fixed; z-index: 10; max-width: 360px; padding: 8px 10px; pointer-events: none;
  background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
  box-shadow: 0 4px 16px rgba(0,0,0,.14); font-size: 12px; color: var(--text-secondary); }
.tip strong { display: block; color: var(--text-primary); font-size: 13px; margin-bottom: 2px; }
.tip[hidden] { display: none; }
</style>
</head>
<body>
<main>
  <h1>Fingerprint clusters</h1>
  <p class="sub"><span id="stats"></span>
    Circles are fingerprints, dots are IPs, and dashed rings group IPs by operator (or AS).
    Hover a dot to light up that operator in every cluster.</p>
  <details class="sub">
    <summary>How the fingerprints are made</summary>
    <ol>
      <li>We take the pcap files from the VoWiFi watchdog pipeline. There's one capture per Diffie-Hellman group
        (14 in total, 768-bit MODP up to X25519), each holding the IKEv2 handshakes with the ePDGs.</li>
      <li>tshark pulls out each ePDG's replies and keeps what the server chose: protocol, encryption, PRF, integrity
        and DH transforms (and the order they come in), attribute types, the key exchange group and the nonce length.
        The nonce itself is random, so only its length counts.</li>
      <li>For every IP, the fields from all 14 captures are joined in DH group order and hashed with MD5.
        That hash is the fingerprint.</li>
      <li>IPs with the same hash answered every test identically, which hints at the same ePDG software and config.
        Only fingerprints shared by two or more IPs are shown below.</li>
    </ol>
  </details>
  <figure>
    <div class="bar">
      <input type="search" list="suggest" placeholder="Search IP or operator" aria-label="Search IP or operator">
      <datalist id="suggest"></datalist>
      <label><input type="checkbox" id="asn"> Group by network (AS)</label>
      <label><input type="checkbox" id="multi"> Hide single-operator, single-AS fingerprints</label>
      <p class="hint">Drag to pan · Ctrl + scroll to zoom · hover for details · click a dot to copy its IP</p>
    </div>
    <svg viewBox="0 0 1000 1000" role="img" aria-label="Packed circles of fingerprint clusters"></svg>
  </figure>
  <p class="note" id="note"></p>
</main>
<div class="tip" hidden></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<script>
const DATA = __DATA__;

const short = h => h.slice(0, 8);
const clusters = Object.entries(DATA.clusters);
document.getElementById("stats").innerHTML =
  `<b>${d3.sum(clusters, ([, ips]) => ips.length)}</b> of the ${DATA.total} IPs in <code>${DATA.source}</code> ` +
  `share their fingerprint with at least one other IP, making up <b>${clusters.length}</b> clusters.`;
document.getElementById("note").textContent = `AS data: ${DATA.asn_source}`;

// suggest operators (alphabetically), then IPs
document.getElementById("suggest").replaceChildren(
  ...[...d3.sort(new Set(Object.values(DATA.operators).flat())), ...Object.keys(DATA.operators)].map(s => new Option(s)));

const tip = document.querySelector(".tip");
function showTip(e, title, lines) {
  const strong = document.createElement("strong");
  strong.textContent = title;
  tip.replaceChildren(strong, ...lines.map(l => Object.assign(document.createElement("div"), {textContent: l})));
  tip.hidden = false;
  moveTip(e);
}
function moveTip(e) {
  const r = tip.getBoundingClientRect();
  tip.style.left = `${e.clientX + 14 + r.width > innerWidth - 8 ? e.clientX - r.width - 14 : e.clientX + 14}px`;
  tip.style.top = `${e.clientY + 14 + r.height > innerHeight - 8 ? e.clientY - r.height - 14 : e.clientY + 14}px`;
}
const hideTip = () => { tip.hidden = true; };

const svg = d3.select("svg");
const g = svg.append("g");
svg.call(d3.zoom().scaleExtent([1, 12])
  .filter(e => e.type === "wheel" ? e.ctrlKey || e.metaKey : !e.button)
  .on("zoom", e => g.attr("transform", e.transform)));

const search = document.querySelector("input[type=search]");
const byAsn = document.getElementById("asn");
const multiOp = document.getElementById("multi");
let dots;

function render() {
  const key = byAsn.checked ? ip => DATA.asns[ip] : ip => DATA.operators[ip].join(", ");
  // a fingerprint has a single operator if one operator is shared by all its IPs
  const shown = multiOp.checked
    ? clusters.filter(([, ips]) => !(DATA.operators[ips[0]].some(op => ips.every(ip => DATA.operators[ip].includes(op))) &&
        ips.every(ip => DATA.asns[ip] === DATA.asns[ips[0]])))
    : clusters;

  // fingerprints > operators (or ASes) > IPs as packed circles, largest fingerprint first
  const root = d3.pack().size([1000, 1000]).padding(d => d.depth ? 2 : 8)(
    d3.hierarchy({children: shown.map(([hash, ips]) => ({hash, children:
        d3.groups(ips, key).map(([group, ips]) => ({group, children: ips.map(ip => ({ip}))}))}))})
      .sum(d => d.ip ? 1 : 0)
      .sort((a, b) => b.value - a.value ||
        d3.ascending(a.data.hash ?? a.data.group ?? a.data.ip, b.data.hash ?? b.data.group ?? b.data.ip)));

  g.selectAll("*").remove();
  g.append("g").selectAll("circle").data(root.children).join("circle")
    .attr("class", "fp").attr("cx", d => d.x).attr("cy", d => d.y).attr("r", d => d.r)
    .on("pointerenter", (e, d) => showTip(e, `Fingerprint ${short(d.data.hash)}`, [`${d.value} IPs`, d.data.hash]))
    .on("pointermove", moveTip).on("pointerleave", hideTip);
  g.append("g").selectAll("circle").data(root.descendants().filter(d => d.depth === 2 && d.value >= 2))
    .join("circle").attr("class", "op").attr("cx", d => d.x).attr("cy", d => d.y).attr("r", d => d.r);
  dots = g.append("g").selectAll("circle").data(root.leaves()).join("circle")
    .attr("class", "ip").attr("cx", d => d.x).attr("cy", d => d.y).attr("r", d => d.r - 1)
    .on("pointerenter", (e, d) => {
      const ops = DATA.operators[d.data.ip], fp = d.parent.parent;
      dots.classed("hl", o => DATA.operators[o.data.ip].some(op => ops.includes(op)));
      showTip(e, d.data.ip, [...(ops.length ? ops : ["Unknown operator"]), DATA.asns[d.data.ip],
        `Fingerprint ${short(fp.data.hash)}, shared with ${fp.value - 1} other IP(s)`]);
    })
    .on("pointermove", moveTip).on("pointerleave", () => { showSearch(); hideTip(); })
    .on("click", (e, d) => navigator.clipboard.writeText(d.data.ip)
      .then(() => { tip.querySelector("strong").textContent = `Copied ${d.data.ip} ✓`; }));
  g.append("g").selectAll("text").data(root.children.filter(d => d.r > 40)).join("text")
    .attr("class", "label").attr("x", d => d.x).attr("y", d => d.y - d.r + 4)
    .text(d => `${short(d.data.hash)} · ${d.value} IPs`);
  showSearch();
}

// highlight IPs and operators matching the search, case-insensitive
function showSearch() {
  const q = search.value.trim().toLowerCase();
  dots.classed("hl", d => q && (d.data.ip.includes(q) || DATA.operators[d.data.ip].some(op => op.toLowerCase().includes(q))));
}
search.addEventListener("input", showSearch);
byAsn.addEventListener("change", render);
multiOp.addEventListener("change", render);
render();
</script>
</body>
</html>
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "hashes", nargs="?", type=Path, help="defaults to the newest csv/hashes_*.csv"
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=SCRIPT_DIR / "fingerprint.html"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    path = args.hashes or max(CSV_DIR.glob("hashes_*.csv"))

    with open(path, newline="") as f:
        hashes = dict(csv.reader(f))

    # fingerprint -> its IPs, for fingerprints shared by 2+ IPs
    clusters = {}
    for ip, h in hashes.items():
        clusters.setdefault(h, []).append(ip)
    clusters = {h: ips for h, ips in clusters.items() if len(ips) > 1}

    # IP -> its operators, from the watchdog API
    operators = {}
    for s in fetch_all("servers"):
        if s["operator"]:
            operators.setdefault(s["target_ip"], set()).add(s["operator"])

    ips = [ip for ips in clusters.values() for ip in ips]
    asns = fetch_asns(ips)
    with open(CSV_DIR / "asns.csv", "w", newline="") as f:
        csv.writer(f, lineterminator="\n").writerows(asns.items())

    data = {
        "source": path.name,
        "total": len(hashes),
        "clusters": clusters,
        "operators": {ip: sorted(operators.get(ip, [])) for ip in ips},
        "asns": asns,
        "asn_source": f"Team Cymru whois on {date.today()}",
    }
    html = HTML.replace("__DATA__", json.dumps(data).replace("</", "<\\/"))
    args.output.write_text(html)
    print(f"{args.output} written.")


if __name__ == "__main__":
    main()
