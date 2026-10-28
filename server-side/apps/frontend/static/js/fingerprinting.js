/* global d3 */

(() => {
  // static snapshot of tools/fingerprint/graph.py's output from 2026-10-27.
  const DATA_URL = "/static/data/fingerprints.json";

  const svg = d3.select("#fp-chart");
  const g = svg.append("g");
  const tip = document.querySelector(".fp-tip");
  const search = document.getElementById("fp-search");
  const byAsn = document.getElementById("fp-asn");
  const multiOp = document.getElementById("fp-multi");

  let data = null;
  let clusters = [];  // [fingerprint, its IPs] pairs.
  let dots = null;

  const short = (hash) => hash.slice(0, 8);

  function showTip(e, title, lines) {
    const strong = document.createElement("strong");
    strong.textContent = title;
    tip.replaceChildren(strong, ...lines.map((l) => Object.assign(document.createElement("div"), { textContent: l })));
    tip.hidden = false;
    moveTip(e);
  }

  function moveTip(e) {
    const r = tip.getBoundingClientRect();
    tip.style.left = `${e.clientX + 14 + r.width > innerWidth - 8 ? e.clientX - r.width - 14 : e.clientX + 14}px`;
    tip.style.top = `${e.clientY + 14 + r.height > innerHeight - 8 ? e.clientY - r.height - 14 : e.clientY + 14}px`;
  }

  function hideTip() {
    tip.hidden = true;
  }

  // true if one operator is shared by all the fingerprint's IPs and they all sit in the same AS.
  function isSingleOperatorAndAs(ips) {
    const ops = data.operators;
    return ops[ips[0]].some((op) => ips.every((ip) => ops[ip].includes(op))) &&
      ips.every((ip) => data.asns[ip] === data.asns[ips[0]]);
  }

  function render() {
    const key = byAsn.checked ? (ip) => data.asns[ip] : (ip) => data.operators[ip].join(", ");
    const shown = multiOp.checked ? clusters.filter(([, ips]) => !isSingleOperatorAndAs(ips)) : clusters;

    // fingerprints > operators (or ASes) > IPs as packed circles, largest fingerprint first.
    const root = d3.pack().size([1000, 1000]).padding((d) => d.depth ? 2 : 8)(
      d3.hierarchy({ children: shown.map(([hash, ips]) => ({ hash, children:
          d3.groups(ips, key).map(([group, ips]) => ({ group, children: ips.map((ip) => ({ ip })) })) })) })
        .sum((d) => d.ip ? 1 : 0)
        .sort((a, b) => b.value - a.value ||
          d3.ascending(a.data.hash ?? a.data.group ?? a.data.ip, b.data.hash ?? b.data.group ?? b.data.ip)));

    g.selectAll("*").remove();
    g.append("g").selectAll("circle").data(root.children ?? []).join("circle")
      .attr("class", "fp-cluster").attr("cx", (d) => d.x).attr("cy", (d) => d.y).attr("r", (d) => d.r)
      .on("pointerenter", (e, d) => showTip(e, `Fingerprint ${short(d.data.hash)}`, [`${d.value} IPs`, d.data.hash]))
      .on("pointermove", moveTip).on("pointerleave", hideTip);
    g.append("g").selectAll("circle").data(root.descendants().filter((d) => d.depth === 2 && d.value >= 2))
      .join("circle").attr("class", "fp-group").attr("cx", (d) => d.x).attr("cy", (d) => d.y).attr("r", (d) => d.r);
    dots = g.append("g").selectAll("circle").data(root.leaves().filter((d) => d.data.ip)).join("circle")
      .attr("class", "fp-ip").attr("cx", (d) => d.x).attr("cy", (d) => d.y).attr("r", (d) => d.r - 1)
      .on("pointerenter", (e, d) => {
        const ops = data.operators[d.data.ip];
        const fp = d.parent.parent;
        dots.classed("hl", (o) => data.operators[o.data.ip].some((op) => ops.includes(op)));
        showTip(e, d.data.ip, [...(ops.length ? ops : ["Unknown operator"]), data.asns[d.data.ip],
          `Fingerprint ${short(fp.data.hash)}, shared with ${fp.value - 1} other IP(s)`]);
      })
      .on("pointermove", moveTip)
      .on("pointerleave", () => { showSearch(); hideTip(); })
      .on("click", (e, d) => navigator.clipboard.writeText(d.data.ip)
        .then(() => { tip.querySelector("strong").textContent = `Copied ${d.data.ip} ✓`; }));
    g.append("g").selectAll("text").data((root.children ?? []).filter((d) => d.r > 40)).join("text")
      .attr("class", "fp-label").attr("x", (d) => d.x).attr("y", (d) => d.y - d.r + 4)
      .text((d) => `${short(d.data.hash)} · ${d.value} IPs`);
    showSearch();
  }

  // highlight IPs and operators matching the search, case-insensitive.
  function showSearch() {
    const q = search.value.trim().toLowerCase();
    dots.classed("hl", (d) => q && (d.data.ip.includes(q) ||
      data.operators[d.data.ip].some((op) => op.toLowerCase().includes(q))));
  }

  svg.call(d3.zoom().scaleExtent([1, 12])
    .filter((e) => e.type === "wheel" ? e.ctrlKey || e.metaKey
      : e.type.startsWith("touch") ? e.touches.length > 1 : !e.button)
    .on("zoom", (e) => g.attr("transform", e.transform)));

  d3.json(DATA_URL).then((json) => {
    data = json;
    clusters = Object.entries(data.clusters);

    document.getElementById("fp-clustered").textContent = d3.sum(clusters, ([, ips]) => ips.length);
    document.getElementById("fp-total").textContent = data.total;
    document.getElementById("fp-count").textContent = clusters.length;
    document.getElementById("fp-source").textContent = `AS data: ${data.asn_source}.`;

    // suggest operators (alphabetically), then IPs.
    document.getElementById("fp-suggest").replaceChildren(
      ...[...d3.sort(new Set(Object.values(data.operators).flat())), ...Object.keys(data.operators)]
        .map((s) => new Option(s)));

    search.addEventListener("input", showSearch);
    byAsn.addEventListener("change", render);
    multiOp.addEventListener("change", render);
    render();
  }).catch((err) => {
    document.getElementById("fp-stats").textContent = `Could not load the fingerprint data (${err.message}).`;
  });
})();
