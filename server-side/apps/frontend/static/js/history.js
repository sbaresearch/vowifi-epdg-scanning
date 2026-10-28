/* global echarts */

(() => {
  const API_KEY = "";

  const API_ORIGIN =
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === "localhost"
      ? "http://127.0.0.1:8000"
      : "";

  // dh_variant -> full name + IANA group number, used for labels and strength ordering.
  const DH_GROUPS = {
    "768MODP": { label: "MODP 768", group: 1 },
    "1024MODP": { label: "MODP 1024", group: 2 },
    "1536MODP": { label: "MODP 1536", group: 5 },
    "2048MODP": { label: "MODP 2048", group: 14 },
    "3072MODP": { label: "MODP 3072", group: 15 },
    "4096MODP": { label: "MODP 4096", group: 16 },
    "6144MODP": { label: "MODP 6144", group: 17 },
    "8192MODP": { label: "MODP 8192", group: 18 },
    "256ECP": { label: "ECP 256", group: 19 },
    "384ECP": { label: "ECP 384", group: 20 },
    "512ECP": { label: "ECP 512", group: 21 },
    "192ECP": { label: "ECP 192", group: 25 },
    "224ECP": { label: "ECP 224", group: 26 },
    "X25519": { label: "Curve25519", group: 31 },
  };

  // fallback for any variant not in the table above.
  function describeVariant(variant) {
    if (DH_GROUPS[variant]) return DH_GROUPS[variant];
    const m = /^(\d+)(MODP|ECP)$/.exec(variant);
    const label = m ? `${m[2]} ${m[1]}` : variant;
    return { label, group: m ? Number(m[1]) : 0 };
  }

  const COLOR_SUPPORTED = "#30a353";

  let operators = [];
  let selected = null;          // the chosen operator list item.
  let servers = [];             // server rows for the chosen operator.
  let selectedServerIds = null; // Set of checked server ids, or null while "all" selected.
  let rangeDays = 0;            // 0 = full history.
  let chart = null;
  let lastTimeline = null;      // last rendered timeline response, kept for re-theming.
  let filterTimer = null;       // debounce for rapid server-checkbox toggles.
  const timelineCache = new Map(); // filter signature -> timeline response.

  // one timeline per vantage point and scan mode (WARP probes from a Cloudflare address).
  const SCAN_MODES = [
    { value: "local", label: "Host" },
    { value: "full", label: "VPN" },
    { value: "full_warp", label: "VPN + WARP" },
    { value: "dh2048_warp", label: "VPN + WARP (DH2048 only)" },
  ];
  let selectedVantage = null;   // null = the API's reference vantage point.
  let selectedMode = "local";   // the only mode the reference host records.

  let rateToastTimer = null;
  function showRateLimited() {
    const toast = document.getElementById("rate-toast");
    toast.hidden = false;
    clearTimeout(rateToastTimer);
    rateToastTimer = setTimeout(() => { toast.hidden = true; }, 4000);
  }

  function apiGet(path) {
    // pass the key as a query param (not a header) so these stay simple GETs with no CORS preflight.
    const sep = path.includes("?") ? "&" : "?";
    return fetch(`${API_ORIGIN}/api/v1${path}${sep}api_key=${encodeURIComponent(API_KEY)}`).then((resp) => {
      if (!resp.ok) {
        if (resp.status === 429) showRateLimited();
        throw new Error(
          resp.status === 429
            ? "Too many requests — please wait a moment and try again."
            : `HTTP ${resp.status}`
        );
      }
      return resp.json();
    });
  }

  function fmtDate(d) {
    return d.toLocaleDateString("en-GB", {
      day: "numeric",
      month: "short",
      year: "numeric",
    });
  }

  function fmtDateTime(d) {
    const time = d.toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
    });
    return `${fmtDate(d)}, ${time}`;
  }

  // --- operator picker -------------------------------------------------------

  function renderOperatorList(filter) {
    const list = document.getElementById("operator-list");
    const q = filter.trim().toLowerCase();
    const matches = operators.filter((op) => {
      if (!q) return true;
      const hay = `${op.operator} ${op.network} ${op.country} ${op.mcc} ${op.mnc}`.toLowerCase();
      return hay.includes(q);
    });

    list.innerHTML = "";
    // matches arrive ordered by country then operator, so a header per country change groups them.
    let currentCountry;
    for (const op of matches) {
      if (op.country !== currentCountry) {
        currentCountry = op.country;
        const header = document.createElement("li");
        header.className = "country-header";
        header.textContent = op.country ?? "Unknown country";
        list.appendChild(header);
      }
      const li = document.createElement("li");
      li.className = "history-list-item";
      if (selected && op.mcc === selected.mcc && op.mnc === selected.mnc) {
        li.classList.add("is-active");
      }
      const meta = [op.network, `${op.mcc}-${op.mnc}`].filter(Boolean).join(" · ");
      li.innerHTML =
        `<span class="op-name">${op.operator ?? "Unknown"}</span>` +
        `<span class="op-meta">${meta}</span>`;
      li.addEventListener("click", () => selectOperator(op));
      list.appendChild(li);
    }
  }

  async function selectOperator(op) {
    selected = op;
    selectedServerIds = null;
    renderOperatorList(document.getElementById("operator-search").value);

    const label = op.country ? `${op.operator} (${op.country})` : op.operator;
    document.getElementById("operator-label").textContent = label;
    document.getElementById("range-toggle").hidden = false;
    document.getElementById("legend").hidden = false;

    // cleared first, so the previous operator's IPs can't filter this one's timeline.
    servers = [];
    renderServerChecklist();

    // in parallel: the timeline starts as "all servers" and doesn't need the list.
    const serversLoad = apiGet(
      `/dh-history/servers?mcc=${encodeURIComponent(op.mcc)}&mnc=${encodeURIComponent(op.mnc)}`
    )
      .then((rows) => {
        if (selected !== op) return;
        servers = rows;
        renderServerChecklist();
      })
      .catch((err) => console.warn("could not load servers:", err));
    await Promise.all([serversLoad, loadTimeline()]);
  }

  // --- server checklist ------------------------------------------------------

  function renderServerChecklist() {
    const box = document.getElementById("server-box");
    const list = document.getElementById("server-list");
    list.innerHTML = "";

    if (servers.length <= 1) {
      box.hidden = true;
      return;
    }
    box.hidden = false;

    const allRow = buildCheckRow("all", "All servers", true);
    allRow.querySelector("input").addEventListener("change", (e) => {
      const on = e.target.checked;
      list.querySelectorAll('input[data-server]').forEach((cb) => (cb.checked = on));
      syncSelectedServers();
    });
    list.appendChild(allRow);

    for (const s of servers) {
      const row = buildCheckRow(s.server_id, s.target_ip, true);
      row.querySelector("input").dataset.server = s.server_id;
      row.querySelector("input").addEventListener("change", syncSelectedServers);
      list.appendChild(row);
    }
  }

  function buildCheckRow(id, text, checked) {
    const li = document.createElement("li");
    li.className = "checklist-row";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.id = `srv-${id}`;
    cb.checked = checked;
    const label = document.createElement("label");
    label.setAttribute("for", cb.id);
    label.textContent = text;
    li.append(cb, label);
    return li;
  }

  function syncSelectedServers() {
    const boxes = [...document.querySelectorAll('input[data-server]')];
    const checked = boxes.filter((cb) => cb.checked).map((cb) => cb.dataset.server);
    const allCb = document.getElementById("srv-all");
    allCb.checked = checked.length === boxes.length;

    // null means "all servers" -> the backend aggregates over every IP.
    selectedServerIds = checked.length === boxes.length ? null : new Set(checked);
    // debounce so toggling several IPs in a row collapses into one request.
    clearTimeout(filterTimer);
    filterTimer = setTimeout(loadTimeline, 300);
  }

  // --- timeline --------------------------------------------------------------

  // vantage point and mode are part of the signature (different histories).
  function timelineSig() {
    const ids = selectedServerIds ? [...selectedServerIds].sort().join(",") : "*";
    return `${selected.mcc}-${selected.mnc}|${ids}|${selectedVantage ?? ""}|${selectedMode}`;
  }

  function loadTimeline() {
    if (!selected) return Promise.resolve();
    // an empty selection would otherwise look identical to "all servers" in the request.
    if (selectedServerIds && selectedServerIds.size === 0) {
      showEmpty("No servers selected - pick at least one IP to see its history.");
      return Promise.resolve();
    }
    const sig = timelineSig();

    // reuse an already-fetched filter state; time ranges are applied client-side anyway.
    if (timelineCache.has(sig)) {
      setLoading(false);
      lastTimeline = timelineCache.get(sig);
      renderTimeline(lastTimeline);
      return Promise.resolve();
    }

    const params = new URLSearchParams({ mcc: selected.mcc, mnc: selected.mnc });
    if (selectedServerIds) for (const id of selectedServerIds) params.append("server_id", id);
    if (selectedVantage) params.set("vantage", selectedVantage);
    if (selectedMode) params.set("mode", selectedMode);
    setLoading(true);
    return apiGet(`/dh-history?${params.toString()}`)
      .then((data) => {
        timelineCache.set(sig, data);
        // requests overlap: one for an earlier selection must not overwrite the current one.
        if (sig !== timelineSig()) return;
        setLoading(false);
        lastTimeline = data;
        renderTimeline(data);
      })
      .catch((err) => {
        if (sig === timelineSig()) showEmpty(`Failed to load data: ${err.message}`);
      });
  }

  // dims the current chart until the next one is drawn.
  function setLoading(on) {
    document.querySelector(".history-panel").classList.toggle("is-loading", on);
    document.getElementById("timeline-loading").hidden = !on;
    if (on) document.getElementById("timeline-empty").hidden = true;
  }

  // hide the plot and show a message without destroying the chart instance.
  function showEmpty(message) {
    setLoading(false);
    lastTimeline = null;
    if (chart) chart.clear();
    document.getElementById("timeline").hidden = true;
    document.getElementById("stats").hidden = true;
    document.getElementById("legend").hidden = true;
    const empty = document.getElementById("timeline-empty");
    empty.hidden = false;
    empty.textContent = message;
  }

  // one drawable dot per scan: [rowIndex, ts] plus the state observed at that scan.
  function buildDots(groups, rows) {
    const dots = [];
    groups.forEach((g, rowIndex) => {
      for (const p of g.points) {
        dots.push({
          value: [rowIndex, new Date(p.ts).getTime()],
          state: p.state,
          groupLabel: rows[rowIndex],
        });
      }
    });
    return dots;
  }

  function pointExtent(groups) {
    let minTs = Infinity;
    let maxTs = -Infinity;
    for (const g of groups) {
      for (const p of g.points) {
        const t = new Date(p.ts).getTime();
        if (t < minTs) minTs = t;
        if (t > maxTs) maxTs = t;
      }
    }
    return { minTs, maxTs };
  }

  function renderTimeline(data) {
    const empty = document.getElementById("timeline-empty");
    const el = document.getElementById("timeline");
    if (!data.groups.length) {
      showEmpty(`No successful DH handshake with this operator measured from ${sourceName()}.`);
      return;
    }
    empty.hidden = true;
    el.hidden = false;
    document.getElementById("legend").hidden = false;

    // strongest group on top: sort ascending by group number (ECharts puts index 0 at the bottom).
    const ordered = [...data.groups].sort(
      (a, b) => describeVariant(a.dh_variant).group - describeVariant(b.dh_variant).group
    );
    const rows = ordered.map((g) => describeVariant(g.dh_variant).label);
    const { minTs, maxTs } = pointExtent(ordered);
    const dots = buildDots(ordered, rows);

    // time-range buttons zoom the x-axis relative to the latest scan, keeping every row.
    const span = rangeDays > 0 ? rangeDays * 86400000 : maxTs - minTs;
    const pad = Math.max(span * 0.02, 43200000); // keeps edge dots off the axis bounds.
    const xWindow = rangeDays > 0
      ? { min: maxTs - span - pad, max: maxTs + pad }
      : { min: minTs - pad, max: maxTs + pad };

    if (!chart) initChart();
    el.style.height = `${rows.length * 42 + 72}px`;
    chart.resize();
    chart.setOption(chartOption(rows, dots, xWindow), { notMerge: true });
    renderStats(ordered);
  }

  function chartOption(rows, dots, xWindow) {
    const isDark =
      document.documentElement.getAttribute("data-theme") === "dark";
    const textColor = isDark ? "#a0afc0" : "#4f6479";
    const axisLine = isDark ? "rgba(255,255,255,0.10)" : "rgba(88,112,141,0.16)";
    const unsupported = isDark ? "#5a6b7e" : "#9aa8b8";
    const supported = isDark ? "#3fbf6a" : COLOR_SUPPORTED;

    return {
      grid: { left: 110, right: 24, top: 16, bottom: 40 },
      tooltip: {
        trigger: "item",
        formatter: (p) => {
          const state = p.data.state === "SUPPORTED" ? "Supported" : "Not supported";
          const when = fmtDateTime(new Date(p.value[1]));
          return `<strong>${p.data.groupLabel}</strong><br/>${state}<br/>${when}`;
        },
      },
      xAxis: {
        type: "time",
        min: xWindow.min,
        max: xWindow.max,
        axisLine: { lineStyle: { color: axisLine } },
        axisLabel: { color: textColor },
        splitLine: { show: true, lineStyle: { color: axisLine, type: "dashed" } },
      },
      yAxis: {
        type: "category",
        data: rows,
        axisTick: { show: false },
        axisLine: { lineStyle: { color: axisLine } },
        axisLabel: { color: textColor, fontWeight: 600 },
      },
      series: [
        {
          // one dot per scan, so every point is hoverable with its own timestamp.
          type: "scatter",
          encode: { x: 1, y: 0 },
          data: dots,
          symbolSize: (_value, params) =>
            params.data.state === "SUPPORTED" ? 13 : 7,
          itemStyle: {
            color: (p) => (p.data.state === "SUPPORTED" ? supported : unsupported),
          },
          emphasis: {
            scale: 1.35,
            itemStyle: { borderColor: textColor, borderWidth: 1 },
          },
        },
      ],
    };
  }

  // --- stat tiles ------------------------------------------------------------

  function renderStats(groups) {
    const stats = document.getElementById("stats");
    let minTs = Infinity;
    let maxTs = -Infinity;
    let weakest = null;

    for (const g of groups) {
      const points = g.points
        .map((p) => ({ ts: new Date(p.ts).getTime(), state: p.state }))
        .sort((a, b) => a.ts - b.ts);
      if (!points.length) continue;

      minTs = Math.min(minTs, points[0].ts);
      maxTs = Math.max(maxTs, points[points.length - 1].ts);

      const latest = points[points.length - 1];
      if (latest.state === "SUPPORTED") {
        const info = describeVariant(g.dh_variant);
        if (!weakest || info.group < weakest.group) weakest = info;
      }
    }

    const tiles = [
      ["Current Weakest Group", weakest ? weakest.label : "—"],
      ["History Span", `${fmtDate(new Date(minTs))} – ${fmtDate(new Date(maxTs))}`],
      ["Latest Update", fmtDate(new Date(maxTs))],
    ];

    stats.innerHTML = "";
    for (const [label, value] of tiles) {
      const tile = document.createElement("div");
      tile.className = "stat-tile";
      tile.innerHTML =
        `<span class="stat-label">${label}</span>` +
        `<span class="stat-value">${value}</span>`;
      stats.appendChild(tile);
    }
    stats.hidden = false;
  }

  // --- setup -----------------------------------------------------------------

  function initChart() {
    chart = echarts.init(document.getElementById("timeline"), null, {
      renderer: "canvas",
    });
    window.addEventListener("resize", () => chart.resize());
    new MutationObserver(() => {
      if (lastTimeline) renderTimeline(lastTimeline);
    }).observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
  }

  function wireRangeToggle() {
    const toggle = document.getElementById("range-toggle");
    toggle.querySelectorAll(".segment-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        toggle
          .querySelectorAll(".segment-btn")
          .forEach((b) => b.classList.remove("segment-btn--active"));
        btn.classList.add("segment-btn--active");
        rangeDays = Number(btn.dataset.days);
        // range is a client-side zoom over the already-fetched history, no refetch.
        if (lastTimeline) renderTimeline(lastTimeline);
      });
    });
  }

  // --- source picker ---------------------------------------------------------

  // "Austria (host)", "Germany (surfshark)".
  function placeName(vp) {
    const country = vp.requested_country || vp.label;
    return vp.provider === "none" ? `${country} (host)` : `${country} (${vp.provider})`;
  }

  function modeLabel(mode) {
    return SCAN_MODES.find((m) => m.value === mode)?.label ?? mode;
  }

  function sourceName() {
    const option = document.getElementById("source-select").selectedOptions[0];
    return option ? `${option.textContent}, ${modeLabel(option.dataset.mode)}` : "the scanning host";
  }

  // only vantage point + mode pairs that have scans, the scanning host first.
  // On failure the defaults above stay.
  async function initSourcePicker() {
    let points;
    try {
      const all = await apiGet("/vantage-points");
      points = Array.isArray(all) ? all.filter((vp) => vp && vp.label && vp.scan_count > 0) : [];
    } catch (err) {
      console.warn("could not load vantage points:", err);
      return;
    }

    const select = document.getElementById("source-select");
    for (const scanMode of SCAN_MODES) {
      const sources = points
        .filter((vp) => (vp.modes ?? []).includes(scanMode.value))
        .map((vp) => ({ vp, place: placeName(vp) }))
        .sort((a, b) => a.place.localeCompare(b.place));
      if (!sources.length) continue;
      const group = document.createElement("optgroup");
      group.label = scanMode.label;
      for (const { vp, place } of sources) {
        const option = document.createElement("option");
        option.dataset.vantage = vp.label;
        option.dataset.mode = scanMode.value;
        option.textContent = place;
        if (vp.server_location && scanMode.value === "local") option.selected = true;
        group.appendChild(option);
      }
      select.appendChild(group);
    }
    if (!select.options.length) return;

    const applySource = () => {
      const option = select.selectedOptions[0];
      selectedVantage = option.dataset.vantage;
      selectedMode = option.dataset.mode;
      document.getElementById("source-mode").textContent = modeLabel(selectedMode);
    };
    applySource();
    select.addEventListener("change", () => {
      applySource();
      loadTimeline();
    });
    // no picker for a single choice.
    document.getElementById("source-box").hidden = select.options.length < 2;
  }

  async function init() {
    const [, ops] = await Promise.all([initSourcePicker(), apiGet("/dh-history/operators")]);
    operators = ops;
    renderOperatorList("");
    document
      .getElementById("operator-search")
      .addEventListener("input", (e) => renderOperatorList(e.target.value));
    wireRangeToggle();
  }

  init().catch((err) => {
    document.getElementById("operator-list").textContent = `Failed to load operators: ${err.message}`;
  });
})();
