/* global echarts */

(() => {
  const API_KEY = "";

  const API_ORIGIN =
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === "localhost"
      ? "http://127.0.0.1:8000"
      : "";

  const LIMIT = 200;

  let allCollisions = [];     // all collision records.
  let level = 0;              // 0 = variants, 1 = keys per variant, 2 = operators per key.
  let selectedVariant = null;
  let selectedKey = null;
  let chart = null;
  let rankToKey = {};         // keys mapped to their rank (amount of appearances).
  let operatorLastSeen = {};  // operator name mapped to last seen date.

  // fetch all collision keys. In batched pages of size LIMIT if needed.
  async function fetchAllCollisionKeys() {
    const results = [];
    let offset = 0;
    while (true) {
      const url = `${API_ORIGIN}/api/v1/collision-keys?limit=${LIMIT}&offset=${offset}`;
      const resp = await fetch(url, { headers: { "X-API-Key": API_KEY } });
      if (!resp.ok) {
        throw new Error(
          resp.status === 429
            ? "Too many requests — please wait a moment and try again."
            : `HTTP ${resp.status}`
        );
      }
      const page = await resp.json();
      results.push(...page);
      if (page.length < LIMIT) break;
      offset += LIMIT;
    }
    return results;
  }

  // prepare data depending on current level of the chart before/while redrawing.
  function dataForLevel() {
    rankToKey = {};
    // level 0: variants
    if (level === 0) {
      const totals = {};
      for (const r of allCollisions) {
        const v = r.dh_variant || "Unknown";
        totals[v] = (totals[v] || 0) + (r.usage_count || 1);
      }
      return Object.entries(totals)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value);
    }
    // level 1: keys
    if (level === 1) {
      const rows = allCollisions
        .filter(r => (r.dh_variant || "Unknown") === selectedVariant)
        .sort((a, b) => (b.usage_count || 1) - (a.usage_count || 1));
      return rows.map((r, i) => {
        const label = `#${i + 1}`;
        rankToKey[label] = r.key;
        return { name: label, value: r.usage_count || 1, key: r.key };
      });
    }

    // level 2: operators
    const record = allCollisions.find(r => r.key === selectedKey);
    return (record?.operators ?? []).map(op => ({
      name: op,
      value: 1,
      last_seen: operatorLastSeen[op] ?? null
    }));
  }

  //populate the chart depending on the current level and theme (dark/light).
  function chartStyling(data) {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    const textColor = isDark ? "#a0afc0" : "#4f6479";
    const borderColor = isDark ? "#111d2e" : "#ffffff";
    const showLegend = level !== 1;

    const tooltipFormatter = level === 1
      ? p => {
          const key = rankToKey[p.name] || "";
          const trunc = key.length > 20 ? key.slice(0, 20) + "…" : key;
          return `${p.name} · ${trunc}<br/>${p.value} uses (${p.percent}%)`;
        }
      : level === 2
        ? p => {
            const ls = p.data?.last_seen;
            const dateStr = ls ? fmtDate(new Date(ls)) : "never";
            return `${p.name}<br/>Last seen: ${dateStr}`;
          }
        : "{b}: {c} ({d}%)";

    return {
      tooltip: { trigger: "item", formatter: tooltipFormatter },
      legend: {
        show: showLegend,
        top: "5%",
        left: "center",
        textStyle: { color: textColor }
      },
      series: [
        {
          name: level === 0 ? "DH Variant" : level === 1 ? selectedVariant : selectedKey,
          type: "pie",
          radius: ["40%", "70%"],
          avoidLabelOverlap: false,
          itemStyle: { borderRadius: 10, borderColor, borderWidth: 2 },
          label: { show: false, position: "center" },
          emphasis: {
            scale: true,
            scaleSize: 14,
            label: {
              show: true,
              fontSize: 28,
              fontWeight: "bold",
              color: textColor
            }
          },
          labelLine: { show: false },
          data
        }
      ]
    };
  }

  // populate the key list below the chart if level == 1 (keys per variant). hide it otherwise.
  function renderKeyList(data) {
    const keyList = document.getElementById("chart-key-list");
    if (level !== 1) { keyList.hidden = true; return; }
    keyList.hidden = false;
    keyList.innerHTML = "";
    data.forEach(({ name, value, key }) => {
      const row = document.createElement("div");
      row.className = "key-list-row";
      row.innerHTML =
        `<span class="key-rank">${name}</span>` +
        `<span class="key-hex">${key}</span>` +
        `<span class="key-count">${value} <span class="key-count-unit">uses</span></span>`;
      row.addEventListener("click", () => keyDetails(key));
      keyList.appendChild(row);
    });
  }

  // hide breadcrumb if level == 0, show on otherwise.
  function updateBreadcrumb() {
    const breadcrumb = document.getElementById("chart-breadcrumb");
    if (level === 0) { breadcrumb.hidden = true; return; }
    breadcrumb.hidden = false;
    const parts = ["All variants"];
    if (level >= 1) parts.push(selectedVariant);
    if (level >= 2) {
      const short = selectedKey.length > 20 ? selectedKey.slice(0, 20) + "…" : selectedKey;
      parts.push(short);
    }
    breadcrumb.textContent = parts.join(" › ");
  }

  function fmtDate(d) {
    return d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
  }

  // shows key field and last seen date if level == 2, hides it otherwise.
  function updateKeyDisplay() {
    const keyDisplayField = document.getElementById("chart-key-display");
    if (level !== 2) { keyDisplayField.hidden = true; return; }
    keyDisplayField.hidden = false;
    document.getElementById("chart-key-text").textContent = selectedKey;
    const record = allCollisions.find(r => r.key === selectedKey);
    const lsEl = document.getElementById("chart-key-last-seen");
    if (record?.updated_at) {
      lsEl.textContent = `Last seen: ${fmtDate(new Date(record.updated_at))}`;
    } else {
      lsEl.textContent = "";
    }
  }

  function redraw() {
    const data = dataForLevel();
    chart.setOption(chartStyling(data), { notMerge: true });
    renderKeyList(data);
    updateBreadcrumb();
    updateKeyDisplay();
    document.getElementById("chart-hover-hint").hidden = level !== 2;
  }

  async function fetchOperatorLastSeen(key) {
    const headers = { "X-API-Key": API_KEY };
    const encodedKey = encodeURIComponent(key);

    const record = allCollisions.find(r => r.key === key);
    const serverIds = record?.server_ids ?? [];

    const perServer = await Promise.all(
      serverIds.map(async id => {
        const [opResp, resResp] = await Promise.all([
          fetch(`${API_ORIGIN}/api/v1/latest-results?server_id=${id}&limit=1`, { headers }),
          fetch(`${API_ORIGIN}/api/v1/results?key_hex=${encodedKey}&server_id=${id}&limit=200`, { headers }),
        ]);

        const operator = opResp.ok
          ? ((await opResp.json())[0]?.operator ?? null)
          : null;

        let observed_at = null;
        if (resResp.ok) {
          const rows = await resResp.json();
          const latest = rows
            .filter(r => r.observed_at)
            .sort((a, b) => new Date(b.observed_at) - new Date(a.observed_at))[0];
          observed_at = latest?.observed_at ?? null;
        }

        return { operator, observed_at };
      })
    );

    const result = {};
    for (const { operator, observed_at } of perServer) {
      if (!operator || !observed_at) continue;
      if (!result[operator] || new Date(observed_at) > new Date(result[operator])) {
        result[operator] = observed_at;
      }
    }
    return result;
  }

  //level 2
  async function keyDetails(key) {
    selectedKey = key;
    ++level;
    operatorLastSeen = await fetchOperatorLastSeen(key);
    redraw();
  }

  function onSegmentClick(params) {
    if (level === 0) {
      selectedVariant = params.name;
      ++level;
      redraw();
    } else if (level === 1) {
      const key = rankToKey[params.name];
      if (key) keyDetails(key);
    }
  }

  function goBack() {
    if (level === 2) { --level; selectedKey = null; operatorLastSeen = {}; }
    else if (level === 1) { --level; selectedVariant = null; }
    redraw();
  }

  function initChart() {
    const el = document.getElementById("chart");
    chart = echarts.init(el, null, { renderer: "canvas" });
    chart.on("click", onSegmentClick);
    window.addEventListener("resize", () => chart.resize());
    new MutationObserver(() => redraw()).observe(document.documentElement, {
      attributes: true, attributeFilter: ["data-theme"]
    });
  }

  async function init() {
    allCollisions = await fetchAllCollisionKeys();
    initChart();
    redraw();
    document.getElementById("chart-back").addEventListener("click", goBack);
  }

  init().catch(err => {
    document.getElementById("chart").textContent = `Failed to load data: ${err.message}`;
  });
})();
