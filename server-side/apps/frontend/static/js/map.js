/* global maplibregl */

(() => {
  /* ---------- Config ---------- */

  const API_KEY = "";

  const API_ORIGIN =
    window.location.hostname === "127.0.0.1" ||
      window.location.hostname === "localhost"
      ? "http://127.0.0.1:8000"
      : "";
  const API_BASE = `${API_ORIGIN}/api/v1/map`;
  const VANTAGE_API = `${API_ORIGIN}/api/v1/vantage-points`;
  const OPERATORS_API = `${API_ORIGIN}/api/v1/dh-history/operators`;
  const GEO_API = `${API_ORIGIN}/api/v1/geoblocking`;

  const WORLD_GEOJSON_DIR = "/static/data/ne_50m_admin_0_countries.json";

  const MAP_STYLE = "https://basemaps.cartocdn.com/gl/positron-gl-style/style.json";

  const DEPRECATED_HANDSHAKES = ["768MODP", "1024MODP", "1536MODP"];
  const HANDSHAKE_RESULTS = ["supported", "not_supported", "no_success", "no_response", "unknown"];

  const COLOR_NO_SCANS = "#f5f5f5";
  const COLOR_NO_SCORED_DATA = "#8f8f8f";
  const COLOR_BORDER = "#0b0b0b";
  const COLOR_RED = "rgb(215,55,45)";
  const COLOR_GREEN = "rgb(48,163,83)";
  const GLOBE_SPACE_COLOR = "#0b1220";

  const _css = getComputedStyle(document.documentElement);
  const COLOR_HIGHLIGHT = _css.getPropertyValue("--map-highlight-color").trim() || "#ffffff";
  const OPACITY_HIGHLIGHT_HOVER = parseFloat(_css.getPropertyValue("--map-highlight-hover-opacity")) || 0.2;
  const OPACITY_HIGHLIGHT_SELECTED = parseFloat(_css.getPropertyValue("--map-highlight-selected-opacity")) || 0.35;

  const SRC_COUNTRIES = "countries";
  const LAYER_FILL = "country-fill";
  const LAYER_LINE = "country-line";
  const LAYER_HIGHLIGHT = "country-highlight";
  const LAYER_HOME = "country-home";

  /* ---------- State ---------- */

  let map = null;
  let popup = null;
  let worldGeoJSON = null;
  let hoveredFeatureId = null;
  let selectedFeatureId = null;

  let mapDataByIso3 = Object.create(null);
  let scoreByIso3 = Object.create(null);
  let popupHandshakeColumns = [];

  // all MCCs per country and MNCs per operator ("country|operator") for the popup.
  let mccsByCountry = Object.create(null);
  let mncsByOperator = Object.create(null);

  // Viewed-from location: a country, merging all its vantage points and modes (latest
  // valid answer per server and DH group). MERGED is all of them; the map opens on it.
  const MERGED = "all";
  // DH2048-only locations are left out: no deprecated results, so all would read 0%.
  const DH2048_ONLY_MODE = "dh2048_warp";
  // one per country: { label of any of its vantage points, country name }.
  let locations = [];
  let selectedVantage = MERGED;

  // What the map shows: DH support or geoblocking (004_geoblocking.sql).
  const VIEW_DH = "dh";
  const VIEW_GEO = "geo";
  let view = VIEW_DH;
  // per home country; preloaded after boot (see ensureGeoData).
  let geoDataByIso3 = null;
  let geoDataLoading = null;
  // while one operator's reach map is shown: where it was picked, the operator, its rows.
  let reach = null;
  let countryNames = Object.create(null);
  let viewControl = null;
  let vantageControl = null;
  let reachBanner = null;
  let blockedList = null;

  /* ---------- Helpers ---------- */

  // Escapes HTML-sensitive characters so dynamic text is safe to inject into templates.
  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  // Normalizes any non-array value to an empty array for safe iteration.
  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  // API rows by their country's ISO3; rows without a usable code are skipped.
  function indexByIso3(rows) {
    const byIso3 = Object.create(null);
    for (const row of rows) {
      if (typeof row?.iso3 !== "string") continue;
      const iso3 = row.iso3.trim().toUpperCase();
      if (iso3 && iso3 !== "-99") byIso3[iso3] = row;
    }
    return byIso3;
  }

  // returns an array of arrays. one per handshake status in HANDSHAKE_FIELDS for an operator. empty array if status is missing.
  function operatorHandshakeLists(operator) {
    return HANDSHAKE_RESULTS.map((field) => asArray(operator?.[field]));
  }

  // extracts the first valid ISO3-like code from feature properties and normalizes it. Tries all sorts of ISO3 standards.
  function Iso3FromFeatureProperties(props) {
    const candidates = [
      props?.ISO_A3,
      props?.ADM0_A3,
      props?.ISO_A3_EH,
      props?.SOV_A3,
      props?.GU_A3,
      props?.SU_A3,
    ];

    for (const candidate of candidates) {
      if (typeof candidate === "string" && candidate && candidate !== "-99") {
        return candidate.toUpperCase();
      }
    }
    return null;
  }

  // Uppercases and trims a handshake token and strips the SUPPORT_DH_ prefix if present.
  function normalizeHandshakeToken(token) {
    if (typeof token !== "string") return "";
    let value = token.trim().toUpperCase();
    if (!value) return "";
    if (value.startsWith("SUPPORT_DH_")) {
      value = value.slice("SUPPORT_DH_".length);
    }
    return value;
  }

  // Maps a token to one of the configured weak DH groups if the token references it.
  function isDeprecated(token) {
    const normalized = normalizeHandshakeToken(token);
    for (const deprecated of DEPRECATED_HANDSHAKES) {
      if (normalized === deprecated || normalized.endsWith(`_${deprecated}`) || normalized.includes(deprecated)) {
        return deprecated;
      }
    }
    return null;
  }

  // Keeps only supported DH-like token formats and excludes tolerate/downgrade pseudo tokens.
  function handshakeNormaizer(token) {
    const normalized = normalizeHandshakeToken(token);
    if (!normalized) return null;
    if (normalized.startsWith("TOLERATE_") || normalized.startsWith("DOWNGRADE_")) {
      return null;
    }
    if (/^\d+MODP$/.test(normalized)) return normalized;
    if (/^\d+ECP$/.test(normalized)) return normalized;
    if (/^X\d+$/.test(normalized)) return normalized;
    return null;
  }

  // Selects the operator display name with a stable fallback label.
  function getOperatorName(operator, index) {
    const name = operator?.operator ?? operator?.network;
    if (typeof name === "string" && name.trim()) return name.trim();
    return `Operator ${index + 1}`;
  }

  // Sorted MCCs/MNCs, runs of 3+ shortened: 840, 854, 855, ..., 874 -> "840, 854–874".
  function formatCodes(codes) {
    const sorted = [...codes].filter(Boolean).sort((a, b) => Number(a) - Number(b));
    const parts = [];
    for (let start = 0; start < sorted.length; ) {
      let end = start;
      while (end + 1 < sorted.length && Number(sorted[end + 1]) === Number(sorted[end]) + 1) end += 1;
      if (end - start >= 2) parts.push(`${sorted[start]}–${sorted[end]}`);
      else parts.push(...sorted.slice(start, end + 1));
      start = end + 1;
    }
    return parts.join(", ");
  }

  // Linearly interpolates one RGB channel component.
  function interpolateChannel(a, b, t) {
    return Math.round(a + (b - a) * t);
  }

  // Deprecated-support share [0, 1] -> color: 0 green, 1 red, yellow between.
  function colorByScore(score) {
    if (score === null || score === undefined) return COLOR_NO_SCORED_DATA;

    const t = 1 - Math.max(0, Math.min(1, score));

    const red = { r: 215, g: 55, b: 45 };
    const yellow = { r: 236, g: 188, b: 55 };
    const green = { r: 48, g: 163, b: 83 };

    if (t <= 0.5) {
      const s = t / 0.5;
      return `rgb(${interpolateChannel(red.r, yellow.r, s)},${interpolateChannel(
        red.g,
        yellow.g,
        s
      )},${interpolateChannel(red.b, yellow.b, s)})`;
    }

    const s = (t - 0.5) / 0.5;
    return `rgb(${interpolateChannel(yellow.r, green.r, s)},${interpolateChannel(
      yellow.g,
      green.g,
      s
    )},${interpolateChannel(yellow.b, green.b, s)})`;
  }

  // Highlights one country; clearSelected undoes it.
  function selectFeature(id) {
    if (id === undefined) return;
    selectedFeatureId = id;
    map.setFeatureState({ source: SRC_COUNTRIES, id }, { selected: true });
  }

  // Clears the selected country highlight.
  function clearSelected() {
    if (selectedFeatureId === null) return;
    map.setFeatureState({ source: SRC_COUNTRIES, id: selectedFeatureId }, { selected: false });
    selectedFeatureId = null;
  }

  // Opens the popup above or below the point, wherever there's more room, capped
  // to fit (the card scrolls). Fixed anchor: MapLibre would shift wide popups sideways.
  function setPopup(html, lngLat) {
    const { y } = map.project(lngLat);
    const mapHeight = map.getContainer().clientHeight;
    const above = y >= mapHeight / 2;
    popup = new maplibregl.Popup({ anchor: above ? "bottom" : "top", maxWidth: "none" })
      .setLngLat(lngLat)
      .setHTML(html)
      .addTo(map);
    popup.getElement().style.maxHeight = `${(above ? y : mapHeight - y) - 8}px`;
    popup.on("close", clearSelected);
  }

  // Renders an HTML <template> by replacing its {{KEY}} placeholders.
  function renderTemplate(templateId, replacements) {
    let html = document.getElementById(templateId).innerHTML;
    for (const [key, value] of Object.entries(replacements)) {
      html = html.replaceAll(`{{${key}}}`, String(value ?? ""));
    }
    return html;
  }

  function noDataPopupHtml(countryName) {
    return renderTemplate("tpl-popup-message", {
      COUNTRY: escapeHtml(countryName),
      MESSAGE: "No scan data available for this country.",
    });
  }

  /* ---------- Data Loading ---------- */

  // Calls the backend API with the required API key header.
  async function apiFetch(path) {
    return fetch(path, { headers: { "X-API-Key": API_KEY } });
  }

  // Loads the switcher's locations (one per country, not DH2048-only); failure is non-fatal.
  async function loadVantagePoints() {
    try {
      const response = await apiFetch(VANTAGE_API);
      if (!response.ok) throw new Error(`status ${response.status}`);
      const json = await response.json();
      if (!Array.isArray(json)) throw new Error("unexpected response");
      const byCountry = new Map();
      for (const vp of json) {
        if (!vp?.label || !(vp.scan_count > 0)) continue;
        const key = vp.iso3 || vp.label;
        const location = byCountry.get(key) ??
          { label: vp.label, name: vp.requested_country || vp.label, useful: false };
        location.useful ||= asArray(vp.modes).some((mode) => mode !== DH2048_ONLY_MODE);
        byCountry.set(key, location);
      }
      locations = [...byCountry.values()]
        .filter((location) => location.useful)
        .sort((a, b) => a.name.localeCompare(b.name));
    } catch (error) {
      console.warn("could not load vantage points:", error);
      locations = [];
    }
  }

  // Loads all MCC/MNC pairs per operator; on failure the popup uses the snapshot's.
  async function loadOperatorCodes() {
    try {
      const response = await apiFetch(OPERATORS_API);
      if (!response.ok) throw new Error(`status ${response.status}`);
      const rows = await response.json();
      if (!Array.isArray(rows)) throw new Error("unexpected response");
      for (const row of rows) {
        // trimmed like the snapshot's names, so keys match.
        const country = row?.country?.trim();
        const operator = row?.operator?.trim();
        if (!country || !operator) continue;
        if (row.mcc) (mccsByCountry[country] ??= new Set()).add(row.mcc);
        if (row.mnc) (mncsByOperator[`${country}|${operator}`] ??= new Set()).add(row.mnc);
      }
    } catch (error) {
      console.warn("could not load operator codes:", error);
    }
  }

  // Loads map scan data and indexes each country entry by ISO3.
  async function loadCountryApiData() {
    const params = new URLSearchParams();
    if (selectedVantage) params.set("vantage", selectedVantage);
    // every picture merges all its scan modes.
    params.set("mode", MERGED);
    const query = params.toString();
    const url = query ? `${API_BASE}?${query}` : API_BASE;
    const mapData = await apiFetch(url);
    if (!mapData.ok) {
      throw new Error(
        mapData.status === 429
          ? "Too many requests — please wait a moment and try again."
          : `Failed to load map data (${mapData.status}).`
      );
    }

    const mapDataJSON = await mapData.json();
    if (!Array.isArray(mapDataJSON)) {
      throw new Error("Unexpected API response for /api/v1/map.");
    }

    // rebuilt: no stale countries from the previous vantage point.
    mapDataByIso3 = indexByIso3(mapDataJSON);
    scoreByIso3 = Object.create(null);
  }

  // sorts handshake columns by family/type, numeric strength and lexicographically.
  // to ensure consistant format if db order changes.
  function compareHandshakeTokens(a, b) {
    // parsing token to family (MODP/ECP) and dhEncryptionBitSize.
    function parse(handshake) {
      if (/^\d+MODP$/.test(handshake)) {
        return { family: 1, dhEncryptionBitSize: Number(handshake.slice(0, -4)) };
      }
      if (/^\d+ECP$/.test(handshake)) {
        return { family: 2, dhEncryptionBitSize: Number(handshake.slice(0, -3)) };
      }
      if (/^X\d+$/.test(handshake)) {
        return { family: 3, dhEncryptionBitSize: Number(handshake.slice(1)) };
      }
      return { family: 4, dhEncryptionBitSize: Number.MAX_SAFE_INTEGER };
    }

    const pa = parse(a);
    const pb = parse(b);
    if (pa.family !== pb.family) return pa.family - pb.family;
    if (pa.dhEncryptionBitSize !== pb.dhEncryptionBitSize) return pa.dhEncryptionBitSize - pb.dhEncryptionBitSize;
    return a.localeCompare(b);
  }

  // processes data operator wise and applies sorting to get popup data.
  function buildPopupHandshakeColumns() {
    const popupData = new Set();

    for (const entry of Object.values(mapDataByIso3)) {
      if (!entry || !Array.isArray(entry.operators)) continue;

      for (const operator of entry.operators) {
        for (const handshakeList of operatorHandshakeLists(operator)) {
          for (const handshake of handshakeList) {
            const dhHandshake = handshakeNormaizer(handshake);
            if (dhHandshake) popupData.add(dhHandshake);
          }
        }
      }
    }

    popupHandshakeColumns = Array.from(popupData).sort(compareHandshakeTokens);
  }

  async function loadWorldGeoJSON() {
    const response = await fetch(WORLD_GEOJSON_DIR);
    if (!response.ok) {
      throw new Error(`Failed to load world geojson (${response.status}).`);
    }
    worldGeoJSON = await response.json();

    // names for vantage countries, which need not be in any API row.
    for (const feature of worldGeoJSON?.features ?? []) {
      const iso3 = Iso3FromFeatureProperties(feature.properties || {});
      const name = feature.properties?.NAME ?? feature.properties?.ADMIN;
      if (iso3 && name && !countryNames[iso3]) countryNames[iso3] = name;
    }
  }

  /* ---------- Scoring ---------- */

  // checks if operator has any valid handshakes (according to HANDSHAKE_FIELDS).
  function hasHandshakes(country) {
    if (!country || !Array.isArray(country.operators)) return false;
    return country.operators.some((operator) =>
      operatorHandshakeLists(operator).some((list) => list.length > 0)
    );
  }

  // answered at least one DH group (✓ or X); others are left out of the score.
  function operatorAnswered(operator) {
    return [operator?.supported, operator?.not_supported, operator?.no_success].some((list) =>
      asArray(list).some((token) => handshakeNormaizer(token))
    );
  }

  // how many of the deprecated groups an operator supports (0-3).
  function operatorDeprecatedSupported(operator) {
    return new Set(asArray(operator?.supported).map(isDeprecated).filter(Boolean)).size;
  }

  // Country score 0-1: supported deprecated groups / 3 / operators that answered.
  function countryScore(country) {
    if (!country || !Array.isArray(country.operators)) {
      return {
        score: null,
        hasScans: false,
      };
    }

    const answered = country.operators.filter(operatorAnswered);
    const supportedCount = answered.reduce(
      (sum, operator) => sum + operatorDeprecatedSupported(operator),
      0
    );
    const score = answered.length > 0
      ? supportedCount / DEPRECATED_HANDSHAKES.length / answered.length
      : null;

    return {
      score,
      hasScans: hasHandshakes(country),
    };
  }

  // Computes and stores score metadata for every ISO3 country entry.
  function saveCountryScores() {
    for (const [iso3, entry] of Object.entries(mapDataByIso3)) {
      scoreByIso3[iso3] = countryScore(entry);
    }
  }

  /* ---------- Popup UI ---------- */

  // Share [0, 1] as a whole percentage.
  function scoreLabel(score) {
    if (score === null || score === undefined) return "N/A";
    return `${Math.round(score * 100)}%`;
  }

  // Mark per DH column: ✓ supported, X not supported/no success, ○ no response, blank none.
  function operatorHandshakeMarks(operator) {
    const tokens = (...lists) => new Set(lists.flatMap(asArray).map(handshakeNormaizer));
    const supported = tokens(operator?.supported);
    const refused = tokens(operator?.not_supported, operator?.no_success);
    const noResponse = tokens(operator?.no_response);
    return (column) =>
      supported.has(column) ? "✓" : refused.has(column) ? "X" : noResponse.has(column) ? "○" : "";
  }

  // "Austria (232)": country with its MCCs (snapshot's until the list loads).
  function countryTitle(countryName, entry) {
    const mccs =
      mccsByCountry[entry?.country] ??
      new Set(asArray(entry?.operators).map((operator) => operator?.mcc));
    const codes = formatCodes(mccs);
    return codes ? `${countryName} (${codes})` : countryName;
  }

  // "A1 Telekom Austria (001, 011, 012)": operator with its MNCs (same fallback).
  function operatorLabel(country, operator, index) {
    const name = getOperatorName(operator, index);
    const mncs = mncsByOperator[`${country}|${operator?.operator}`] ?? new Set([operator?.mnc]);
    const codes = formatCodes(mncs);
    return codes ? `${name} (${codes})` : name;
  }

  // tint for deprecated columns (header and cells).
  function deprecatedClass(column) {
    return DEPRECATED_HANDSHAKES.includes(column) ? " new-popup-grid-cell--deprecated" : "";
  }

  // the table's warning sign, replacing ✓ for supported deprecated groups.
  const WARNING_SIGN =
    '<span class="dh-weak-mark" role="img" title="Supports a deprecated DH group" ' +
    'aria-label="Supports a deprecated DH group">!</span>';

  // Popup HTML: title, score, legend, then a row of DH marks per operator.
  function buildPopupHtml(countryName, countryStats, entry) {
    const title = escapeHtml(countryTitle(countryName, entry));
    if (!countryStats?.hasScans) {
      return renderTemplate("tpl-popup-message", {
        COUNTRY: title,
        MESSAGE: "No scans available for this country.",
      });
    }

    // narrow DH columns with slanted names; the operator column takes the rest.
    const columns = popupHandshakeColumns;
    const headerCells = columns
      .map(
        (col) =>
          `<div class="new-popup-grid-cell new-popup-grid-cell--title new-popup-grid-cell--slanted${deprecatedClass(
            col
          )}"><span>${escapeHtml(col)}</span></div>`
      )
      .join("");

    const rows = entry.operators
      .map((operator, index) => {
        const markFor = operatorHandshakeMarks(operator);
        const cells = columns
          .map((col) => {
            const mark = markFor(col);
            // warning sign replaces ✓ here.
            const content =
              mark === "✓" && DEPRECATED_HANDSHAKES.includes(col)
                ? WARNING_SIGN
                : mark ? `<span class="new-popup-mark">${mark}</span>` : "";
            return `<div class="new-popup-grid-cell new-popup-grid-cell--head${deprecatedClass(
              col
            )}">${content}</div>`;
          })
          .join("");
        const label = escapeHtml(operatorLabel(entry.country, operator, index));
        return `<div class="new-popup-grid-row new-popup-grid-row--body"><div class="new-popup-grid-cell new-popup-grid-cell--operator">${label}</div>${cells}</div>`;
      })
      .join("");

    return renderTemplate("tpl-popup-score", {
      COUNTRY: title,
      SCORE: scoreLabel(countryStats.score),
      HEADER_CELLS: headerCells,
      ROWS: rows,
    });
  }

  /* ---------- Map Rendering ---------- */

  // Writes per-feature fill colors into GeoJSON properties based on computed country scores.
  function countryColors() {
    if (!worldGeoJSON?.features) return;

    for (const feature of worldGeoJSON.features) {
      const props = feature.properties || (feature.properties = {});
      const iso3 = Iso3FromFeatureProperties(props);

      if (!iso3) {
        props._fill = COLOR_NO_SCANS;
        continue;
      }

      const stats = scoreByIso3[iso3];

      if (!stats?.hasScans) {
        props._fill = COLOR_NO_SCANS;
        continue;
      }

      props._fill = colorByScore(stats.score);
    }
  }

  // Highlights the country, centers on the click (same zoom), opens its popup.
  function onCountryClick(event) {
    const feature = event.features?.[0];
    if (!feature) return;

    // also clears the previous highlight.
    popup?.remove();
    selectFeature(feature.id);
    map.jumpTo({ center: event.lngLat });

    const iso3 = Iso3FromFeatureProperties(feature.properties || {});

    if (reach) {
      setPopup(buildReachPopupHtml(iso3), event.lngLat);
      return;
    }

    if (view === VIEW_GEO) {
      const entry = iso3 ? geoDataByIso3?.[iso3] : null;
      if (entry) openGeoPopup({ entry, iso3, lngLat: event.lngLat, featureId: feature.id });
      else setPopup(noDataPopupHtml(nameOfCountry(iso3) ?? "Unknown"), event.lngLat);
      return;
    }

    const countryMapData = iso3 ? mapDataByIso3[iso3] : null;
    const countryName = countryMapData?.country || iso3 || "Unknown";
    const html = countryMapData
      ? buildPopupHtml(countryName, scoreByIso3[iso3], countryMapData)
      : noDataPopupHtml(countryName);
    setPopup(html, event.lngLat);
  }

  // Applies globe space background by toggling the css background color.
  function applyGlobeFog() {
    if (!map) return;
    const proj = map.getProjection?.();
    const name = typeof proj === "string" ? proj : (proj?.type ?? proj?.name ?? "mercator");
    map.getContainer().style.backgroundColor = name === "globe" ? GLOBE_SPACE_COLOR : "";
  }

  // Creates the MapLibre instance, layers, controls, and interaction event handlers.
  function createMap() {
    const mapContainer = document.getElementById("map");
    if (!mapContainer) {
      throw new Error('Map cant be loaded.');
    }

    map = new maplibregl.Map({
      container: "map",
      style: MAP_STYLE,
      center: [0, 20],
      zoom: 1.4,
      projection: "mercator",
      antialias: true,
    });

    map.dragRotate.disable();

    const startCollapsed = window.matchMedia("(max-width: 640px)").matches;

    // right column: the legend, and under it the reach map's country list.
    const sideEl = document.createElement("div");
    sideEl.className = "map-side";
    mapContainer.appendChild(sideEl);

    const legendEl = document.getElementById("map-legend");
    legendEl.className =
      "mapboxgl-legend top-right" + (startCollapsed ? " legend-hidden" : "");
    legendEl.removeAttribute("hidden");
    sideEl.appendChild(legendEl);

    // Custom control that toggles the legend panel, styled like the other controls.
    class LegendInfoControl {
      onAdd() {
        this._container = document.createElement("div");
        this._container.className = "maplibregl-ctrl maplibregl-ctrl-group";
        this._btn = document.createElement("button");
        this._btn.type = "button";
        this._btn.className =
          "legend-info-btn" + (startCollapsed ? "" : " legend-info-btn--active");
        this._btn.title = startCollapsed ? "Show legend" : "Hide legend";
        this._btn.textContent = "i";
        this._btn.addEventListener("click", () => {
          this.setHidden(!legendEl.classList.contains("legend-hidden"));
        });
        this._container.appendChild(this._btn);
        return this._container;
      }
      // shared with the legend's own close button, so the info button stays in sync.
      setHidden(hidden) {
        legendEl.classList.toggle("legend-hidden", hidden);
        this._btn.classList.toggle("legend-info-btn--active", !hidden);
        this._btn.title = hidden ? "Show legend" : "Hide legend";
      }
      onRemove() { this._container.remove(); }
    }

    // Picker: merged picture or one country scans ran from.
    class VantageControl {
      onAdd() {
        this._container = document.createElement("div");
        this._container.className =
          "maplibregl-ctrl maplibregl-ctrl-group vantage-ctrl";

        const label = document.createElement("label");
        label.className = "vantage-ctrl-label";
        label.htmlFor = "vantage-select";
        label.textContent = "Scanned from";

        this._select = document.createElement("select");
        this._select.className = "vantage-ctrl-select";
        this._select.id = "vantage-select";
        const merged = document.createElement("option");
        merged.value = MERGED;
        merged.textContent = "All vantage points (merged)";
        merged.selected = selectedVantage === MERGED;
        this._select.appendChild(merged);
        for (const location of locations) {
          const option = document.createElement("option");
          option.value = location.label;
          option.textContent = location.name;
          option.selected = location.label === selectedVantage;
          this._select.appendChild(option);
        }
        this._select.addEventListener("change", () => {
          switchVantage(this._select.value, this._select);
        });

        this._container.append(label, this._select);
        return this._container;
      }
      setHidden(hidden) {
        if (this._container) this._container.hidden = hidden;
      }
      onRemove() { this._container.remove(); }
    }

    // view toggle's top-center slot; narrower, it would collide with the vantage picker.
    const viewSlotEl = document.createElement("div");
    viewSlotEl.className = "view-ctrl-slot";
    mapContainer.appendChild(viewSlotEl);
    const wideScreen = window.matchMedia("(min-width: 901px)");

    // Toggle: DH support or geoblocking, one click each.
    class ViewControl {
      onAdd() {
        // its side position, while the reach banner holds the top center.
        this._corner = mapContainer.querySelector(".maplibregl-ctrl-top-left");
        this._container = document.createElement("div");
        this._container.className =
          "maplibregl-ctrl maplibregl-ctrl-group vantage-ctrl";
        this._container.setAttribute("role", "group");
        this._container.setAttribute("aria-label", "Map view");

        this._buttons = [[VIEW_DH, "DH support"], [VIEW_GEO, "Geoblocking"]].map(([value, text]) => {
          const button = document.createElement("button");
          button.type = "button";
          button.className = "view-ctrl-btn";
          button.dataset.view = value;
          button.textContent = text;
          button.addEventListener("click", () => switchView(value));
          return button;
        });

        this._container.append(...this._buttons);
        this.update();
        return this._container;
      }
      update(busy = false) {
        for (const button of this._buttons ?? []) {
          button.setAttribute("aria-pressed", String(button.dataset.view === view));
          button.disabled = busy;
        }
        this.place();
      }
      place() {
        if (!this._container?.parentElement) return;
        const target = reach === null && wideScreen.matches ? viewSlotEl : this._corner;
        // moving a node blurs it: only when the place changes.
        if (this._container.parentElement !== target) target.prepend(this._container);
      }
      onRemove() { this._container.remove(); }
    }

    viewControl = new ViewControl();
    vantageControl = new VantageControl();
    reachBanner = new ReachBanner(mapContainer);
    blockedList = new BlockedList(sideEl, !startCollapsed);

    map.addControl(new maplibregl.NavigationControl(), "top-right");
    map.addControl(new maplibregl.GlobeControl(), "top-right");
    const legendControl = new LegendInfoControl();
    map.addControl(legendControl, "top-right");
    // the closed legend takes the focus with it: hand it to the button that reopens it.
    legendEl.querySelector(".legend-close").addEventListener("click", () => {
      legendControl.setHidden(true);
      legendControl._btn.focus();
    });
    map.addControl(viewControl, "top-left");
    // always added: the merged picture works without the location list.
    map.addControl(vantageControl, "top-left");
    viewControl.place();
    wideScreen.addEventListener("change", () => viewControl.place());

    // Esc leaves the reach map, like its Back button.
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && reach) exitReach();
    });

    map.on("style.load", applyGlobeFog);
    map.on("projectiontransition", applyGlobeFog);

    map.on("load", () => {
      applyGlobeFog();
      map.addSource(SRC_COUNTRIES, {
        type: "geojson",
        data: worldGeoJSON,
        generateId: true,
      });

      map.addLayer({
        id: LAYER_FILL,
        type: "fill",
        source: SRC_COUNTRIES,
        paint: {
          "fill-color": ["get", "_fill"],
          "fill-opacity": 0.85,
        },
      });

      map.addLayer({
        id: LAYER_LINE,
        type: "line",
        source: SRC_COUNTRIES,
        paint: {
          "line-color": COLOR_BORDER,
          "line-width": 0.55,
        },
      });

      // the operator's home country on its reach map.
      map.addLayer({
        id: LAYER_HOME,
        type: "line",
        source: SRC_COUNTRIES,
        filter: ["==", ["get", "_home"], true],
        paint: {
          "line-color": COLOR_BORDER,
          "line-width": 2.5,
        },
      });

      map.addLayer({
        id: LAYER_HIGHLIGHT,
        type: "fill",
        source: SRC_COUNTRIES,
        paint: {
          "fill-color": COLOR_HIGHLIGHT,
          "fill-opacity": [
            "case",
            ["boolean", ["feature-state", "selected"], false], OPACITY_HIGHLIGHT_SELECTED,
            ["boolean", ["feature-state", "hover"], false], OPACITY_HIGHLIGHT_HOVER,
            0,
          ],
        },
      });

      map.on("mousemove", LAYER_FILL, (e) => {
        map.getCanvas().style.cursor = "pointer";
        const id = e.features?.[0]?.id;
        if (id === hoveredFeatureId) return;
        if (hoveredFeatureId !== null) {
          map.setFeatureState({ source: SRC_COUNTRIES, id: hoveredFeatureId }, { hover: false });
        }
        hoveredFeatureId = id ?? null;
        if (hoveredFeatureId !== null) {
          map.setFeatureState({ source: SRC_COUNTRIES, id: hoveredFeatureId }, { hover: true });
        }
      });

      map.on("mouseleave", LAYER_FILL, () => {
        map.getCanvas().style.cursor = "";
        if (hoveredFeatureId !== null) {
          map.setFeatureState({ source: SRC_COUNTRIES, id: hoveredFeatureId }, { hover: false });
          hoveredFeatureId = null;
        }
      });

      // a click off every country closes the reach map, without reopening a popup.
      // Registered first: the country handler below recenters, which moves event.point.
      map.on("click", (event) => {
        if (reach && !map.queryRenderedFeatures(event.point, { layers: [LAYER_FILL] }).length) {
          exitReach({ reopen: false });
        }
      });

      // clicks elsewhere close the popup (closeOnClick), which clears the highlight.
      map.on("click", LAYER_FILL, onCountryClick);
    });
  }

  /* ---------- Vantage switching ---------- */

  function switchVantage(label, selectEl) {
    if (!label || label === selectedVantage) return Promise.resolve();
    const previous = selectedVantage;
    selectedVantage = label;
    return reloadView(selectEl, () => {
      selectedVantage = previous;
    });
  }

  // Reloads data for another vantage point and repaints in place (camera kept);
  // `restore` reverts the caller's state if the reload fails.
  async function reloadView(selectEl, restore) {
    if (selectEl) selectEl.disabled = true;

    try {
      // the open popup is stale.
      popup?.remove();

      await loadCountryApiData();
      buildPopupHandshakeColumns();
      saveCountryScores();
      countryColors();

      map.getSource(SRC_COUNTRIES)?.setData(worldGeoJSON);
      updateLegendVantage();
    } catch (error) {
      console.error(error);
      // back to the last working view.
      restore();
      if (selectEl) selectEl.value = selectedVantage;
    } finally {
      if (selectEl) selectEl.disabled = false;
    }
  }

  // Names the active location in the legend (unambiguous screenshots).
  function updateLegendVantage() {
    const target = document.getElementById("legend-vantage");
    if (!target) return;
    target.textContent =
      selectedVantage === MERGED
        ? "All vantage points, merged"
        : locations.find((location) => location.label === selectedVantage)?.name ?? "";
    target.parentElement?.toggleAttribute("hidden", !target.textContent);
  }

  /* ---------- Geoblocking ---------- */

  // operator states, worst first: a country takes its worst operator's (geoCountryState).
  const GEO_STATES = ["geoblocking", "vpn_blocking", "open", "home_only", "no_answers"];

  const GEO_COLORS = {
    geoblocking: COLOR_RED,
    // red as well: any geoblocking indication; only the warning mark sets it apart.
    vpn_blocking: COLOR_RED,
    open: COLOR_GREEN,
    // nothing scanned from abroad yet: shown like no scans.
    home_only: COLOR_NO_SCANS,
    no_answers: COLOR_NO_SCORED_DATA,
  };

  // vantage country fill on one operator's reach map.
  const REACH_COLORS = {
    blocks: COLOR_RED,
    answers: COLOR_GREEN,
    no_answers: COLOR_NO_SCORED_DATA,
  };

  // mark per operator state (map.css .geo-mark--*).
  const GEO_MARKS = {
    geoblocking: "blocks",
    vpn_blocking: "warn",
    open: "answers",
    home_only: "home",
    no_answers: "none",
  };

  // for operators that answered only the host's direct scans (vpn_silent).
  const VPN_NOTE =
    "Never answers through VPN or WARP, so it may block those addresses rather than countries.";
  const VPN_WARNING = `\u26A0\uFE0E ${VPN_NOTE}`;

  // decorative: the text next to it says the same.
  function geoMark(kind) {
    return `<span class="geo-mark geo-mark--${kind}" aria-hidden="true"></span>`;
  }

  function nameOfCountry(iso3) {
    return iso3 ? countryNames[iso3] ?? iso3 : null;
  }

  // "1 country", "3 countries".
  function countText(count, one, many) {
    return `${count} ${count === 1 ? one : many}`;
  }

  async function loadGeoData() {
    const response = await apiFetch(GEO_API);
    if (!response.ok) {
      throw new Error(
        response.status === 429
          ? "Too many requests — please wait a moment and try again."
          : `Failed to load geoblocking data (${response.status}).`
      );
    }
    const rows = await response.json();
    if (!Array.isArray(rows)) {
      throw new Error("Unexpected API response for /api/v1/geoblocking.");
    }
    geoDataByIso3 = indexByIso3(rows);
  }

  // one request, shared by the preload after boot and the first switch.
  function ensureGeoData() {
    geoDataLoading ??= loadGeoData().catch((error) => {
      geoDataLoading = null;
      throw error;
    });
    return geoDataLoading;
  }

  // geoblocking, yet silent to every VPN and WARP scan: likely blocks those addresses instead.
  function operatorState(operator) {
    return operator?.state === "geoblocking" && operator?.vpn_silent ? "vpn_blocking" : operator?.state;
  }

  function stateRank(state) {
    const rank = GEO_STATES.indexOf(state);
    return rank < 0 ? GEO_STATES.length : rank;
  }

  function geoCountryState(entry) {
    const ranks = asArray(entry?.operators).map((operator) => stateRank(operatorState(operator)));
    return GEO_STATES[Math.min(GEO_STATES.length - 1, ...ranks)];
  }

  // "blocks 27 of 28 countries": always the operator doing it.
  function geoStatus(operator) {
    const blocks = asArray(operator?.blocks).length;
    const answers = operator?.answers ?? 0;
    switch (operator?.state) {
      case "geoblocking":
        return `blocks ${blocks} of ${countText(blocks + answers, "country", "countries")}`;
      case "open":
        return `answers to ${countText(answers, "country", "countries")}`;
      case "home_only":
        return "only scanned at home";
      default:
        return "never answers";
    }
  }

  function geoSummaryHtml(entry) {
    const operators = asArray(entry?.operators);
    const state = geoCountryState(entry);
    const total = countText(operators.length, "operator", "operators");
    const count = (of) => operators.filter((operator) => operatorState(operator) === of).length;
    const text = {
      geoblocking: `${count("geoblocking")} of ${total} geoblock`,
      vpn_blocking: `${count("vpn_blocking")} of ${total} may only block VPN and WARP`,
      open: "No operator geoblocks",
      home_only: "Only scanned at home",
      no_answers: "No operator answers",
    }[state];
    return `${geoMark(GEO_MARKS[state])}<span>${escapeHtml(text)}</span>`;
  }

  // Popup: one row per operator, geoblocking ones first; a row opens its reach map.
  function buildGeoPopupHtml(entry, iso3) {
    const rows = asArray(entry.operators)
      .map((operator, index) => ({ operator, index, state: operatorState(operator) }))
      .sort(
        (a, b) =>
          stateRank(a.state) - stateRank(b.state) ||
          String(a.operator?.operator ?? "").localeCompare(String(b.operator?.operator ?? ""))
      )
      .map(({ operator, index, state }) => {
        const title = state === "vpn_blocking" ? `${VPN_NOTE} Show where it answers.` : "Show where it answers";
        return (
          `<button type="button" class="geo-row" data-index="${index}" title="${escapeHtml(title)}">` +
          geoMark(GEO_MARKS[state] ?? "none") +
          `<span class="geo-row-name">${escapeHtml(operatorLabel(entry.country, operator, index))}</span>` +
          `<span class="geo-row-status">${escapeHtml(geoStatus(operator))}</span>` +
          `<span class="geo-row-go" aria-hidden="true">›</span></button>`
        );
      })
      .join("");

    return renderTemplate("tpl-popup-geoblocking", {
      COUNTRY: escapeHtml(countryTitle(entry.country || nameOfCountry(iso3), entry)),
      SUMMARY: geoSummaryHtml(entry),
      ROWS: rows,
    });
  }

  // origin: { entry, iso3, lngLat, featureId } of the home country clicked.
  function openGeoPopup(origin) {
    setPopup(buildGeoPopupHtml(origin.entry, origin.iso3), origin.lngLat);
    popup.getElement().addEventListener("click", (clickEvent) => {
      const button = clickEvent.target.closest(".geo-row");
      if (button) showReach(origin, origin.entry.operators[Number(button.dataset.index)], button);
    });
  }

  // "A1 Telekom Austria blocks Germany" / "0 of 4 scans answered".
  function buildReachPopupHtml(iso3) {
    const row = iso3 ? reach.bySeenFrom[iso3] : null;
    const home = iso3 !== null && iso3 === reach.entry.iso3;
    const country = nameOfCountry(iso3) ?? "Unknown";
    const name = getOperatorName(reach.operator, 0);

    let mark = "";
    let text = "Not scanned from here yet";
    let detail = "";
    if (row) {
      detail = `${row.answered} of ${countText(row.probes, "scan", "scans")} answered`;
      if (row.state === "answers") {
        mark = geoMark("answers");
        text = `${name} answers to ${country}`;
      } else if (row.state === "no_answers") {
        mark = geoMark("none");
        text = `${name} never answers`;
      } else {
        mark = geoMark("blocks");
        text = home ? "No answer at home" : `${name} blocks ${country}`;
      }
    }

    return renderTemplate("tpl-popup-reach", {
      COUNTRY: escapeHtml(home ? `${country}, home country` : country),
      VERDICT: `${mark}<span>${escapeHtml(text)}</span>`,
      DETAIL: escapeHtml(detail),
    });
  }

  // fill in the geoblocking views: one operator's reach map, else the overview.
  function geoFill(iso3) {
    if (reach) {
      const row = iso3 ? reach.bySeenFrom[iso3] : null;
      return (row && REACH_COLORS[row.state]) || COLOR_NO_SCANS;
    }
    const entry = iso3 ? geoDataByIso3?.[iso3] : null;
    return entry ? GEO_COLORS[geoCountryState(entry)] : COLOR_NO_SCANS;
  }

  // Repaints for the current view; only the reach map outlines a home country.
  function applyColors() {
    if (view === VIEW_DH) countryColors();
    for (const feature of worldGeoJSON?.features ?? []) {
      const props = feature.properties || (feature.properties = {});
      const iso3 = Iso3FromFeatureProperties(props);
      props._home = reach !== null && iso3 === reach.entry.iso3;
      if (view === VIEW_GEO) props._fill = geoFill(iso3);
    }
    map?.getSource(SRC_COUNTRIES)?.setData(worldGeoJSON);
  }

  // Banner over one operator's reach map, top center: controls only sit in corners.
  class ReachBanner {
    constructor(parent) {
      this._container = document.createElement("div");
      this._container.className = "reach-banner";
      this._container.setAttribute("role", "status");

      const line = document.createElement("div");
      line.className = "reach-banner-row";
      this._mark = document.createElement("span");
      this._mark.setAttribute("aria-hidden", "true");
      this._name = document.createElement("span");
      this._name.className = "reach-banner-name";
      this._status = document.createElement("span");
      this._status.className = "reach-banner-status";

      const back = document.createElement("button");
      back.type = "button";
      back.className = "reach-banner-back";
      back.textContent = "Back";
      back.title = "Back to the overview (Esc)";
      back.addEventListener("click", () => exitReach());
      line.append(this._mark, this._name, this._status, back);

      this._note = document.createElement("div");
      this._note.className = "reach-banner-note";
      this._note.textContent = VPN_WARNING;

      this._container.append(line, this._note);
      parent.appendChild(this._container);
      this.update();
    }
    update() {
      this._container.hidden = reach === null;
      if (!reach) return;
      const { operator } = reach;
      const name = getOperatorName(operator, 0);
      const state = operatorState(operator);
      this._container.style.setProperty("--reach-accent", GEO_COLORS[state] ?? COLOR_NO_SCORED_DATA);
      this._mark.className = `geo-mark geo-mark--${GEO_MARKS[state] ?? "none"}`;
      this._name.textContent = name;
      this._name.title = `${name}, ${reach.entry.country}`;
      this._status.textContent = geoStatus(operator);
      this._note.hidden = !operator?.vpn_silent;
    }
  }

  // one item per name; two columns from 9 names on, filled top to bottom.
  function fillCountryList(list, names) {
    list.replaceChildren(
      ...names.map((name) => {
        const item = document.createElement("li");
        item.textContent = name;
        return item;
      })
    );
    const gridRows = names.length > 8 ? Math.ceil(names.length / 2) : names.length;
    list.style.gridTemplateRows = `repeat(${gridRows}, auto)`;
  }

  // Countries the reach map's operator blocks, then where it answers; `open` is false on phones, like the legend.
  class BlockedList {
    constructor(parent, open) {
      this._container = document.createElement("details");
      this._container.className = "blocked-list";
      this._container.open = open;
      this._title = document.createElement("summary");
      this._note = document.createElement("p");
      this._note.className = "blocked-list-note";
      this._note.textContent = VPN_WARNING;
      this._list = document.createElement("ul");
      this._answersTitle = document.createElement("p");
      this._answersTitle.className = "blocked-list-subhead";
      this._answersList = document.createElement("ul");
      this._container.append(this._title, this._note, this._list, this._answersTitle, this._answersList);
      parent.appendChild(this._container);
      this.update();
    }
    update() {
      const names = (iso3s) =>
        iso3s
          .map((iso3) => {
            const name = nameOfCountry(iso3);
            return iso3 === reach.entry.iso3 ? `${name}, home country` : name;
          })
          .sort((a, b) => a.localeCompare(b));
      const blocks = reach ? names(asArray(reach.operator?.blocks)) : [];
      const answers = reach
        ? names(
            Object.values(reach.bySeenFrom)
              .filter((row) => row.state === "answers")
              .map((row) => row.seen_from)
          )
        : [];
      this._container.hidden = !blocks.length && !answers.length;
      if (this._container.hidden) return;

      const heading = (mark, text) => `${geoMark(mark)}<span>${escapeHtml(text)}</span>`;
      const answersHeading = heading("answers", `Answers to ${countText(answers.length, "country", "countries")}`);
      const vpnSilent = blocks.length > 0 && Boolean(reach.operator?.vpn_silent);
      this._note.hidden = !vpnSilent;
      // blocks nothing: the answering countries are the whole list.
      this._title.innerHTML = blocks.length
        ? heading(vpnSilent ? "warn" : "blocks", `Blocks ${countText(blocks.length, "country", "countries")}`)
        : answersHeading;
      fillCountryList(this._list, blocks.length ? blocks : answers);

      const extra = blocks.length ? answers : [];
      this._answersTitle.hidden = this._answersList.hidden = extra.length === 0;
      this._answersTitle.innerHTML = answersHeading;
      fillCountryList(this._answersList, extra);
    }
  }

  // Legend block, toggle, vantage picker, banner and list for the current view.
  function updateViewUi() {
    document.getElementById("legend-dh").hidden = view !== VIEW_DH;
    document.getElementById("legend-geo").hidden = view !== VIEW_GEO || reach !== null;
    document.getElementById("legend-reach").hidden = reach === null;
    // geoblocking merges every vantage point.
    vantageControl?.setHidden(view !== VIEW_DH);
    viewControl?.update();
    reachBanner?.update();
    blockedList?.update();
  }

  // the active button again leaves a reach map for its overview.
  async function switchView(next) {
    if (next === view) {
      if (reach) exitReach();
      return;
    }
    viewControl?.update(true);

    try {
      popup?.remove();
      if (next === VIEW_GEO) await ensureGeoData();
      view = next;
      reach = null;
      applyColors();
    } catch (error) {
      // the last working view stays.
      console.error(error);
    } finally {
      updateViewUi();
    }
  }

  // Recolors the map by where one operator answers.
  async function showReach(origin, operator, button) {
    if (!operator) return;
    if (button) button.disabled = true;

    try {
      const params = new URLSearchParams({ country: origin.entry.country, operator: operator.operator });
      const response = await apiFetch(`${GEO_API}/reach?${params}`);
      if (!response.ok) {
        throw new Error(`Failed to load reach data (${response.status}).`);
      }
      const rows = asArray(await response.json());
      // counts from these rows: banner and list match the colors after a refresh.
      reach = {
        ...origin,
        operator: {
          ...operator,
          blocks: rows.filter((row) => row.state === "blocks").map((row) => row.seen_from),
          answers: rows.filter((row) => row.state === "answers").length,
        },
        bySeenFrom: Object.fromEntries(rows.map((row) => [row.seen_from, row])),
      };
      popup?.remove();
      applyColors();
      updateViewUi();
    } catch (error) {
      // the overview stays as it was.
      console.error(error);
    } finally {
      if (button) button.disabled = false;
    }
  }

  // Back to the overview; reopen: the home country's popup, to pick the next operator.
  function exitReach({ reopen = true } = {}) {
    if (!reach) return;
    const { entry, iso3, lngLat, featureId } = reach;
    reach = null;
    popup?.remove();
    applyColors();
    updateViewUi();
    if (!reopen) return;

    selectFeature(featureId);
    map.jumpTo({ center: lngLat });
    openGeoPopup({ entry, iso3, lngLat, featureId });
  }

  /* ---------- Boot ---------- */

  // Runs startup: load all data, compute scores/colors, then initialize map rendering.
  async function boot() {
    if (typeof maplibregl === "undefined") {
      throw new Error("MapLibre GL is not available.");
    }

    // not awaited: only popup labels need it, with a fallback until loaded.
    loadOperatorCodes();
    await loadVantagePoints();
    await loadCountryApiData();
    buildPopupHandshakeColumns();
    await loadWorldGeoJSON();

    saveCountryScores();
    countryColors();
    createMap();
    updateLegendVantage();

    // not awaited: makes the first switch to geoblocking instant.
    ensureGeoData().catch((error) => console.warn("geoblocking data not preloaded:", error));
  }

  boot().catch((error) => {
    console.error(error);
    const mapEl = document.getElementById("map");
    if (mapEl) {
      mapEl.innerHTML = `<pre class="map-new-error">${escapeHtml(String(error))}</pre>`;
    }
  });
})();
