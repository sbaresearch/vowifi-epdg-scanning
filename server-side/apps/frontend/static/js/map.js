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

  const WORLD_GEOJSON_DIR = "/static/data/ne_50m_admin_0_countries.json";

  const MAP_STYLE = "https://basemaps.cartocdn.com/gl/positron-gl-style/style.json";

  const DEPRECATED_HANDSHAKES = ["768MODP", "1024MODP", "1536MODP"];
  const HANDSHAKE_RESULTS = ["supported", "not_supported", "no_success", "no_response", "unknown"];

  const COLOR_NO_SCANS = "#f5f5f5";
  const COLOR_NO_SCORED_DATA = "#8f8f8f";
  const COLOR_BORDER = "#0b0b0b";
  const GLOBE_SPACE_COLOR = "#0b1220";

  const _css = getComputedStyle(document.documentElement);
  const COLOR_HIGHLIGHT = _css.getPropertyValue("--map-highlight-color").trim() || "#ffffff";
  const OPACITY_HIGHLIGHT_HOVER = parseFloat(_css.getPropertyValue("--map-highlight-hover-opacity")) || 0.2;
  const OPACITY_HIGHLIGHT_SELECTED = parseFloat(_css.getPropertyValue("--map-highlight-selected-opacity")) || 0.35;

  const SRC_COUNTRIES = "countries";
  const LAYER_FILL = "country-fill";
  const LAYER_LINE = "country-line";
  const LAYER_HIGHLIGHT = "country-highlight";

  const deselectZoomOutFactor = 0.66;

  /* ---------- State ---------- */

  let map = null;
  let popup = null;
  let worldGeoJSON = null;
  let hoveredFeatureId = null;
  let selectedFeatureId = null;
  let preSelectCamera = null;
  let popupCloseHandler = null;

  const mapDataByIso3 = Object.create(null);
  const scoreByIso3 = Object.create(null);
  let popupHandshakeColumns = [];

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

  // Linearly interpolates one RGB channel component.
  function interpolateChannel(a, b, t) {
    return Math.round(a + (b - a) * t);
  }

  // Converts a score in [-1, 1] into a red->yellow->green color shade.
  function colorByScore(score) {
    if (score === null || score === undefined) return COLOR_NO_SCORED_DATA;

    const clamped = Math.max(-1, Math.min(1, score));
    const t = (clamped + 1) / 2;

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

  // Computes a [SW, NE] bounding box from any GeoJSON geometry.
  function bboxFromGeometry(geometry) {
    let minLng = Infinity, minLat = Infinity, maxLng = -Infinity, maxLat = -Infinity;
    function scan(coords) {
      if (typeof coords[0] === "number") {
        if (coords[0] < minLng) minLng = coords[0];
        if (coords[1] < minLat) minLat = coords[1];
        if (coords[0] > maxLng) maxLng = coords[0];
        if (coords[1] > maxLat) maxLat = coords[1];
      } else {
        for (const c of coords) scan(c);
      }
    }
    if (geometry.type === "GeometryCollection") {
      for (const g of geometry.geometries) scan(g.coordinates);
    } else {
      scan(geometry.coordinates);
    }
    return [[minLng, minLat], [maxLng, maxLat]];
  }

  // Clears the selected country highlight and optionally restores the pre-select camera.
  function clearSelected(skipZoom = false) {
    if (selectedFeatureId !== null) {
      map.setFeatureState({ source: SRC_COUNTRIES, id: selectedFeatureId }, { selected: false });
      selectedFeatureId = null;
    }
    if (!skipZoom && preSelectCamera) {
      // map.flyTo({ center: preSelectCamera.center, zoom: preSelectCamera.zoom});
      map.flyTo({ zoom: (map.getZoom() * deselectZoomOutFactor)});
      preSelectCamera = null;
    }
  }

  // Creates a popup at the clicked country.
  function setPopup(html, lngLat) {
    const popupMaxWidth = `${Math.max(420, window.innerWidth - 24)}px`;
    if (popup) {
      popup.off("close", popupCloseHandler);
      popup.remove();
    }
    popupCloseHandler = () => clearSelected();
    popup = new maplibregl.Popup({ closeButton: true, maxWidth: popupMaxWidth })
      .setLngLat(lngLat)
      .setHTML(html)
      .addTo(map);

    popup.on("close", popupCloseHandler);

    const popupRoot = popup.getElement?.();
    if (popupRoot) {
      const templatedRows = popupRoot.querySelectorAll(".new-popup-grid-row[data-grid-template]");
      templatedRows.forEach((row) => {
        const template = row.getAttribute("data-grid-template");
        if (!template) return;
        row.style.gridTemplateColumns = template;
      });
    }

    // Tries to fit large popups inside viewport horizontally.
    requestAnimationFrame(() => {
      if (!popup) return;
      const el = popup.getElement?.();
      if (!el) return;

      el.style.marginLeft = "0px";
      const rect = el.getBoundingClientRect();
      const margin = 8;
      const overflowRight = rect.right - (window.innerWidth - margin);
      const overflowLeft = margin - rect.left;

      let shiftX = 0;
      if (overflowRight > 0) shiftX -= overflowRight;
      if (overflowLeft > 0) shiftX += overflowLeft;

      if (shiftX !== 0) {
        el.style.marginLeft = `${Math.round(shiftX)}px`;
      }
    });
  }

  // Reads raw HTML from an <template> element by ID.
  function getTemplateHtml(templateId) {
    const tpl = document.getElementById(templateId);
    if (!tpl || tpl.tagName !== "TEMPLATE") return "";
    return tpl.innerHTML;
  }

  // Renders a template by replacing {{KEY}} placeholders with provided values.
  function renderTemplate(templateId, replacements) {
    let html = getTemplateHtml(templateId);
    if (!html) return "";

    for (const [key, value] of Object.entries(replacements || {})) {
      html = html.replaceAll(`{{${key}}}`, String(value ?? ""));
    }
    return html;
  }

  /* ---------- Data Loading ---------- */

  // Calls the backend API with the required API key header.
  async function apiFetch(path) {
    return fetch(path, { headers: { "X-API-Key": API_KEY } });
  }

  // Loads map scan data and indexes each country entry by ISO3.
  async function loadCountryApiData() {
    const mapData = await apiFetch(API_BASE);
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

    for (const data of mapDataJSON) {
      if (!data) continue;
      if (typeof data.iso3 !== "string") continue;
      const iso3 = data.iso3.trim().toUpperCase();
      if (!iso3 || iso3 === "-99") continue;
      mapDataByIso3[iso3] = data;
    }
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
  }

  /* ---------- Scoring ---------- */

  // checks if operator has any valid handshakes (according to HANDSHAKE_FIELDS).
  function hasHandshakes(country) {
    if (!country || !Array.isArray(country.operators)) return false;
    return country.operators.some((operator) =>
      operatorHandshakeLists(operator).some((list) => list.length > 0)
    );
  }

  // looks up all deprecated handshakes for an operator and then valus them.
  // deprecated supported rises negative += 1. deprecated not supported raises positive +=1.
  function operatorDeprecatedCounts(operator) {
    const countsByDeprecated = Object.create(null);
    for (const deprecated of DEPRECATED_HANDSHAKES) {
      countsByDeprecated[deprecated] = { positive: 0, negative: 0 };
    }

    for (const supported of asArray(operator?.supported)) {
      const deprecated = isDeprecated(supported);
      if (deprecated) countsByDeprecated[deprecated].negative += 1;
    }

    // no_success should not be relevant. left for downgrade/tolerate later.
    for (const noSuccess of asArray(operator?.no_success)) {
      const deprecated = isDeprecated(noSuccess);
      if (deprecated) countsByDeprecated[deprecated].positive += 1;
    }

    for (const notSupported of asArray(operator?.not_supported)) {
      const deprecated = isDeprecated(notSupported);
      if (deprecated) countsByDeprecated[deprecated].positive += 1;
    }

    return countsByDeprecated;
  }

  // Computes country score from aggregated deprecated-group outcomes across all operators.
  function countryScore(country) {
    if (!country || !Array.isArray(country.operators)) {
      return {
        score: null,
        hasScans: false,
      };
    }

    let positiveCount = 0;
    let negativeCount = 0;

    country.operators.forEach((operator) => {
      const perDeprecated = operatorDeprecatedCounts(operator);

      for (const deprecated of DEPRECATED_HANDSHAKES) {
        positiveCount += perDeprecated[deprecated].positive;
        negativeCount += perDeprecated[deprecated].negative;
      }
    });

    const denom = positiveCount + negativeCount;
    const score = denom > 0 ? (positiveCount - negativeCount) / denom : null;

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

  // Converts internal score range [-1, 1] to a user-facing 1.0-10.0 label.
  function scoreLabel(score) {
    if (score === null || score === undefined) return "N/A";
    const normalized = ((score + 1) / 2) * 9 + 1;
    return `${normalized.toFixed(1)}/10`;
  }

  // determines marks (✓, X, ○, empty) per handshake column for an operator.
  // handshake colums are retriefed from the HTML template. kept for easy adaptability.
  function operatorHandshakeMarks(operator, columns) {
    const operatorResults = Object.create(null);
    for (const col of columns) {
      operatorResults[col] = { success: 0, fail: 0, noResponse: 0 };
    }

    // adds results from handshake list into operator results.
    function add(handshakes, field) {
      for (const handshake of asArray(handshakes)) {
        const normalizedHandshake = handshakeNormaizer(handshake);
        if (!normalizedHandshake || !operatorResults[normalizedHandshake]) continue;
        operatorResults[normalizedHandshake][field] += 1;
      }
    }

    add(operator?.supported, "success");
    // not needed yet but left for downgrade/tolerate.
    add(operator?.no_success, "fail");
    add(operator?.not_supported, "fail");
    add(operator?.no_response, "noResponse");

    const marks = Object.create(null);
    for (const col of columns) {
      const counts = operatorResults[col];
      if (counts.success > 0) marks[col] = "✓";
      else if (counts.fail > 0) marks[col] = "X";
      else if (counts.noResponse > 0) marks[col] = "○";
      else marks[col] = "";
    }
    return marks;
  }

  // translates handshake marks into css objects.
  function markClass(column, mark) {
    if (mark === "○") return "new-popup-mark--no-response";
    const deprecated = DEPRECATED_HANDSHAKES.includes(column);
    if (mark === "✓") return deprecated ? "new-popup-mark--weak-good" : "new-popup-mark--strong-good";
    if (mark === "X") return deprecated ? "new-popup-mark--weak-bad" : "new-popup-mark--strong-bad";
    return "";
  }

  // Builds popup HTML for a country, including score header and per-operator handshake grid.
  function buildPopupHtml(countryName, countryStats, entry) {
    if (!countryStats || !countryStats.hasScans) {
      const html = renderTemplate("tpl-popup-message", {
        COUNTRY: escapeHtml(countryName),
        MESSAGE: "No scans available for this country.",
      });
      if (html) return html;
    }

    const columns = popupHandshakeColumns;
    if (!columns.length) {
      const html = renderTemplate("tpl-popup-message", {
        COUNTRY: escapeHtml(countryName),
        MESSAGE: "No DH handshake columns could be derived from data.",
      });
      if (html) return html;
    }

    const gridTemplate = `minmax(180px,1.8fr) repeat(${columns.length},minmax(90px,1fr))`;
    const headerCells = columns
      .map(
        (col) =>
          `<div class="new-popup-grid-cell new-popup-grid-cell--title">${escapeHtml(col)}</div>`
      )
      .join("");

    let rowsHtml = "";
    const operators = Array.isArray(entry?.operators) ? entry.operators : [];
    operators.forEach((operator, index) => {
      const marks = operatorHandshakeMarks(operator, columns);
      const valueCells = columns
        .map((col) => {
          const mark = marks[col];
          const markClassName = markClass(col, mark);
          const content = mark
            ? `<span class="new-popup-mark ${markClassName}">${mark}</span>`
            : "";
          return `<div class="new-popup-grid-cell new-popup-grid-cell--head">${content}</div>`;
        })
        .join("");

      rowsHtml += renderTemplate("tpl-popup-row", {
        GRID_TEMPLATE: gridTemplate,
        OPERATOR: escapeHtml(getOperatorName(operator, index)),
        VALUE_CELLS: valueCells,
      });
    });

    if (!rowsHtml) {
      rowsHtml = renderTemplate("tpl-popup-row-empty", {
        MESSAGE: "No operators found.",
      });
    }

    const html = renderTemplate("tpl-popup-score", {
      COUNTRY: escapeHtml(countryName),
      SCORE: scoreLabel(countryStats.score),
      GRID_TEMPLATE: gridTemplate,
      HEADER_CELLS: headerCells,
      ROWS: rowsHtml,
    });
    if (html) return html;

    return `<div class="new-popup-fallback">${escapeHtml(countryName)} (${scoreLabel(
      countryStats.score
    )})</div>`;
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

  // Handles country clicks and opens either a data popup or a no-data message popup.
  async function onCountryClick(event) {
    const feature = event.features?.[0];
    if (!feature) return;

    // Save camera before first selection so we can restore it on deselect.
    if (selectedFeatureId === null) {
      preSelectCamera = { center: map.getCenter(), zoom: map.getZoom() };
    }
    clearSelected(true);
    if (feature.id !== undefined) {
      selectedFeatureId = feature.id;
      map.setFeatureState({ source: SRC_COUNTRIES, id: selectedFeatureId }, { selected: true });
    }

    const props = feature.properties || {};
    const iso3 = Iso3FromFeatureProperties(props);

    // Use the full geometry from worldGeoJSON to avoid viewport-clipped geometry
    // which would cause fitBounds to not zoom out for large partially-visible countries.
    const fullFeature = iso3
      ? worldGeoJSON?.features?.find((f) => Iso3FromFeatureProperties(f.properties || {}) === iso3)
      : null;
    const geom = fullFeature?.geometry ?? feature.geometry;
    if (geom) {
      map.fitBounds(bboxFromGeometry(geom), { padding: 120, maxZoom: 6 });
    } else {
      map.flyTo({ center: event.lngLat });
    }
    const countryMapData = iso3 ? mapDataByIso3[iso3] : null;
    const countryName = countryMapData?.country || iso3 || "Unknown";

    if (!countryMapData || !iso3) {
      const html =
        renderTemplate("tpl-popup-message", {
          COUNTRY: escapeHtml(countryName),
          MESSAGE: "No scan data available for this country.",
        }) ||
        `<div class="new-popup-fallback">${escapeHtml(
          countryName
        )}: No scan data available for this country.</div>`;
      setPopup(html, event.lngLat);
      return;
    }

    const score = scoreByIso3[iso3];
    setPopup(buildPopupHtml(countryName, score, countryMapData), event.lngLat);
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

    const legendEl = document.getElementById("map-legend");
    legendEl.className = "mapboxgl-legend top-right";
    legendEl.removeAttribute("hidden");
    mapContainer.appendChild(legendEl);

    // Custom control that toggles the legend panel, styled like the other controls.
    class LegendInfoControl {
      onAdd() {
        this._container = document.createElement("div");
        this._container.className = "maplibregl-ctrl maplibregl-ctrl-group";
        this._btn = document.createElement("button");
        this._btn.type = "button";
        this._btn.className = "legend-info-btn legend-info-btn--active";
        this._btn.title = "Hide legend";
        this._btn.textContent = "i";
        this._btn.addEventListener("click", () => {
          const hidden = legendEl.classList.toggle("legend-hidden");
          this._btn.classList.toggle("legend-info-btn--active", !hidden);
          this._btn.title = hidden ? "Show legend" : "Hide legend";
        });
        this._container.appendChild(this._btn);
        return this._container;
      }
      onRemove() { this._container.remove(); }
    }

    map.addControl(new maplibregl.NavigationControl(), "top-right");
    map.addControl(new maplibregl.GlobeControl(), "top-right");
    map.addControl(new LegendInfoControl(), "top-right");

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

      map.on("click", LAYER_FILL, onCountryClick);

      // Deselect when clicking the map background (outside any country).
      map.on("click", (e) => {
        const hits = map.queryRenderedFeatures(e.point, { layers: [LAYER_FILL] });
        if (hits.length === 0) {
          if (popup) popup.remove();
          clearSelected();
        }
      });
    });
  }

  /* ---------- Boot ---------- */

  // Runs startup: load all data, compute scores/colors, then initialize map rendering.
  async function boot() {
    if (typeof maplibregl === "undefined") {
      throw new Error("MapLibre GL is not available.");
    }

    await loadCountryApiData();
    buildPopupHandshakeColumns();
    await loadWorldGeoJSON();

    saveCountryScores();
    countryColors();
    createMap();
  }

  boot().catch((error) => {
    console.error(error);
    const mapEl = document.getElementById("map");
    if (mapEl) {
      mapEl.innerHTML = `<pre class="map-new-error">${escapeHtml(String(error))}</pre>`;
    }
  });
})();
