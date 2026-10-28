/* global agGrid */

(() => {
  const API_KEY = "";
  
  const API_ORIGIN =
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === "localhost"
      ? "http://127.0.0.1:8000"
      : "";
  const BLOCK_SIZE = 100;
  // a probe, not a DH group offer; left out, as in the history and collision views.
  const EXCLUDED_DH_VARIANT = "DOWNGRADE_DH2048";
  let currentMode = "latest";


  // Status bar
  

  const statusEl = document.getElementById("tableStatus");

  function setStatus(message, isError = false) {
    if (!statusEl) return;
    statusEl.textContent = message;
    statusEl.classList.toggle("table-note-error", isError);
  }

  
  // Formatters
  

  function formatDate(value) {
    if (!value) return "";
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
  }


  // Filterung


  function applyFilters(params, filterModel) {
    const textFields = ["country", "operator", "network", "dh_variant", "key_hex", "mcc", "mnc", "result"];
    for (const field of textFields) {
      const f = filterModel[field];
      if (f?.filterType === "text" && f.filter?.trim()) {
        let val = f.filter.trim();
        if (field === "result") val = val.toUpperCase();
        // MNCs are stored zero-padded ("10" -> "010").
        if (field === "mnc") val = val.padStart(3, "0");
        params.set(field, val);
      }
    }

    // API param "vantage" (label or uuid), not the column name.
    const vantage = filterModel.vantage_label;
    if (vantage?.filterType === "text" && vantage.filter?.trim()) {
      params.set("vantage", vantage.filter.trim());
    }

    // server address; API param "ip".
    const ip = filterModel.target_ip;
    if (ip?.filterType === "text" && ip.filter?.trim()) {
      params.set("ip", ip.filter.trim());
    }

    const dhGroup = filterModel.dh_group;
    if (dhGroup?.filterType === "number" && dhGroup.filter != null) {
      params.set("dh_group", String(dhGroup.filter));
    }

    const obs = filterModel.observed_at;
    if (obs?.filterType === "date") {
      const { type, dateFrom, dateTo } = obs;
      if (type === "equals" && dateFrom) {
        params.set("observed_from", `${dateFrom}T00:00:00`);
        params.set("observed_to",   `${dateFrom}T23:59:59`);
      } else if ((type === "greaterThan" || type === "greaterThanOrEqual") && dateFrom) {
        params.set("observed_from", `${dateFrom}T00:00:00`);
      } else if ((type === "lessThan" || type === "lessThanOrEqual") && dateFrom) {
        params.set("observed_to", `${dateFrom}T23:59:59`);
      } else if (type === "inRange" && dateFrom && dateTo) {
        params.set("observed_from", `${dateFrom}T00:00:00`);
        params.set("observed_to",   `${dateTo}T23:59:59`);
      }
    }
  }

  
  // Sort (API supports single column sort)
  

  function applySort(params, sortModel) {
    if (sortModel.length > 0) {
      params.set("sort_by",  sortModel[0].colId);
      params.set("sort_dir", sortModel[0].sort);
    }
  }

  
  // Columns


  function keyCellRenderer(params) {
    const val = params.value ?? "";
    const el = document.createElement("span");
    el.className = "key-hex-cell";
    el.title = val;
    el.textContent = val;
    el.addEventListener("click", () => {
      navigator.clipboard.writeText(val).then(() => {
        el.textContent = "✓ Copied";
        el.classList.add("key-hex-copied");
        setTimeout(() => {
          el.textContent = val;
          el.classList.remove("key-hex-copied");
        }, 1500);
      });
    });
    return el;
  }

  // deprecated MODP groups (up to 1536 bits) and the two tests built around them.
  const WEAK_VARIANTS = new Set(["768MODP", "1024MODP", "1536MODP", "TOLERATE_DH1024", "DOWNGRADE_DH2048"]);
  // IKE transform id -> bits, for the deprecated groups.
  const WEAK_DH_GROUPS = new Map([[1, 768], [2, 1024], [5, 1536]]);

  // bits of the accepted deprecated group, judged by the negotiated group:
  // a DOWNGRADE_DH2048 success that kept 2048 bits is a refusal.
  function acceptedWeakBits(row) {
    if (row?.result !== "SUCCESS" || !WEAK_VARIANTS.has(row.dh_variant)) return undefined;
    return WEAK_DH_GROUPS.get(row.dh_group);
  }

  // alert mark after the variant; tint via cellClassRules.
  function dhVariantCellRenderer(params) {
    const el = document.createElement("span");
    el.textContent = params.value ?? "";
    const bits = acceptedWeakBits(params.data);
    if (bits) {
      const mark = document.createElement("span");
      mark.className = "dh-weak-mark";
      mark.textContent = "!";
      mark.title = `Server accepted a deprecated ${bits}-bit DH group`;
      mark.setAttribute("role", "img");
      mark.setAttribute("aria-label", mark.title);
      el.append(mark);
    }
    return el;
  }

  const columnDefs = [
    {
      // tells apart the same server/variant from different vantage points.
      field: "vantage_label",
      headerName: "Scanned from",
      minWidth: 150,
      filter: "agTextColumnFilter",
      filterParams: { filterOptions: ["contains"], defaultOption: "contains" },
    },
    {
      field: "country",
      headerName: "Country",
      minWidth: 140,
      filter: "agTextColumnFilter",
    },
    {
      field: "mcc",
      headerName: "MCC",
      width: 90,
      filter: "agTextColumnFilter",
      filterParams: { filterOptions: ["equals"], defaultOption: "equals" },
    },
    {
      field: "mnc",
      headerName: "MNC",
      width: 90,
      filter: "agTextColumnFilter",
      filterParams: { filterOptions: ["equals"], defaultOption: "equals" },
    },
    {
      field: "operator",
      headerName: "Operator",
      minWidth: 180,
      filter: "agTextColumnFilter",
    },
    {
      field: "network",
      headerName: "Network",
      minWidth: 180,
      filter: "agTextColumnFilter",
    },
    {
      // full address matches exactly, partial as prefix.
      field: "target_ip",
      headerName: "Server IP",
      minWidth: 150,
      filter: "agTextColumnFilter",
      filterParams: { filterOptions: ["startsWith"], defaultOption: "startsWith" },
    },
    {
      field: "dh_variant",
      headerName: "DH Variant",
      minWidth: 160,
      filter: "agTextColumnFilter",
      cellRenderer: dhVariantCellRenderer,
      cellClassRules: { "dh-weak-cell": (params) => acceptedWeakBits(params.data) !== undefined },
    },
    {
      field: "result",
      headerName: "Result",
      minWidth: 160,
      filter: "agTextColumnFilter",
      filterParams: { filterOptions: ["equals"], defaultOption: "equals" },
    },
    {
      field: "dh_group",
      headerName: "DH Group",
      width: 120,
      filter: "agNumberColumnFilter",
      filterParams: { filterOptions: ["equals"], defaultOption: "equals" },
    },
    {
      field: "observed_at",
      headerName: "Observed",
      minWidth: 180,
      filter: "agDateColumnFilter",
      valueFormatter: (p) => formatDate(p.value),
    },
    {
      field: "key_hex",
      headerName: "Key Hex",
      minWidth: 200,
      flex: 1,
      filter: "agTextColumnFilter",
      cellRenderer: keyCellRenderer,
    },
  ];

 
  // Data
  

  let controller = null;

  const datasource = {
    async getRows(params) {
      controller?.abort();
      controller = new AbortController();

      setStatus("Loading…");

      const endpoint = currentMode === "latest" ? "latest-results" : "all-results";
      const url = new URL(`${API_ORIGIN}/api/v1/${endpoint}`, window.location.origin);
      url.searchParams.set("offset", String(params.startRow));
      url.searchParams.set("limit",  String(Math.min(BLOCK_SIZE, params.endRow - params.startRow)));
      applyFilters(url.searchParams, params.filterModel ?? {});
      applySort(url.searchParams,    params.sortModel  ?? []);
      url.searchParams.set("exclude_dh_variant", EXCLUDED_DH_VARIANT);

      try {
        const res = await fetch(url.toString(), {
          signal:  controller.signal,
          headers: { "X-API-Key": API_KEY },
        });

        if (!res.ok) {
          throw new Error(
            res.status === 429
              ? "Too many requests — please wait a moment and try again."
              : `HTTP ${res.status}`
          );
        }

        const rows = await res.json();
        if (!Array.isArray(rows)) throw new Error("Unexpected response format");

        const limit   = params.endRow - params.startRow;
        const lastRow = rows.length < limit ? params.startRow + rows.length : undefined;

        params.successCallback(rows, lastRow);

        setStatus(
          rows.length === 0 && params.startRow === 0
            ? "No results found."
            : ""
        );
      } catch (err) {
        if (err.name === "AbortError") {
          params.failCallback();
          return;
        }
        console.error(err);
        params.failCallback();
        setStatus(`Error loading data: ${err.message}`, true);
      }
    },
  };

  
  // Shareable links
  // View and filters live in the URL hash (/table/#view=all&mcc=232&mnc=10); keys are
  // API param names plus "view" ("mode" is the scan mode).


  const HASH_FILTERS = {
    vantage:    { field: "vantage_label", filterType: "text",   type: "contains" },
    country:    { field: "country",       filterType: "text",   type: "contains" },
    mcc:        { field: "mcc",           filterType: "text",   type: "equals" },
    mnc:        { field: "mnc",           filterType: "text",   type: "equals" },
    operator:   { field: "operator",      filterType: "text",   type: "contains" },
    network:    { field: "network",       filterType: "text",   type: "contains" },
    ip:         { field: "target_ip",     filterType: "text",   type: "startsWith" },
    dh_variant: { field: "dh_variant",    filterType: "text",   type: "contains" },
    result:     { field: "result",        filterType: "text",   type: "equals" },
    dh_group:   { field: "dh_group",      filterType: "number", type: "equals" },
    key_hex:    { field: "key_hex",       filterType: "text",   type: "contains" },
  };

  function readHash() {
    const hash = new URLSearchParams(window.location.hash.slice(1));
    const filterModel = {};
    for (const [key, { field, filterType, type }] of Object.entries(HASH_FILTERS)) {
      const value = hash.get(key)?.trim();
      if (!value) continue;
      const filter = filterType === "number" ? Number(value) : value;
      if (Number.isNaN(filter)) continue;
      filterModel[field] = { filterType, type, filter };
    }
    return { view: hash.get("view") === "all" ? "all" : "latest", filterModel };
  }

  // replaceState: no history entry per keystroke, no hashchange feedback.
  function writeHash(gridApi) {
    const hash = new URLSearchParams();
    if (currentMode === "all") hash.set("view", "all");
    const filterModel = gridApi.getFilterModel();
    for (const [key, { field }] of Object.entries(HASH_FILTERS)) {
      const value = filterModel[field]?.filter;
      if (value != null && String(value).trim()) hash.set(key, String(value).trim());
    }
    const query = hash.toString();
    history.replaceState(null, "", query ? `#${query}` : window.location.pathname + window.location.search);
  }

  function showMode(mode) {
    currentMode = mode;
    const isAll = mode === "all";
    const toggleEl = document.getElementById("endpoint-toggle");
    // the intro animation assumes "Latest" is active.
    if (isAll) toggleEl?.classList.remove("is-intro");
    toggleEl?.querySelectorAll(".segment-btn").forEach((b) => {
      b.classList.toggle("segment-btn--active", b.dataset.mode === mode);
    });
    document.querySelector(".table-label").textContent =
      isAll ? "All Watchdog Scan Results" : "Latest Watchdog Scan Results";
    document.getElementById("tableHeading").textContent =
      isAll ? "All Data" : "Latest Data";
  }


  // Grid
  

  const gridOptions = {
    theme: "legacy",

    rowModelType: "infinite",
    datasource,
    cacheBlockSize: BLOCK_SIZE,
    maxBlocksInCache: 10,
    maxConcurrentDatasourceRequests: 1,
    blockLoadDebounceMillis: 200,

    columnDefs,
    defaultColDef: {
      sortable: true,
      resizable: true,
      floatingFilter: true,
    },

    rowSelection: {
      mode: "multiRow",
      checkboxes: false,
      headerCheckbox: false,
    },
    enableCellTextSelection: true,
  };

  document.addEventListener("DOMContentLoaded", () => {
    // apply the link's view and filters before the first request.
    const shared = readHash();
    showMode(shared.view);
    const gridApi = agGrid.createGrid(document.getElementById("vowifiGrid"), {
      ...gridOptions,
      initialState: { filter: { filterModel: shared.filterModel } },
    });
    gridApi.addEventListener("filterChanged", () => writeHash(gridApi));

    // a link pasted into an open table.
    window.addEventListener("hashchange", () => {
      const { view, filterModel } = readHash();
      if (view !== currentMode) {
        showMode(view);
        gridApi.setGridOption("datasource", datasource);
      }
      gridApi.setFilterModel(filterModel);
    });

    const toggleEl = document.getElementById("endpoint-toggle");

    toggleEl?.querySelector(".segment-btn")
      ?.addEventListener("animationend", () => toggleEl.classList.remove("is-intro"), { once: true });

    toggleEl?.addEventListener("click", (e) => {
      const btn = e.target.closest(".segment-btn");
      if (!btn || btn.dataset.mode === currentMode) return;
      toggleEl.classList.remove("is-intro");

      showMode(btn.dataset.mode);
      // filters stay; resetting the datasource refetches with them.
      gridApi.setGridOption("datasource", datasource);
      // a view switch fires no filterChanged, so write the URL here.
      writeHash(gridApi);
    });
  });
})();
