/* global agGrid */

(() => {
  const API_KEY = "";
  const API_ORIGIN =
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === "localhost"
      ? "http://127.0.0.1:8000"
      : "";
  const BLOCK_SIZE = 100;
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

  function resultCellClass(params) {
    switch (params.value) {
      case "SUCCESS":            return "cell-result-success";
      case "NO_PROPOSAL_CHOSEN": return "cell-result-warn";
      default:                   return "cell-result-fail";
    }
  }


  // Filterung


  function applyFilters(params, filterModel) {
    const textFields = ["country", "operator", "network", "dh_variant", "key_hex", "mcc", "mnc", "result"];
    for (const field of textFields) {
      const f = filterModel[field];
      if (f?.filterType === "text" && f.filter?.trim()) {
        const val = f.filter.trim();
        params.set(field, field === "result" ? val.toUpperCase() : val);
      }
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

  const columnDefs = [
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
      field: "dh_variant",
      headerName: "DH Variant",
      minWidth: 160,
      filter: "agTextColumnFilter",
    },
    {
      field: "result",
      headerName: "Result",
      minWidth: 160,
      filter: "agTextColumnFilter",
      filterParams: { filterOptions: ["equals"], defaultOption: "equals" },
      cellClass: resultCellClass,
    },
    {
      field: "dh_group",
      headerName: "DH Group",
      width: 120,
      filter: "agNumberColumnFilter",
      filterParams: { filterOptions: ["equals"], defaultOption: "equals" },
    },
    {
      field: "encr_key_len",
      headerName: "Key Length",
      width: 120,
      filter: false,
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
    const gridApi = agGrid.createGrid(document.getElementById("vowifiGrid"), gridOptions);

    const toggleEl = document.getElementById("endpoint-toggle");

    toggleEl?.querySelector(".segment-btn")
      ?.addEventListener("animationend", () => toggleEl.classList.remove("is-intro"), { once: true });

    toggleEl?.addEventListener("click", (e) => {
      const btn = e.target.closest(".segment-btn");
      if (!btn || btn.dataset.mode === currentMode) return;
      toggleEl.classList.remove("is-intro");

      currentMode = btn.dataset.mode;
      const isAll = currentMode === "all";

      toggleEl.querySelectorAll(".segment-btn").forEach((b) => {
        b.classList.toggle("segment-btn--active", b.dataset.mode === currentMode);
      });
      document.querySelector(".table-label").textContent =
        isAll ? "All Watchdog Scan Results" : "Latest Watchdog Scan Results";
      document.getElementById("tableHeading").textContent =
        isAll ? "All Data" : "Latest Data";
      gridApi.setFilterModel(null);
      gridApi.setGridOption("datasource", datasource);
    });
  });
})();
