(() => {
  const API_KEY = "";
  const API_ORIGIN =
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === "localhost"
      ? "http://127.0.0.1:8000"
      : "";

  const PATHS = {
    csv: "/api/v1/takeout/csv",
    sql: "/api/v1/takeout/sql",
  };

  // streaming download for takeout files (CSV, SQL) with API key in query string.
  document.querySelectorAll("a[data-format]").forEach((link) => {
    const path = PATHS[link.dataset.format];
    if (!path) return;
    link.href = `${API_ORIGIN}${path}?api_key=${encodeURIComponent(API_KEY)}`;
  });
})();
