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

  // Matches the breakpoint the header switches to its mobile layout at.
  const MOBILE_QUERY = "(max-width: 640px)";

  // streaming download for takeout files (CSV, SQL) with API key in query string.
  document.querySelectorAll("a[data-format]").forEach((link) => {
    const path = PATHS[link.dataset.format];
    if (!path) return;
    link.href = `${API_ORIGIN}${path}?api_key=${encodeURIComponent(API_KEY)}`;

    // The takeout files are large, and the pills are easy to hit by accident on
    // a phone, so confirm before spending someone's mobile data on one.
    link.addEventListener("click", (event) => {
      if (!window.matchMedia(MOBILE_QUERY).matches) return;
      const label = link.textContent.trim() || link.dataset.format.toUpperCase();
      if (!window.confirm(`Start the ${label} download? The file may be large.`)) {
        event.preventDefault();
      }
    });
  });
})();
