(function () {
  var STORAGE_KEY = 'vowifi-theme';

  function getPreferred() {
    var saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'dark' || saved === 'light') return saved;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);

    var grid = document.getElementById('vowifiGrid');
    if (grid) {
      grid.classList.toggle('ag-theme-quartz', theme === 'light');
      grid.classList.toggle('ag-theme-quartz-dark', theme === 'dark');
    }

    var btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
      var icon = btn.querySelector('.theme-icon');
      if (icon) icon.textContent = theme === 'dark' ? '\u2600' : '\u263D';
    }
  }

  function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme') || 'light';
    var next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem(STORAGE_KEY, next);
    applyTheme(next);
  }

  document.documentElement.setAttribute('data-theme', getPreferred());

  window.toggleTheme = toggleTheme;

  // Sync button icon and AG Grid class once DOM is ready, then set up click
  document.addEventListener('DOMContentLoaded', function () {
    applyTheme(document.documentElement.getAttribute('data-theme') || getPreferred());
    var btn = document.getElementById('theme-toggle');
    if (btn) btn.addEventListener('click', toggleTheme);
  });
})();
