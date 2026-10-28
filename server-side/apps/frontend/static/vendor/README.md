# Vendored frontend libraries

The website serves these libraries itself instead of loading them from a CDN. Its content security policy (`infrastructure/nginx.config`) only allows scripts from its own origin. The version is part of every file name.

| Library | Version | License | Used on | Source |
|---|---|---|---|---|
| [MapLibre GL JS](https://github.com/maplibre/maplibre-gl-js) | 5.19.0 | BSD-3-Clause | map | `maplibre-gl@5.19.0`: `dist/maplibre-gl.js`, `dist/maplibre-gl.css` |
| [AG Grid Community](https://github.com/ag-grid/ag-grid) | 35.2.1 | MIT | table | `ag-grid-community@35.2.1`: `dist/ag-grid-community.min.js`, `styles/ag-grid.css`, `styles/ag-theme-quartz.css` |
| [Apache ECharts](https://github.com/apache/echarts) | 5.6.0 | Apache-2.0 | collisions, DH history | `echarts@5.6.0`: `dist/echarts.min.js` |
| [D3](https://github.com/d3/d3) | 7.9.0 | ISC | fingerprinting | `d3@7.9.0`: `dist/d3.min.js` |

The files are unmodified copies of the npm releases listed under Source.
