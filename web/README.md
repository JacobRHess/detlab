# detlab — web

Static portfolio site for [JacobRHess/detlab](https://github.com/JacobRHess/detlab).
Vite + React + TypeScript, deployed to GitHub Pages by `.github/workflows/pages.yml`.

The site is a thin view over the repo: pages are generated from `cases/` and
`src/detlab/` by `scripts/build_web_data.py`. The "Try the detector"
playground runs the actual `detlab.detector` Python module in the browser
via [Pyodide](https://pyodide.org), so the in-browser detection is the same
code CI runs — no parallel JS port to drift against.

## Local development

```bash
# From the repo root, build the data bundle first:
py scripts/build_app.py        # produces app/lookups/detlab_cases.csv
py scripts/build_web_data.py   # produces web/src/data/cases.json,
                               #          web/public/cases/*.json,
                               #          web/public/py/*.py

# Then serve the site:
cd web
npm install
npm run dev                    # http://localhost:5173
```

## Scripts

```bash
npm run dev          # Vite dev server with HMR
npm run typecheck    # TypeScript only, no emit
npm run build        # tsc -b && vite build, output in dist/
npm run preview      # serve the built site locally
```

The `VITE_BASE` env var overrides the GitHub Pages base path (`/detlab/`)
for custom domains: `VITE_BASE=/ npm run build`.

## Data layout

`scripts/build_web_data.py` emits two layers so the bundle stays small as
the lab grows:

- `web/src/data/cases.json` — **lean summary** (id, title, technique, tactic,
  severity, status, fixture record counts, wiring). Bundled with the site
  via `lib/cases.ts`. Read synchronously by every page.
- `web/public/cases/<id>.json` — **per-case detail** (README, attack notes,
  SPL/macros/Sigma, fixture content). Fetched on demand by `CaseDetail` via
  `loadCase(id)`; cached after first fetch.
- `web/public/py/{detector,entropy,zeek_loader}.py` — copies of
  `src/detlab/*.py`, written into Pyodide's in-memory FS at runtime so the
  in-browser detector is the same code CI runs.

## Component layout

```
web/
├── public/
│   ├── favicon.svg
│   ├── cases/                  # generated: per-case detail (fetched on demand)
│   └── py/                     # generated: detlab.detector + deps for Pyodide
├── src/
│   ├── components/
│   │   ├── AttackMatrix.tsx        # tactic-grouped grid of shipped/planned cells
│   │   ├── charts.tsx              # BarChart, Donut, Sparkline, Heatmap, StatCard
│   │   ├── CodeBlock.tsx           # SPL / Sigma / Python with copy button
│   │   ├── DetectorPlayground.tsx  # Pyodide runner + threshold sliders
│   │   ├── FixtureStats.tsx        # qtype donut, port chart, length histogram
│   │   ├── FixtureViewer.tsx       # collapsible Zeek log preview
│   │   ├── Markdown.tsx            # GFM markdown for case READMEs
│   │   └── PipelineDiagram.tsx     # 5-step flow per detector
│   ├── data/cases.json         # generated: lean summary
│   ├── lib/
│   │   ├── cases.ts                # dataset, getCase, loadCase (async)
│   │   ├── fixtureStats.ts         # in-browser fixture summary
│   │   ├── pyodide.ts              # lazy Pyodide bridge
│   │   └── thresholds.ts           # detector kwarg metadata for sliders
│   ├── pages/
│   │   ├── Home.tsx                # hero + KPI strip + ATT&CK matrix
│   │   ├── Stats.tsx               # full Enterprise tactic heatmap + charts
│   │   ├── CaseDetail.tsx          # tabbed per-case view
│   │   └── About.tsx
│   ├── App.tsx, main.tsx       # router shell, lazy route imports
│   └── styles.css              # dark cyber theme matching the Splunk dashboards
├── index.html
├── package.json
├── tsconfig.json
└── vite.config.ts
```

Routes are code-split via `React.lazy` so the home-page bundle stays small;
opening a case lazily loads the case-detail chunk and that case's JSON.
