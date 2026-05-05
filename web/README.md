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
py scripts/build_web_data.py   # produces web/src/data/cases.json + web/public/py/

# Then serve the site:
cd web
npm install
npm run dev                    # http://localhost:5173
```

## Build

```bash
npm run build                  # static output in dist/
```

The `VITE_BASE` env var overrides the GitHub Pages base path (`/detlab/`)
for custom domains: `VITE_BASE=/ npm run build`.

## Layout

```
web/
├── public/
│   ├── favicon.svg
│   └── py/                    # generated: copies of detlab.detector + deps
├── src/
│   ├── components/            # AttackMatrix, CodeBlock, FixtureViewer,
│   │                          # DetectorPlayground, Markdown
│   ├── data/cases.json        # generated: full case content + wiring
│   ├── lib/
│   │   ├── cases.ts           # typed dataset access
│   │   └── pyodide.ts         # lazy Pyodide bridge
│   ├── pages/                 # Home (matrix) / CaseDetail (tabs) / About
│   ├── App.tsx, main.tsx      # router shell
│   └── styles.css             # dark cyber theme matching the Splunk dashboards
├── index.html
├── package.json
├── tsconfig.json
└── vite.config.ts
```
