/* Lazy-loaded Pyodide bridge.
   The detlab.detector module + its dependencies (entropy.py, zeek_loader.py)
   are pure stdlib, so we just write them into Pyodide's in-memory FS as a
   `detlab` package and import normally. No wheels, no wasm extras. */

const PYODIDE_VERSION = "0.26.2";
const PYODIDE_CDN = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;

declare global {
  interface Window {
    loadPyodide?: (config: { indexURL: string }) => Promise<PyodideRuntime>;
  }
  interface ImportMeta {
    env: { BASE_URL: string };
  }
}

export interface PyodideRuntime {
  runPythonAsync: (code: string) => Promise<unknown>;
  globals: { set: (k: string, v: unknown) => void };
  FS: {
    mkdir: (path: string) => void;
    writeFile: (path: string, data: string) => void;
    analyzePath: (path: string) => { exists: boolean };
  };
}

let runtime: PyodideRuntime | null = null;
let pending: Promise<PyodideRuntime> | null = null;

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${src}"]`);
    if (existing) {
      existing.addEventListener("load", () => resolve());
      existing.addEventListener("error", () => reject(new Error(`failed to load ${src}`)));
      return;
    }
    const s = document.createElement("script");
    s.src = src;
    s.async = true;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error(`failed to load ${src}`));
    document.head.appendChild(s);
  });
}

async function fetchPy(name: string): Promise<string> {
  const url = `${import.meta.env.BASE_URL}py/${name}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`fetch ${url}: ${r.status}`);
  return r.text();
}

export async function loadDetectorRuntime(
  onProgress?: (msg: string) => void,
): Promise<PyodideRuntime> {
  if (runtime) return runtime;
  if (pending) return pending;

  pending = (async () => {
    onProgress?.("Loading Pyodide runtime…");
    if (!window.loadPyodide) {
      await loadScript(`${PYODIDE_CDN}pyodide.js`);
    }
    if (!window.loadPyodide) throw new Error("Pyodide failed to register on window");

    const py = await window.loadPyodide({ indexURL: PYODIDE_CDN });

    onProgress?.("Loading detlab.detector…");
    const [detector, entropy, killchain, zeek] = await Promise.all([
      fetchPy("detector.py"),
      fetchPy("entropy.py"),
      fetchPy("killchain.py"),
      fetchPy("zeek_loader.py"),
    ]);

    if (!py.FS.analyzePath("/detlab").exists) py.FS.mkdir("/detlab");
    py.FS.writeFile("/detlab/__init__.py", "");
    py.FS.writeFile("/detlab/entropy.py", entropy);
    py.FS.writeFile("/detlab/zeek_loader.py", zeek);
    py.FS.writeFile("/detlab/detector.py", detector);
    py.FS.writeFile("/detlab/killchain.py", killchain);

    await py.runPythonAsync(`
import sys
if "/" not in sys.path:
    sys.path.insert(0, "/")
`);

    runtime = py;
    onProgress?.("Ready.");
    return py;
  })();

  return pending;
}

export interface DetectorRunResult {
  alerts: Record<string, unknown>[];
  recordCount: number;
  durationMs: number;
}

export async function runDetector(
  fnName: string,
  fixtureText: string,
  onProgress?: (msg: string) => void,
  kwargs?: Record<string, number>,
): Promise<DetectorRunResult> {
  const py = await loadDetectorRuntime(onProgress);
  const started = performance.now();

  py.globals.set("INPUT_TEXT", fixtureText);
  py.globals.set("FN_NAME", fnName);
  py.globals.set("KWARGS_JSON", JSON.stringify(kwargs ?? {}));

  const code = `
import json
from dataclasses import asdict, is_dataclass
from detlab import detector as _detector

records = []
for line in INPUT_TEXT.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    try:
        records.append(json.loads(line))
    except json.JSONDecodeError:
        continue

fn = getattr(_detector, FN_NAME)
kwargs = json.loads(KWARGS_JSON)
alerts = fn(records, **kwargs) if kwargs else fn(records)
serialised = []
for a in alerts:
    if is_dataclass(a):
        serialised.append(asdict(a))
    elif isinstance(a, dict):
        serialised.append(a)
    else:
        serialised.append({"repr": repr(a)})

json.dumps({"alerts": serialised, "record_count": len(records)})
`;
  const raw = (await py.runPythonAsync(code)) as string;
  const parsed = JSON.parse(raw) as { alerts: Record<string, unknown>[]; record_count: number };
  return {
    alerts: parsed.alerts,
    recordCount: parsed.record_count,
    durationMs: performance.now() - started,
  };
}

export interface KillChainTimelineEntry {
  technique: string;
  tactic: string;
  detector_function: string;
  case_id: string;
  case_title: string;
  timestamp: number;
  detail: string;
}

export interface KillChainResult {
  src: string;
  technique_count: number;
  tactic_count: number;
  earliest_ts: number;
  latest_ts: number;
  duration_seconds: number;
  timeline: KillChainTimelineEntry[];
  tactics: string[];
}

/** Run the cross-detector kill-chain analysis against a multi-source-IP
 * record stream. Each line of `fixtureText` is a JSON record; the function
 * returns one alert per source IP that fires >=2 distinct techniques. */
export async function runKillChain(
  fixtureText: string,
  onProgress?: (msg: string) => void,
): Promise<{ chains: KillChainResult[]; recordCount: number; durationMs: number }> {
  const py = await loadDetectorRuntime(onProgress);
  const started = performance.now();
  py.globals.set("INPUT_TEXT", fixtureText);
  const code = `
import json
from dataclasses import asdict
from detlab.killchain import detect_attack_chain

records = []
for line in INPUT_TEXT.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    try:
        records.append(json.loads(line))
    except json.JSONDecodeError:
        continue

chains = detect_attack_chain(records)
serialised = [asdict(c) for c in chains]
json.dumps({"chains": serialised, "record_count": len(records)})
`;
  const raw = (await py.runPythonAsync(code)) as string;
  const parsed = JSON.parse(raw) as { chains: KillChainResult[]; record_count: number };
  return {
    chains: parsed.chains,
    recordCount: parsed.record_count,
    durationMs: performance.now() - started,
  };
}
