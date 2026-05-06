import { useEffect, useMemo, useRef, useState } from "react";

import { CaseFull } from "../lib/cases";
import { runDetector } from "../lib/pyodide";
import { DETECTOR_THRESHOLDS, ThresholdKnob } from "../lib/thresholds";

interface Props {
  c: CaseFull;
}

type FixtureKey = "positive" | "negative" | "custom";

function formatNumber(v: unknown): string {
  if (typeof v === "number") {
    if (Number.isInteger(v)) return v.toLocaleString();
    return v.toFixed(3);
  }
  if (Array.isArray(v)) return v.join(", ");
  if (v === null || v === undefined) return "—";
  return String(v);
}

function AlertTable({ alerts }: { alerts: Record<string, unknown>[] }) {
  if (!alerts.length) {
    return <div className="alert-empty">✓ Detector returned 0 alerts on this input.</div>;
  }
  const cols = Object.keys(alerts[0]);
  return (
    <div style={{ overflowX: "auto" }}>
      <table className="alert-table">
        <thead>
          <tr>
            {cols.map((k) => (
              <th key={k}>{k}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {alerts.map((a, i) => (
            <tr key={i}>
              {cols.map((k) => (
                <td key={k}>{formatNumber(a[k])}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function DetectorPlayground({ c }: Props) {
  const fnName = c.wiring.detector_function;
  const positive = c.fixtures.positive;
  const negative = c.fixtures.negative;

  const knobs: ThresholdKnob[] = useMemo(
    () => (fnName ? DETECTOR_THRESHOLDS[fnName] ?? [] : []),
    [fnName],
  );
  const knobDefaults = useMemo(() => {
    const out: Record<string, number> = {};
    for (const k of knobs) out[k.key] = k.default;
    return out;
  }, [knobs]);
  const [knobValues, setKnobValues] = useState<Record<string, number>>(knobDefaults);

  const [active, setActive] = useState<FixtureKey>("positive");
  const initialText = useMemo(() => positive?.content ?? negative?.content ?? "", [positive, negative]);
  const [text, setText] = useState(initialText);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState<string>("");
  const [result, setResult] = useState<{ alerts: Record<string, unknown>[]; records: number; ms: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Lets the keydown handler run the freshest version without re-binding listeners every render.
  const runRef = useRef<() => void>();

  if (!fnName) {
    return (
      <div className="playground muted">
        No playground wired for this case yet — add a CASE_WIRING entry in
        <code> scripts/build_web_data.py</code>.
      </div>
    );
  }

  function loadFixture(key: FixtureKey) {
    setActive(key);
    setError(null);
    setResult(null);
    if (key === "positive" && positive) setText(positive.content);
    else if (key === "negative" && negative) setText(negative.content);
  }

  async function run() {
    setRunning(true);
    setError(null);
    setResult(null);
    setStatus("Initialising…");
    try {
      const kwargs: Record<string, number> = {};
      for (const k of knobs) {
        if (knobValues[k.key] !== k.default) kwargs[k.key] = knobValues[k.key];
      }
      const out = await runDetector(fnName!, text, setStatus, kwargs);
      setResult({ alerts: out.alerts, records: out.recordCount, ms: Math.round(out.durationMs) });
      setStatus(`Done · ${out.recordCount} records, ${out.alerts.length} alert${out.alerts.length === 1 ? "" : "s"} in ${Math.round(out.durationMs)} ms`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStatus("Failed.");
    } finally {
      setRunning(false);
    }
  }

  function resetThresholds() {
    setKnobValues(knobDefaults);
  }

  const hasCustomThresholds = knobs.some((k) => knobValues[k.key] !== k.default);

  runRef.current = run;
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      // Cmd+Enter (mac) / Ctrl+Enter (everything else): run the detector.
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        runRef.current?.();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="playground">
      <div className="playground__head">
        <div>
          <h3 className="playground__title">Try the detector</h3>
          <p className="playground__sub">
            Runs <code>detlab.detector.{fnName}</code> in your browser via Pyodide — same code CI runs.
          </p>
        </div>
        <div className="playground__controls">
          <button
            className={`btn ${active === "positive" ? "btn--primary" : ""}`}
            onClick={() => loadFixture("positive")}
            disabled={!positive}
            type="button"
          >
            Load positive fixture
          </button>
          <button
            className={`btn ${active === "negative" ? "btn--primary" : ""}`}
            onClick={() => loadFixture("negative")}
            disabled={!negative}
            type="button"
          >
            Load negative fixture
          </button>
          <button
            className="btn btn--primary"
            onClick={run}
            disabled={running}
            type="button"
            title="Cmd/Ctrl + Enter"
          >
            {running ? "Running…" : "▶ Run detector"}
            <span className="kbd" aria-hidden="true">⌘/Ctrl + ↵</span>
          </button>
        </div>
      </div>

      {knobs.length > 0 && (
        <div className="thresholds">
          <div className="thresholds__head">
            <h4>Detector thresholds</h4>
            {hasCustomThresholds && (
              <button type="button" className="thresholds__reset" onClick={resetThresholds}>
                reset to defaults
              </button>
            )}
          </div>
          {knobs.map((k) => {
            const v = knobValues[k.key] ?? k.default;
            return (
              <div className="thresh-row" key={k.key}>
                <div>
                  <span className="thresh-row__label">{k.label}</span>
                  <span className="thresh-row__hint">{k.hint}</span>
                </div>
                <input
                  type="range"
                  min={k.min}
                  max={k.max}
                  step={k.step}
                  value={v}
                  onChange={(e) =>
                    setKnobValues({ ...knobValues, [k.key]: Number(e.target.value) })
                  }
                />
                <span className="thresh-row__value">{k.format ? k.format(v) : v}</span>
              </div>
            );
          })}
        </div>
      )}

      <textarea
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          if (active !== "custom") setActive("custom");
        }}
        spellCheck={false}
        aria-label="Zeek log input"
      />

      {status && <div className="run-status">{status}</div>}
      {error && (
        <div className="run-status" style={{ color: "var(--danger)" }}>
          Error: {error}
        </div>
      )}
      {result && (
        <>
          <div className="run-status">
            {result.records} record{result.records === 1 ? "" : "s"} parsed · {result.alerts.length} alert
            {result.alerts.length === 1 ? "" : "s"} · {result.ms} ms
          </div>
          <AlertTable alerts={result.alerts} />
        </>
      )}
    </div>
  );
}
