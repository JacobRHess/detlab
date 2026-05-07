/* Splunk dashboard preview — mocks the Splunk Web chrome (URL bar,
 * dashboard title, time-range picker, results table) showing what the
 * case's per-dashboard view would render once the .spl is installed.
 *
 * The fake table is populated from the case's positive fixture run
 * through the same Python detector that drives the playground tab — so
 * what the user sees here is the actual alert shape Splunk would
 * produce, not a placeholder.
 *
 * Used inside the "Run in Splunk" tab so the visitor gets a strong
 * mental picture of the deliverable without needing a Splunk install.
 */

import { useEffect, useState } from "react";

import { CaseFull } from "../lib/cases";
import { runDetector } from "../lib/pyodide";

interface AlertRow {
  [k: string]: unknown;
}

function abbreviate(value: unknown, max = 40): string {
  if (Array.isArray(value)) return abbreviate(value.join(", "), max);
  if (value === null || value === undefined) return "—";
  if (typeof value === "number") {
    return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(2);
  }
  const s = String(value);
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…";
}

export default function SplunkDashboardPreview({ c }: { c: CaseFull }) {
  const fnName = c.wiring?.detector_function;
  const positive = c.fixtures?.positive;
  const [running, setRunning] = useState(false);
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [recordCount, setRecordCount] = useState(0);
  const [ms, setMs] = useState(0);

  // Auto-run on mount so the preview is populated without the user
  // having to click. Pyodide caches across tab switches.
  useEffect(() => {
    if (!fnName || !positive) return;
    let cancelled = false;
    setRunning(true);
    runDetector(fnName, positive.content)
      .then((r) => {
        if (cancelled) return;
        setAlerts(r.alerts);
        setRecordCount(r.recordCount);
        setMs(r.durationMs);
        setError(null);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setRunning(false);
      });
    return () => {
      cancelled = true;
    };
  }, [fnName, positive]);

  if (!fnName || !positive) {
    return (
      <div className="splunk-preview splunk-preview--empty">
        <p className="muted" style={{ fontSize: 13 }}>
          Dashboard preview unavailable — case has no Pyodide wiring.
        </p>
      </div>
    );
  }

  const cols = alerts && alerts.length > 0 ? Object.keys(alerts[0]).slice(0, 6) : [];

  return (
    <div className="splunk-preview">
      <div className="splunk-preview__chrome">
        <span className="splunk-preview__dot splunk-preview__dot--r" />
        <span className="splunk-preview__dot splunk-preview__dot--y" />
        <span className="splunk-preview__dot splunk-preview__dot--g" />
        <code className="splunk-preview__url">
          /en-US/app/detlab/{c.view_name}
        </code>
      </div>

      <div className="splunk-preview__body">
        <div className="splunk-preview__title">
          <span className="splunk-preview__appname">detlab</span>
          <span className="splunk-preview__sep">›</span>
          <span>{c.title}</span>
        </div>

        <div className="splunk-preview__form">
          <label>
            <span>earliest</span>
            <input type="text" defaultValue="-24h" disabled />
          </label>
          <label>
            <span>latest</span>
            <input type="text" defaultValue="now" disabled />
          </label>
          <label>
            <span>severity</span>
            <select disabled defaultValue={c.severity}>
              <option>{c.severity}</option>
            </select>
          </label>
          <button type="button" className="btn btn--primary" disabled>
            Apply
          </button>
        </div>

        <div className="splunk-preview__panel">
          <div className="splunk-preview__panel-head">
            <strong>Alerts</strong>
            <span className="muted" style={{ fontSize: 12 }}>
              {running
                ? "running search…"
                : alerts
                  ? `${alerts.length} alert${alerts.length === 1 ? "" : "s"} · ${recordCount.toLocaleString()} records · ${ms.toFixed(0)} ms`
                  : "—"}
            </span>
          </div>

          {error ? (
            <div className="empty-state" style={{ margin: 0 }}>
              <p style={{ fontSize: 13 }}>Failed to populate preview: {error}</p>
            </div>
          ) : !alerts ? (
            <div className="splunk-preview__skeleton">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="splunk-preview__skeleton-row" />
              ))}
            </div>
          ) : alerts.length === 0 ? (
            <p className="muted" style={{ fontSize: 13, padding: "12px 14px" }}>
              No alerts on the bundled positive fixture — adjust thresholds in
              the "Try it" tab to see what fires.
            </p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table className="splunk-preview__table">
                <thead>
                  <tr>
                    {cols.map((col) => (
                      <th key={col}>{col}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 8).map((row, i) => (
                    <tr key={i}>
                      {cols.map((col) => (
                        <td key={col}>{abbreviate(row[col])}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
              {alerts.length > 8 && (
                <p className="muted" style={{ fontSize: 12, padding: "8px 14px 0" }}>
                  …{alerts.length - 8} more rows in real Splunk results.
                </p>
              )}
            </div>
          )}
        </div>

        <p className="splunk-preview__caption">
          Mocked from the actual detector run on this case's positive fixture
          via Pyodide — same logic Splunk would execute on real telemetry.
          Time-range and severity inputs above mirror the actual dashboard
          form tokens shipped in <code>app/default/data/ui/views/{c.view_name}.xml</code>.
        </p>
      </div>
    </div>
  );
}
