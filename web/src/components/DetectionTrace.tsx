/* What-just-happened visualisation for the detector playground.
 *
 * Two pieces:
 *   1. Three-card pipeline trace (parsed → ran → result) visible after Run.
 *      Numbers prominently rendered, labels muted. Designed for the
 *      non-technical viewer to immediately read "yes the detector ran,
 *      yes it found N alerts" without reading the alert table.
 *   2. Per-alert gate explainer — for each row in the alert output,
 *      maps every threshold knob to the matching alert field and shows
 *      ✓ value vs threshold. The technical reader gets the why-this-fired
 *      receipt; the non-technical reader gets a green tick they can
 *      visually count. */

import { ThresholdKnob } from "../lib/thresholds";

interface RunResult {
  records: number;
  alerts: Record<string, unknown>[];
  ms: number;
}

interface TraceProps {
  result: RunResult;
  fnName: string;
}

export function DetectionTrace({ result, fnName }: TraceProps) {
  const fired = result.alerts.length > 0;
  return (
    <div className="trace" role="status" aria-live="polite">
      <div className="trace__card">
        <div className="trace__num">1</div>
        <div className="trace__big">{result.records.toLocaleString()}</div>
        <div className="trace__small">records parsed</div>
        <div className="trace__hint">JSON-lines from fixture</div>
      </div>
      <div className="trace__arrow">→</div>
      <div className="trace__card">
        <div className="trace__num">2</div>
        <div className="trace__big">{result.ms.toLocaleString()} <span className="trace__unit">ms</span></div>
        <div className="trace__small">detector ran</div>
        <div className="trace__hint">
          <code>{fnName}</code> in Pyodide
        </div>
      </div>
      <div className="trace__arrow">→</div>
      <div className={`trace__card trace__card--${fired ? "fired" : "quiet"}`}>
        <div className="trace__num">3</div>
        <div className="trace__big">{result.alerts.length}</div>
        <div className="trace__small">{fired ? "alert" + (result.alerts.length === 1 ? "" : "s") + " fired" : "alerts (silent)"}</div>
        <div className="trace__hint">
          {fired ? "thresholds met — see breakdown below" : "all gates kept it quiet"}
        </div>
      </div>
    </div>
  );
}

// ---------- Per-alert gate explainer ----------

interface ExplainerProps {
  alerts: Record<string, unknown>[];
  knobs: ThresholdKnob[];
  knobValues: Record<string, number>;
}

interface Gate {
  label: string;
  fieldName: string;
  value: number;
  threshold: number;
  op: "≥" | "≤";
  passed: boolean;
  format: (v: number) => string;
}

/** Map a threshold knob to the matching alert field. Knobs are named
 * `min_<field>` or `max_<field>`; the alert field is just `<field>`.
 * Returns null if the alert doesn't have a numeric value at that field
 * (which is fine — not every knob is reflected on every alert dataclass). */
function gateFor(
  knob: ThresholdKnob,
  alert: Record<string, unknown>,
  threshold: number,
): Gate | null {
  const isMin = knob.key.startsWith("min_");
  const isMax = knob.key.startsWith("max_");
  if (!isMin && !isMax) return null;
  const fieldName = knob.key.replace(/^(min_|max_)/, "");
  const raw = alert[fieldName];
  if (typeof raw !== "number") return null;
  const op: "≥" | "≤" = isMin ? "≥" : "≤";
  const passed = isMin ? raw >= threshold : raw <= threshold;
  return {
    label: knob.label,
    fieldName,
    value: raw,
    threshold,
    op,
    passed,
    format: knob.format ?? ((v) => v.toLocaleString()),
  };
}

export function AlertExplainer({ alerts, knobs, knobValues }: ExplainerProps) {
  if (alerts.length === 0) return null;

  return (
    <div className="explainer">
      <h4 className="explainer__head">
        Why {alerts.length === 1 ? "this alert" : "these alerts"} fired
      </h4>
      <p className="explainer__sub muted">
        For each alert, every threshold knob the detector exposes maps to a field on
        the alert. Green ticks are gates that passed; red marks are gates that failed.
        For a fired alert, every gate must pass.
      </p>
      {alerts.map((alert, idx) => {
        const gates = knobs
          .map((k) => gateFor(k, alert, knobValues[k.key] ?? k.default))
          .filter((g): g is Gate => g !== null);
        if (gates.length === 0) {
          return (
            <div key={idx} className="explainer__alert muted">
              Alert {idx + 1}: no threshold knobs map to this alert's fields —
              detector uses fixed (non-tunable) gates.
            </div>
          );
        }
        return (
          <div key={idx} className="explainer__alert">
            <div className="explainer__alert-head">Alert {idx + 1}</div>
            <ul className="explainer__gates">
              {gates.map((g) => (
                <li
                  key={g.fieldName}
                  className={`explainer__gate explainer__gate--${g.passed ? "pass" : "fail"}`}
                >
                  <span className="explainer__check">{g.passed ? "✓" : "✗"}</span>
                  <span className="explainer__label">{g.label}</span>
                  <code className="explainer__value">{g.format(g.value)}</code>
                  <span className="explainer__op">{g.op}</span>
                  <code className="explainer__threshold">{g.format(g.threshold)}</code>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
}
