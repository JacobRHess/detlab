/* Cross-evaluation scoreboard.
 *
 * Loads every shipped case's full fixtures, then runs every detector against
 * every fixture pair (positive + negative) via Pyodide. Renders the result
 * as a colour-coded matrix that makes detector *specificity* visible:
 *
 *   - diagonal positive cells → expected fires (green)
 *   - off-diagonal positive cells with hits → potential overlap (amber)
 *   - any negative cell with hits → false positive (red)
 *
 * The summary headline ("N/N detectors fired on diagonal · M unexpected
 * hits") is the single line that says "this lab's detections are tight".
 */

import { useState } from "react";

import { CaseSummary, dataset, loadCase } from "../lib/cases";
import { loadDetectorRuntime, runDetector } from "../lib/pyodide";

interface CellResult {
  positive: number;
  negative: number;
}

interface ScoreboardResult {
  cells: Record<string, Record<string, CellResult>>;
  summary: {
    diagonalFires: number;
    diagonalTotal: number;
    unexpectedFires: number;
    falsePositives: number;
  };
  durationMs: number;
}

type ScoreboardState =
  | { status: "idle" }
  | { status: "loading"; message: string; progress: number; total: number }
  | { status: "done"; result: ScoreboardResult }
  | { status: "error"; message: string };

function classify(detectorCase: string, fixtureCase: string, result: CellResult) {
  const isDiagonal = detectorCase === fixtureCase;
  if (isDiagonal) {
    if (result.positive >= 1 && result.negative === 0) return "expected-fire";
    if (result.positive === 0) return "missed-fire";
    return "false-positive"; // diagonal but negative also fired
  }
  // off-diagonal
  if (result.positive > 0 || result.negative > 0) {
    if (result.negative > 0) return "false-positive";
    return "off-diagonal-fire";
  }
  return "expected-silent";
}

const CELL_COLORS: Record<string, string> = {
  "expected-fire": "rgba(83, 160, 81, 0.30)",
  "expected-silent": "transparent",
  "off-diagonal-fire": "rgba(248, 190, 52, 0.25)",
  "false-positive": "rgba(220, 78, 65, 0.30)",
  "missed-fire": "rgba(220, 78, 65, 0.45)",
};

const CELL_BORDERS: Record<string, string> = {
  "expected-fire": "var(--shipped)",
  "expected-silent": "var(--border)",
  "off-diagonal-fire": "var(--warn)",
  "false-positive": "var(--danger)",
  "missed-fire": "var(--danger)",
};

function shortLabel(c: CaseSummary): string {
  // T1071.004 -> 1071.004 (drops the prefix to keep cells narrow).
  return c.mitre_technique.replace(/^T/, "");
}

export default function CrossEvalScoreboard() {
  const [state, setState] = useState<ScoreboardState>({ status: "idle" });

  async function run() {
    const cases = dataset.cases;
    const total = cases.length * cases.length;
    setState({ status: "loading", message: "Loading Pyodide runtime…", progress: 0, total });

    try {
      await loadDetectorRuntime();
      setState({ status: "loading", message: "Loading case fixtures…", progress: 0, total });

      const fulls = await Promise.all(cases.map((c) => loadCase(c.id)));
      const valid = fulls.filter((f): f is NonNullable<typeof f> => f !== null);
      if (valid.length !== cases.length) {
        throw new Error("could not load all case detail files");
      }

      const cells: Record<string, Record<string, CellResult>> = {};
      const started = performance.now();

      let done = 0;
      for (const detectorCase of cases) {
        const fnName = detectorCase.wiring.detector_function;
        if (!fnName) continue;
        cells[detectorCase.id] = {};

        for (const fixtureCase of valid) {
          const positive = fixtureCase.fixtures.positive;
          const negative = fixtureCase.fixtures.negative;
          const positiveAlerts = positive
            ? (await runDetector(fnName, positive.content)).alerts.length
            : 0;
          const negativeAlerts = negative
            ? (await runDetector(fnName, negative.content)).alerts.length
            : 0;
          cells[detectorCase.id][fixtureCase.id] = {
            positive: positiveAlerts,
            negative: negativeAlerts,
          };
          done++;
          setState({
            status: "loading",
            message: `Running ${detectorCase.title} · ${fixtureCase.title}`,
            progress: done,
            total,
          });
        }
      }

      const summary = {
        diagonalFires: 0,
        diagonalTotal: 0,
        unexpectedFires: 0,
        falsePositives: 0,
      };
      for (const d of cases) {
        for (const f of cases) {
          const cell = cells[d.id]?.[f.id];
          if (!cell) continue;
          if (d.id === f.id) {
            summary.diagonalTotal++;
            if (cell.positive >= 1) summary.diagonalFires++;
          } else if (cell.positive > 0) {
            summary.unexpectedFires++;
          }
          if (cell.negative > 0) summary.falsePositives++;
        }
      }

      const durationMs = performance.now() - started;
      setState({
        status: "done",
        result: { cells, summary, durationMs },
      });
    } catch (err) {
      setState({
        status: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return (
    <div>
      {state.status === "idle" && (
        <div className="empty-state">
          <p style={{ marginTop: 0 }}>
            Runs every detector against every case's positive and negative fixtures
            in your browser. Loads Pyodide (~8 MB, first run) and {dataset.cases.length}
            &nbsp;case files (~150 KB each), then executes
            {" "}
            {dataset.cases.length * dataset.cases.length * 2} detector calls.
            Takes ~10 s after the runtime warms.
          </p>
          <button type="button" className="btn btn--primary" onClick={run}>
            ▶ Run cross-evaluation
          </button>
        </div>
      )}

      {state.status === "loading" && (
        <div className="empty-state" aria-busy="true">
          <p style={{ marginTop: 0, fontFamily: "var(--font-mono)" }}>
            {state.message}
          </p>
          <div className="bar-chart" style={{ maxWidth: 480, margin: "0 auto" }}>
            <div className="bar-chart__row" style={{ height: 14, gridTemplateColumns: "1fr 80px" }}>
              <div className="bar-chart__track">
                <div
                  className="bar-chart__fill"
                  style={{
                    width: `${state.total > 0 ? (state.progress / state.total) * 100 : 0}%`,
                    background: "var(--accent)",
                  }}
                />
              </div>
              <div className="bar-chart__value">
                {state.progress}/{state.total}
              </div>
            </div>
          </div>
        </div>
      )}

      {state.status === "error" && (
        <div className="empty-state">
          <p style={{ color: "var(--danger)" }}>Failed: {state.message}</p>
          <button type="button" className="btn" onClick={run}>
            Retry
          </button>
        </div>
      )}

      {state.status === "done" && <ScoreboardMatrix result={state.result} />}
    </div>
  );
}

function ScoreboardMatrix({ result }: { result: ScoreboardResult }) {
  const cases = dataset.cases;
  const { summary, durationMs } = result;

  return (
    <>
      <div className="scoreboard-summary">
        <span className={summary.diagonalFires === summary.diagonalTotal ? "pass" : "fail"}>
          {summary.diagonalFires} / {summary.diagonalTotal} detectors fired on diagonal
        </span>
        <span className="dot">·</span>
        <span className={summary.unexpectedFires === 0 ? "pass" : "warn"}>
          {summary.unexpectedFires} unexpected off-diagonal hits
        </span>
        <span className="dot">·</span>
        <span className={summary.falsePositives === 0 ? "pass" : "fail"}>
          {summary.falsePositives} false positives on negatives
        </span>
        <span className="dot">·</span>
        <span className="muted">{Math.round(durationMs).toLocaleString()} ms</span>
      </div>

      <div className="scoreboard">
        <table className="scoreboard__table">
          <thead>
            <tr>
              <th className="scoreboard__corner" scope="col">
                <span>detector ↓</span>
                <br />
                <span className="muted">fixture →</span>
              </th>
              {cases.map((c) => (
                <th
                  key={c.id}
                  className="scoreboard__col-head"
                  title={`${c.mitre_technique} · ${c.title}`}
                >
                  <div className="scoreboard__col-id">{shortLabel(c)}</div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cases.map((d) => (
              <tr key={d.id}>
                <th
                  className="scoreboard__row-head"
                  scope="row"
                  title={`${d.wiring.detector_function} · ${d.title}`}
                >
                  <div className="scoreboard__row-id">{shortLabel(d)}</div>
                  <div className="scoreboard__row-fn">
                    {d.wiring.detector_function?.replace("detect_", "")}
                  </div>
                </th>
                {cases.map((f) => {
                  const cell = result.cells[d.id]?.[f.id];
                  if (!cell) {
                    return <td key={f.id} className="scoreboard__cell muted-cell">—</td>;
                  }
                  const cls = classify(d.id, f.id, cell);
                  return (
                    <td
                      key={f.id}
                      className={`scoreboard__cell scoreboard__cell--${cls}`}
                      style={{
                        background: CELL_COLORS[cls],
                        borderLeftColor: CELL_BORDERS[cls],
                      }}
                      title={`${d.title} on ${f.title}: ${cell.positive} on positive, ${cell.negative} on negative`}
                    >
                      <div className="scoreboard__cell-pos">{cell.positive}</div>
                      <div className="scoreboard__cell-neg">{cell.negative}</div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
        <div className="scoreboard__legend">
          <span><span className="swatch" style={{ background: CELL_COLORS["expected-fire"] }}></span>diagonal fires (expected)</span>
          <span><span className="swatch" style={{ background: CELL_COLORS["off-diagonal-fire"] }}></span>off-diagonal hit</span>
          <span><span className="swatch" style={{ background: CELL_COLORS["false-positive"] }}></span>fired on negative (FP)</span>
          <span><span className="swatch" style={{ background: CELL_COLORS["missed-fire"] }}></span>missed fire (FN)</span>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          Each cell shows alert counts for {" "}
          <span className="dim">positive</span> / <span className="dim">negative</span> fixtures.
        </p>
      </div>
    </>
  );
}
