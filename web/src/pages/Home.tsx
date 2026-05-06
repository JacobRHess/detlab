import { Link } from "react-router-dom";

import AttackMatrix from "../components/AttackMatrix";
import { dataset } from "../lib/cases";

function uniqTactics(): number {
  const s = new Set<string>();
  for (const c of dataset.cases) s.add(c.mitre_tactic);
  return s.size;
}

function totalFixtures(): number {
  let n = 0;
  for (const c of dataset.cases) {
    n += c.fixture_record_counts.positive + c.fixture_record_counts.negative;
  }
  return n;
}

/** Per-tactic shipped + planned counts for the coverage progress strip.
 * Only renders tactics that have *any* coverage (out_of_scope tactics are
 * shown on the Roadmap page, not here). */
function coverageRows() {
  const max = Math.max(
    ...dataset.tactics.map((t) => t.shipped_count + t.planned_count),
    1,
  );
  return dataset.tactics
    .filter((t) => t.shipped_count + t.planned_count > 0)
    .sort(
      (a, b) =>
        b.shipped_count + b.planned_count - (a.shipped_count + a.planned_count),
    )
    .map((t) => {
      const total = t.shipped_count + t.planned_count;
      const shippedPct = (t.shipped_count / max) * 100;
      const plannedPct = (t.planned_count / max) * 100;
      return { tactic: t, total, shippedPct, plannedPct };
    });
}

export default function Home() {
  const shipped = dataset.cases.length;
  const planned = dataset.planned.length;
  const featured = dataset.cases[0];
  const rows = coverageRows();

  return (
    <>
      <section className="hero">
        <span className="hero__eyebrow">network detection · MITRE ATT&amp;CK</span>
        <h1>Each detection ships with the attack that produces it.</h1>
        <p>
          detlab is a Splunk-focused network-detection lab. Every MITRE ATT&amp;CK case bundles a
          reproducible attack, captured Zeek telemetry, a Splunk-native detection (SPL + Sigma),
          and pytest fixtures that prove the rule fires positive and stays quiet on benign traffic.
          Try the detectors right here in your browser — no install required.
        </p>
        <div className="hero__ctas">
          {featured && (
            <Link to={`/case/${featured.id}`} className="btn btn--primary">
              Try a live detection →
            </Link>
          )}
          <a
            href="https://github.com/JacobRHess/detlab"
            target="_blank"
            rel="noreferrer"
            className="btn"
          >
            Source on GitHub
          </a>
        </div>
      </section>

      <section className="kpi-strip">
        <div className="kpi">
          <div className="kpi__value" style={{ color: "var(--shipped)" }}>{shipped}</div>
          <div className="kpi__label">Cases shipped</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{planned}</div>
          <div className="kpi__label">Cases planned</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{uniqTactics()}</div>
          <div className="kpi__label">ATT&amp;CK tactics covered</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{totalFixtures().toLocaleString()}</div>
          <div className="kpi__label">Test-fixture records</div>
        </div>
      </section>

      <div className="section-title">
        <h2>Coverage progress, per tactic</h2>
        <span className="muted">
          green = shipped · blue = planned · click for tactic detail
        </span>
      </div>
      <section className="coverage-strip">
        {rows.map(({ tactic, shippedPct, plannedPct }) => (
          <Link
            key={tactic.slug}
            to={`/tactic/${tactic.slug}`}
            className="coverage-row"
            style={{ textDecoration: "none", color: "var(--text)" }}
          >
            <div className="coverage-row__head">
              <span className="coverage-row__name">{tactic.name}</span>
              <span className="coverage-row__counts">
                {tactic.shipped_count > 0 && (
                  <span className="pass">{tactic.shipped_count}✓</span>
                )}
                {tactic.shipped_count > 0 && tactic.planned_count > 0 && " · "}
                {tactic.planned_count > 0 && (
                  <span className="planned">{tactic.planned_count} planned</span>
                )}
              </span>
            </div>
            <div className="coverage-row__bar">
              <div
                className="coverage-row__bar-shipped"
                style={{ width: `${shippedPct}%` }}
              />
              <div
                className="coverage-row__bar-planned"
                style={{ width: `${plannedPct}%` }}
              />
            </div>
          </Link>
        ))}
      </section>

      <div className="section-title">
        <h2>Coverage matrix</h2>
        <span className="muted">click a shipped technique to drill in · planned cells go to the tactic page</span>
      </div>
      <AttackMatrix />

      <div className="section-title" style={{ marginTop: 20 }}>
        <h2>How a case is structured</h2>
      </div>
      <div className="cards">
        <div className="card">
          <h3>1. Reproducible attack</h3>
          <p>Each case ships a script or container recipe (dnscat2, Sliver, chisel, …) so the telemetry can be regenerated end-to-end in the lab.</p>
        </div>
        <div className="card">
          <h3>2. Captured Zeek telemetry</h3>
          <p>Trimmed positive and negative fixtures live next to the rule. The same data drives CI and the in-browser playground.</p>
        </div>
        <div className="card">
          <h3>3. Splunk-native detection</h3>
          <p>Production SPL macro + saved search, plus a Sigma cross-reference for portability across SIEMs.</p>
        </div>
        <div className="card">
          <h3>4. Tested in CI</h3>
          <p>A Python detector mirrors the SPL as a testable spec; pytest asserts positive fires, negative stays silent. Drift is a build break.</p>
        </div>
      </div>
    </>
  );
}
