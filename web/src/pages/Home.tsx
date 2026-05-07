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

export default function Home() {
  const shipped = dataset.cases.length;
  const tacticsCovered = uniqTactics();
  const featured = dataset.cases[0];

  // Tactics with at least one shipped case, sorted by case count desc.
  // Out-of-scope tactics are absent — they live on /roadmap.
  const tacticPills = [...dataset.tactics]
    .filter((t) => t.shipped_count > 0)
    .sort((a, b) => b.shipped_count - a.shipped_count);

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
          <div className="kpi__label">Detections shipped</div>
        </div>
        <div className="kpi">
          <div className="kpi__value" style={{ color: "var(--shipped)" }}>{tacticsCovered}/14</div>
          <div className="kpi__label">ATT&amp;CK tactics covered</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">2</div>
          <div className="kpi__label">Telemetry sources <span className="muted">(Zeek + Suricata)</span></div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{totalFixtures().toLocaleString()}</div>
          <div className="kpi__label">Test-fixture records</div>
        </div>
      </section>

      <div className="section-title">
        <h2>Coverage by tactic</h2>
        <span className="muted">click a tactic to see its shipped detections</span>
      </div>
      <section className="tactic-pill-grid">
        {tacticPills.map((tactic) => (
          <Link
            key={tactic.slug}
            to={`/tactic/${tactic.slug}`}
            className="tactic-pill"
          >
            <div className="tactic-pill__count">{tactic.shipped_count}</div>
            <div className="tactic-pill__name">{tactic.name}</div>
          </Link>
        ))}
      </section>

      <div className="section-title">
        <h2>Coverage matrix</h2>
        <span className="muted">click a shipped technique to drill in</span>
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

      <div className="section-title" style={{ marginTop: 20 }}>
        <h2>Compose the detectors</h2>
        <span className="muted">cross-detector kill-chain analysis</span>
      </div>
      <div className="killchain-cta">
        <div>
          <h3 style={{ marginTop: 0 }}>Kill-chain meta-detector</h3>
          <p style={{ marginBottom: 8 }}>
            Each detection is useful on its own, but the <em>sequence</em> is what
            convicts. The kill-chain page runs every detector against a synthesized
            multi-stage intrusion and visualizes which ATT&amp;CK techniques fire
            on the same source IP — the same logic ships as the{" "}
            <code>detlab_kill_chain</code> Splunk macro.
          </p>
        </div>
        <Link to="/kill-chain" className="btn btn--primary">
          Run the kill-chain demo →
        </Link>
      </div>
    </>
  );
}
