/* Risk-Based Alerting (RBA) leaderboard.
 *
 * In a mature Splunk ES deployment, individual detections are no longer
 * "every fire = notable event" — each detection contributes a risk score
 * to the involved entities (system / user), and the SOC reviews entities
 * that have *accumulated* enough risk over a window. This page mirrors
 * that workflow:
 *
 *   - Bundles per-case risk_score (0-100, sourced from CASE_METADATA).
 *   - Renders the catalogue ranked by risk so the user can see how each
 *     detection contributes to the org-wide RBA budget.
 *   - Visualizes a synthetic "current risk leaderboard" — what an analyst
 *     would see at the top of the ES Risk Analysis dashboard.
 */

import { useMemo } from "react";
import { Link } from "react-router-dom";

import { CaseSummary, dataset, tacticLabel } from "../lib/cases";
import { riskBucket } from "../lib/risk";

interface RankedSrc {
  src: string;
  type: "system" | "user";
  totalRisk: number;
  techniques: { id: string; technique: string; title: string; risk: number }[];
}

/** Synthesized risk leaderboard — what an analyst would see at the top
 * of the ES Risk Analysis dashboard. Each entity here fires a small
 * realistic chain of techniques (recon → C2 → exfil for a compromised
 * host; cred-access → lateral for a stolen service account). Limited to
 * 3-4 techniques per row so the totals read like real RBA output and
 * not a brute-force sum of the catalogue. */
function syntheticLeaderboard(): RankedSrc[] {
  const byTechnique = new Map<string, CaseSummary>();
  for (const c of dataset.cases) byTechnique.set(c.mitre_technique, c);

  function chain(techniques: string[]) {
    return techniques
      .map((t) => byTechnique.get(t))
      .filter((c): c is CaseSummary => c !== undefined)
      .map((c) => ({
        id: c.id,
        technique: c.mitre_technique,
        title: c.title,
        risk: c.risk_score,
      }));
  }

  const rows: RankedSrc[] = [
    {
      src: "10.0.42.18",
      type: "system",
      techniques: chain(["T1595.002", "T1190", "T1071.001", "T1041"]),
      totalRisk: 0,
    },
    {
      src: "svc-build@corp",
      type: "user",
      techniques: chain(["T1110.001", "T1021.002", "T1570"]),
      totalRisk: 0,
    },
    {
      src: "10.10.5.77",
      type: "system",
      techniques: chain(["T1568.002", "T1219"]),
      totalRisk: 0,
    },
    {
      src: "alex.davis@corp",
      type: "user",
      techniques: chain(["T1133", "T1213.002", "T1567.002"]),
      totalRisk: 0,
    },
  ];
  for (const r of rows) {
    r.totalRisk = r.techniques.reduce((s, t) => s + t.risk, 0);
  }
  return rows.filter((r) => r.techniques.length > 0);
}

function RiskBar({ score, max = 100 }: { score: number; max?: number }) {
  const pct = Math.min(100, (score / max) * 100);
  const { color } = riskBucket(Math.min(score, 100));
  return (
    <div className="risk-bar">
      <div className="risk-bar__track">
        <div
          className="risk-bar__fill"
          style={{ width: `${pct}%`, background: color }}
          aria-hidden="true"
        />
      </div>
      <span className="risk-bar__num">{score}</span>
    </div>
  );
}

export default function Risk() {
  const ranked = useMemo(() => {
    return [...dataset.cases]
      .filter((c) => c.risk_score > 0)
      .sort((a, b) => b.risk_score - a.risk_score);
  }, []);

  const buckets = useMemo(() => {
    const out: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const c of dataset.cases) {
      const b = riskBucket(c.risk_score).label;
      if (b in out) out[b]++;
    }
    return out;
  }, []);

  const avgRisk = useMemo(() => {
    const scored = dataset.cases.filter((c) => c.risk_score > 0);
    return scored.length === 0
      ? 0
      : Math.round(scored.reduce((s, c) => s + c.risk_score, 0) / scored.length);
  }, []);

  const leaderboard = useMemo(() => {
    return syntheticLeaderboard().sort((a, b) => b.totalRisk - a.totalRisk);
  }, []);

  return (
    <article>
      <div className="page-header">
        <h1>Risk-Based Alerting</h1>
        <p className="muted" style={{ maxWidth: 760 }}>
          Mature Splunk ES deployments don't fire a notable event on every
          detection — each rule contributes a <strong>risk score</strong> to
          the involved entity (a system or user), and the SOC reviews entities
          that have <em>accumulated</em> risk over a window. The detlab
          catalogue ships scored detections so the same rollup works the moment
          the app is installed.
        </p>
      </div>

      <section className="kpi-strip" style={{ marginTop: 12 }}>
        <div className="kpi">
          <div className="kpi__value" style={{ color: "var(--danger)" }}>{buckets.Critical}</div>
          <div className="kpi__label">Critical (90+)</div>
        </div>
        <div className="kpi">
          <div className="kpi__value" style={{ color: "#fb8c00" }}>{buckets.High}</div>
          <div className="kpi__label">High (70–89)</div>
        </div>
        <div className="kpi">
          <div className="kpi__value" style={{ color: "var(--warn)" }}>{buckets.Medium}</div>
          <div className="kpi__label">Medium (50–69)</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{avgRisk}</div>
          <div className="kpi__label">Average risk score</div>
        </div>
      </section>

      <div className="section-title" style={{ marginTop: 24 }}>
        <h2>Detection catalogue ranked by risk</h2>
        <span className="muted">click a row to see the full case</span>
      </div>
      <div className="risk-table">
        <div className="risk-table__head">
          <span>case</span>
          <span>tactic</span>
          <span>entity</span>
          <span>tier</span>
          <span>risk score</span>
        </div>
        {ranked.map((c) => {
          const bucket = riskBucket(c.risk_score);
          return (
            <Link key={c.id} to={`/case/${c.id}`} className="risk-table__row">
              <div>
                <div className="risk-table__title">{c.title}</div>
                <code className="risk-table__tech">{c.mitre_technique}</code>
              </div>
              <span>{tacticLabel(c.mitre_tactic)}</span>
              <span className="risk-table__entity">
                {c.risk_object_type === "user" ? "👤 user" : "💻 system"}
              </span>
              <span className="risk-table__tier">tier {c.pyramid_tier}</span>
              <div>
                <RiskBar score={c.risk_score} />
                <span className="risk-bucket" style={{ color: bucket.color }}>
                  {bucket.label}
                </span>
              </div>
            </Link>
          );
        })}
      </div>

      <div className="section-title" style={{ marginTop: 28 }}>
        <h2>Synthetic ES Risk Analysis dashboard</h2>
        <span className="muted">how scores roll up to entities over a 24h window</span>
      </div>
      <p className="muted" style={{ fontSize: 13, marginTop: -4 }}>
        Each row simulates an entity that fired several detlab detections inside
        the same window. The total risk is the sum of contributing case scores;
        ES surfaces entities by descending total so the SOC works the riskiest
        first. This is the core RBA workflow.
      </p>

      <div className="risk-leaderboard">
        {leaderboard.map((row, idx) => {
          const bucket = riskBucket(Math.min(row.totalRisk, 100));
          return (
            <div key={row.src} className="risk-leaderboard__row">
              <div className="risk-leaderboard__rank">#{idx + 1}</div>
              <div className="risk-leaderboard__src">
                <code>{row.src}</code>
                <span className="risk-leaderboard__type">{row.type}</span>
              </div>
              <div className="risk-leaderboard__total">
                <RiskBar score={row.totalRisk} max={Math.max(300, row.totalRisk)} />
                <span className="risk-bucket" style={{ color: bucket.color }}>
                  {bucket.label}
                </span>
              </div>
              <div className="risk-leaderboard__contributors">
                {row.techniques.map((t) => (
                  <Link
                    key={t.id + t.technique}
                    to={`/case/${t.id}`}
                    className="risk-contrib-chip"
                    title={`+${t.risk} from ${t.title}`}
                  >
                    <code>{t.technique}</code>
                    <span className="risk-contrib-chip__plus">+{t.risk}</span>
                  </Link>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      <h3 style={{ marginTop: 28 }}>The Splunk implementation</h3>
      <p className="muted" style={{ fontSize: 13, maxWidth: 760 }}>
        Each case's <code>savedsearches.conf</code> stanza ships the Splunk ES
        risk modifier action: <code>action.risk = 1</code>,{" "}
        <code>action.risk.param._risk_score = &lt;score&gt;</code>,{" "}
        <code>action.risk.param._risk_object_field = &lt;src|user&gt;</code>.
        ES rolls the contributions up via the{" "}
        <code>risk_index</code> data model and surfaces entities on the Risk
        Analysis dashboard. The same scores feed the lookup{" "}
        <code>detlab_cases.csv</code> for ad-hoc SPL queries:
      </p>
      <pre className="codeblock">
{`| inputlookup detlab_cases.csv
| stats sum(risk_score) AS total_risk by mitre_tactic
| sort -total_risk`}
      </pre>
    </article>
  );
}
