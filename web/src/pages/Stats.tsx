import { useMemo } from "react";

import { BarChart, Donut, Heatmap, HeatmapCell, HeatmapColumn, StatCard } from "../components/charts";
import { dataset, tacticLabel } from "../lib/cases";
import { summarize } from "../lib/fixtureStats";

const SEVERITY_COLOR: Record<string, string> = {
  low: "#53a051",
  medium: "#f8be34",
  high: "#dc4e41",
  critical: "#dc4e41",
};

// MITRE ATT&CK enterprise tactics, in the canonical order used by the navigator.
// Tactics with no detlab cases will render as empty columns to make the
// "what we're not yet covering" obvious.
const ATTACK_TACTICS: { key: string; label: string }[] = [
  { key: "reconnaissance", label: "Reconnaissance" },
  { key: "resource-development", label: "Resource Dev" },
  { key: "initial-access", label: "Initial Access" },
  { key: "execution", label: "Execution" },
  { key: "persistence", label: "Persistence" },
  { key: "privilege-escalation", label: "Priv. Escalation" },
  { key: "defense-evasion", label: "Defense Evasion" },
  { key: "credential-access", label: "Credential Access" },
  { key: "discovery", label: "Discovery" },
  { key: "lateral-movement", label: "Lateral Movement" },
  { key: "collection", label: "Collection" },
  { key: "command-and-control", label: "Command & Control" },
  { key: "exfiltration", label: "Exfiltration" },
  { key: "impact", label: "Impact" },
];

export default function Stats() {
  const data = useMemo(() => {
    let totalRecords = 0;
    let positives = 0;
    let negatives = 0;
    let connRecords = 0;
    let dnsRecords = 0;
    const tacticBuckets: Record<string, number> = {};
    const severityBuckets: Record<string, number> = {};
    const perCase: { id: string; title: string; recordCount: number; tactic: string }[] = [];

    for (const c of dataset.cases) {
      const pos = c.fixtures.positive ? summarize(c.fixtures.positive.content) : null;
      const neg = c.fixtures.negative ? summarize(c.fixtures.negative.content) : null;
      const recordCount = (pos?.recordCount ?? 0) + (neg?.recordCount ?? 0);
      totalRecords += recordCount;
      positives += pos?.recordCount ?? 0;
      negatives += neg?.recordCount ?? 0;
      if (pos?.hasDns || neg?.hasDns) dnsRecords += recordCount;
      if (pos?.hasConn || neg?.hasConn) connRecords += recordCount;

      tacticBuckets[c.mitre_tactic] = (tacticBuckets[c.mitre_tactic] ?? 0) + 1;
      severityBuckets[c.severity] = (severityBuckets[c.severity] ?? 0) + 1;

      perCase.push({
        id: c.id,
        title: c.title,
        recordCount,
        tactic: c.mitre_tactic,
      });
    }

    return {
      totalRecords,
      positives,
      negatives,
      connRecords,
      dnsRecords,
      tacticBuckets,
      severityBuckets,
      perCase,
    };
  }, []);

  const heatmapColumns: HeatmapColumn[] = useMemo(() => {
    return ATTACK_TACTICS.map((t) => {
      const cases = dataset.cases.filter((c) => c.mitre_tactic === t.key);
      const planned = dataset.planned.filter((p) => p.mitre_tactic === t.key);
      const cells: HeatmapCell[] = [];
      for (const c of cases) {
        cells.push({
          id: c.mitre_technique,
          label: c.title,
          href: `#/case/${c.id}`,
          intensity: c.severity === "high" || c.severity === "critical" ? 1 : 0.6,
          status: "shipped",
        });
      }
      for (const p of planned) {
        cells.push({
          id: p.mitre_technique,
          label: p.title,
          href: p.mitre_url,
          intensity: 0.5,
          status: "planned",
        });
      }
      if (cells.length === 0) {
        cells.push({
          id: "—",
          label: "no detlab coverage",
          intensity: 0,
          status: "uncovered",
        });
      }
      return { title: t.label, cells };
    });
  }, []);

  const severityData = Object.entries(data.severityBuckets).map(([sev, count]) => ({
    label: sev.charAt(0).toUpperCase() + sev.slice(1),
    value: count,
    color: SEVERITY_COLOR[sev] ?? "var(--accent)",
  }));

  const tacticData = Object.entries(data.tacticBuckets)
    .map(([tactic, count]) => ({ label: tacticLabel(tactic), value: count }))
    .sort((a, b) => b.value - a.value);

  const perCaseData = data.perCase
    .sort((a, b) => b.recordCount - a.recordCount)
    .map((c) => ({
      label: c.title,
      value: c.recordCount,
      color: "var(--accent)",
      href: `#/case/${c.id}`,
    }));

  return (
    <>
      <section className="hero">
        <span className="hero__eyebrow">lab telemetry · live computation</span>
        <h1>What's actually in this lab.</h1>
        <p>
          Every number on this page is computed in your browser from the same
          <code> cases.json </code> the rest of the site reads. No server, no
          analytics — just a tour of the detection surface, the fixtures backing
          it, and where the lab is headed next on the MITRE ATT&amp;CK matrix.
        </p>
      </section>

      <div className="stats-grid">
        <StatCard
          label="Cases shipped"
          value={dataset.cases.length}
          accent="var(--shipped)"
          hint={`across ${Object.keys(data.tacticBuckets).length} ATT&CK tactics`}
        />
        <StatCard
          label="Test-fixture records"
          value={data.totalRecords.toLocaleString()}
          hint={`${data.positives.toLocaleString()} positive · ${data.negatives.toLocaleString()} negative`}
        />
        <StatCard
          label="ATT&CK techniques covered"
          value={dataset.cases.length}
          hint={`${dataset.planned.length} planned`}
        />
        <StatCard
          label="Detector functions"
          value={dataset.cases.length}
          hint="all stdlib-only Python · run unchanged in browser"
        />
      </div>

      <section className="section-block">
        <div className="section-block__title">
          <h3>ATT&amp;CK coverage map</h3>
          <span className="muted">enterprise tactics · click a covered cell to drill in</span>
        </div>
        <Heatmap columns={heatmapColumns} />
      </section>

      <section className="section-block">
        <div className="section-block__title">
          <h3>Cases by tactic</h3>
          <span className="muted">where the lab focuses</span>
        </div>
        <BarChart data={tacticData} />
      </section>

      <section className="section-block">
        <div className="section-block__title">
          <h3>Severity mix</h3>
          <span className="muted">alert.severity values across shipped saved searches</span>
        </div>
        <Donut
          data={severityData}
          centerValue={dataset.cases.length}
          centerLabel="cases"
        />
      </section>

      <section className="section-block">
        <div className="section-block__title">
          <h3>Fixture record counts</h3>
          <span className="muted">positive + negative, per case</span>
        </div>
        <BarChart data={perCaseData} />
      </section>

      <section className="section-block">
        <div className="section-block__title">
          <h3>Detection styles in this lab</h3>
          <span className="muted">five distinct approaches</span>
        </div>
        <table className="confusion-table">
          <thead>
            <tr>
              <th>Style</th>
              <th>Cases</th>
              <th>What signal it keys on</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Aggregation + threshold</td>
              <td>T1071.004 · T1048.003 · T1110.001 · T1046</td>
              <td className="muted-cell">group records over a window, count / sum / avg, threshold</td>
            </tr>
            <tr>
              <td>Timing variance (CoV)</td>
              <td>T1071.001</td>
              <td className="muted-cell">stddev of inter-connection intervals; low CoV = beacon</td>
            </tr>
            <tr>
              <td>Per-record threshold</td>
              <td>T1572</td>
              <td className="muted-cell">duration + bytes on a single conn.log row, port-restricted</td>
            </tr>
            <tr>
              <td>IOC enrichment (lookup)</td>
              <td>T1090.003</td>
              <td className="muted-cell">match dest IP against a refreshed relay list</td>
            </tr>
            <tr>
              <td>Entropy + structure</td>
              <td>T1568.002 · T1071.004</td>
              <td className="muted-cell">randomness of base or sub-domain labels</td>
            </tr>
          </tbody>
        </table>
      </section>
    </>
  );
}
