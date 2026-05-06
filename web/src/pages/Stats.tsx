import { useMemo } from "react";

import { BarChart, Donut, Heatmap, HeatmapCell, HeatmapColumn, StatCard } from "../components/charts";
import CrossEvalScoreboard from "../components/CrossEvalScoreboard";
import { dataset, tacticLabel } from "../lib/cases";
import { downloadNavigatorLayer } from "../lib/navigatorExport";

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
    const tacticBuckets: Record<string, number> = {};
    const severityBuckets: Record<string, number> = {};
    const sourceBuckets: Record<string, number> = {};
    const perCase: { id: string; title: string; recordCount: number; tactic: string }[] = [];

    for (const c of dataset.cases) {
      const pos = c.fixture_record_counts.positive;
      const neg = c.fixture_record_counts.negative;
      const recordCount = pos + neg;
      totalRecords += recordCount;
      positives += pos;
      negatives += neg;

      tacticBuckets[c.mitre_tactic] = (tacticBuckets[c.mitre_tactic] ?? 0) + 1;
      severityBuckets[c.severity] = (severityBuckets[c.severity] ?? 0) + 1;

      const kind = c.wiring.fixture_kind ?? "unknown";
      sourceBuckets[kind] = (sourceBuckets[kind] ?? 0) + 1;

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
      tacticBuckets,
      severityBuckets,
      sourceBuckets,
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
        <div className="action-row">
          <button type="button" className="btn" onClick={downloadNavigatorLayer}>
            ⬇ Download ATT&amp;CK Navigator layer
          </button>
          <a
            href="https://mitre-attack.github.io/attack-navigator/"
            target="_blank"
            rel="noreferrer"
            className="btn"
          >
            Open Navigator ↗
          </a>
        </div>
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
          label="Telemetry sources"
          value={Object.keys(data.sourceBuckets).length}
          hint={Object.entries(data.sourceBuckets)
            .map(([k, v]) => `${v} ${k.replace("_", " ")}`)
            .join(" · ")}
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
          <h3>Cross-evaluation scoreboard</h3>
          <span className="muted">specificity check · runs every detector × every fixture in your browser</span>
        </div>
        <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
          A well-tuned detection fires on its own positive fixture, stays silent on its own
          negative fixture, and stays silent on every <em>other</em> case's fixtures too.
          This grid runs every shipped detector against every shipped case's fixtures and
          colour-codes the result. The diagonal should glow green; everything else should be quiet.
        </p>
        <CrossEvalScoreboard />
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
          <h3>What this lab can't catch (and why)</h3>
          <span className="muted">honest gaps · scoping the network-detection charter</span>
        </div>
        <div className="gaps">
          <div className="gaps__item">
            <h4>Process / EDR telemetry</h4>
            <p>
              detlab is a <em>network-detection</em> lab — it consumes Zeek and Suricata.
              Anything that needs Sysmon / WinEvtx / EDR logs (T1059 PowerShell, T1003 LSASS
              dumping, T1547 persistence) is out of scope by design.
            </p>
          </div>
          <div className="gaps__item">
            <h4>Encrypted-payload C2</h4>
            <p>
              Tools that piggy-back on legitimate-looking TLS to a known CDN
              (Cobalt Strike + Cloudflare domain fronting, custom HTTPS implants
              with stolen certs) defeat byte-pattern and host-header rules.
              JA3/JA4 fingerprinting is the next frontier — not yet wired up here.
            </p>
          </div>
          <div className="gaps__item">
            <h4>Long-tail jitter / anti-detection beacons</h4>
            <p>
              Sliver with <code>--jitter 50</code> or random-walk schedulers
              push the timing-variance signal past detlab's CoV threshold.
              The T1071.001 tuning knobs let you trade jitter coverage for FPs;
              the lab does not yet ship pre-tuned profiles per environment.
            </p>
          </div>
          <div className="gaps__item">
            <h4>Initial access / Application-layer exploits</h4>
            <p>
              T1190 (exploit public-facing app) and T1133 (external remote services)
              show up most cleanly in IDS / WAF telemetry — Suricata's eve.json is
              ingested by the lab but no case maps an alert family yet. Planned
              follow-up.
            </p>
          </div>
          <div className="gaps__item">
            <h4>Identity-driven attacks</h4>
            <p>
              T1078 valid accounts, T1098 account manipulation, password-spraying
              variants — all need authentication-system telemetry (AD logs, IdP
              audit). Out of scope; pair detlab with an identity-detection lab.
            </p>
          </div>
          <div className="gaps__item">
            <h4>Adversary infrastructure pivots</h4>
            <p>
              The Tor case is IOC-driven — refresh the lookup or you go blind.
              Bridges, meek, snowflake, and obfs4 transports specifically defeat
              the public-relay-IP signal. A traffic-analysis-based detection
              would be a nice add (out of scope today).
            </p>
          </div>
        </div>
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
