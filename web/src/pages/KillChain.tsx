/* Kill-chain meta-detector visualization page.
 *
 * Generates a multi-stage synthetic intrusion (one source IP firing
 * recon → exploit → C2 → lateral → exfil), runs every detector via
 * Pyodide, and renders the resulting timeline. The page is self-driving:
 * a "Run demo" button kicks off the analysis and a horizontal swimlane
 * shows each technique on the chain in chronological order.
 *
 * The point: each individual detection is useful, but the *sequence* is
 * what tells a SOC analyst they're looking at a real intrusion and not
 * a single-detector false positive. */

import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { KillChainResult, runKillChain } from "../lib/pyodide";
import { tacticColor } from "../lib/tactic";

interface Scenario {
  id: string;
  title: string;
  blurb: string;
  src: string;
  generate: (src: string) => string;
}

function jsonl(records: object[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

/** Synthetic 'ransomware-style' intrusion. Same source IP touches every
 * stage from external recon to exfiltration. Fires ~7 distinct techniques.
 * Timestamps are evenly spaced over ~30 minutes so the timeline is readable. */
function ransomwareScenario(src: string): string {
  const t0 = 1_700_000_000;
  const records: object[] = [];

  // 1. Recon — port scan against an internal target.
  for (let i = 0; i < 130; i++) {
    records.push({
      ts: t0 + i * 0.05,
      "id.orig_h": src,
      "id.resp_h": "10.0.0.50",
      "id.resp_p": 1024 + i,
      proto: "tcp",
      duration: 0.01,
      orig_bytes: 0,
      resp_bytes: 0,
      conn_state: "REJ",
    });
  }
  // 2. Initial access — Suricata exploit alert (web app).
  for (let i = 0; i < 5; i++) {
    records.push({
      timestamp: new Date((t0 + 60 + i * 5) * 1000).toISOString(),
      event_type: "alert",
      src_ip: src,
      dest_ip: "10.0.0.50",
      proto: "TCP",
      alert: {
        signature: `ET WEB_SPECIFIC_APPS Apache Log4j RCE attempt`,
        signature_id: 2034647 + i,
        category: "Attempted Administrator Privilege Gain",
        severity: 1,
      },
    });
  }
  // 3. Persistence — external remote service abuse (RDP from external).
  for (let i = 0; i < 3; i++) {
    records.push({
      ts: t0 + 300 + i,
      "id.orig_h": src,
      "id.resp_h": `10.0.0.${30 + i}`,
      "id.resp_p": 3389,
      proto: "tcp",
      service: "rdp",
      duration: 60,
      orig_bytes: 50_000,
      resp_bytes: 200_000,
      conn_state: "SF",
    });
  }
  // 4. C2 — HTTP beaconing back to attacker.
  for (let i = 0; i < 60; i++) {
    records.push({
      ts: t0 + 600 + i * 10,
      "id.orig_h": src,
      "id.resp_h": "203.0.113.7",
      "id.resp_p": 443,
      proto: "tcp",
      service: "ssl",
      duration: 0.3,
      orig_bytes: 480,
      resp_bytes: 240,
      conn_state: "SF",
    });
  }
  // 5. Lateral movement — internal RDP fan-out.
  for (let i = 0; i < 6; i++) {
    records.push({
      ts: t0 + 1100 + i * 5,
      "id.orig_h": src,
      "id.resp_h": `10.0.1.${100 + i}`,
      "id.resp_p": 3389,
      proto: "tcp",
      service: "rdp",
      duration: 120,
      orig_bytes: 80_000,
      resp_bytes: 300_000,
      conn_state: "SF",
    });
  }
  // 6. Lateral tool transfer — SMB write of a large payload to one host.
  records.push({
    ts: t0 + 1300,
    "id.orig_h": src,
    "id.resp_h": "10.0.1.100",
    "id.resp_p": 445,
    proto: "tcp",
    service: "smb",
    duration: 30,
    orig_bytes: 12_000_000,
    resp_bytes: 5_000,
    conn_state: "SF",
  });
  // 7. Cloud exfil — large uplink to AWS S3 IP range.
  for (let i = 0; i < 12; i++) {
    records.push({
      ts: t0 + 1500 + i * 30,
      "id.orig_h": src,
      "id.resp_h": "52.216.20.5",
      "id.resp_p": 443,
      proto: "tcp",
      service: "ssl",
      duration: 60,
      orig_bytes: 6_000_000,
      resp_bytes: 5_000,
      conn_state: "SF",
    });
  }
  return jsonl(records);
}

/** A subtler scenario — DNS tunneling C2 + RMM resolution + DNS exfil
 * from the same insider. Three distinct techniques, all DNS-flavored,
 * showing the meta-detector catches things even when the underlying
 * detectors all share a telemetry source. */
function insiderDnsScenario(src: string): string {
  const t0 = 1_700_000_000;
  const records: object[] = [];

  // 1. RMM resolution — single AnyDesk lookup.
  records.push({
    ts: t0,
    "id.orig_h": src,
    "id.resp_h": "10.0.0.53",
    query: "anydesk.com",
    qtype_name: "A",
    rcode_name: "NOERROR",
  });
  // 2. DNS tunneling — 70 long-label TXT queries to evilc2.example.
  for (let i = 0; i < 70; i++) {
    records.push({
      ts: t0 + 60 + i * 0.5,
      "id.orig_h": src,
      "id.resp_h": "10.0.0.53",
      query: `vqfh3rsx7zaby4nklm5q6t7u8wp9c2g${i.toString().padStart(4, "0")}.evilc2.example`,
      qtype_name: "TXT",
      rcode_name: "NOERROR",
    });
  }
  // 3. DNS exfil — 50 super-long-label A queries to a different domain
  //    (volume-based exfiltration signature).
  for (let i = 0; i < 50; i++) {
    records.push({
      ts: t0 + 200 + i * 0.5,
      "id.orig_h": src,
      "id.resp_h": "10.0.0.53",
      query:
        `${"x".repeat(60)}.${i.toString().padStart(3, "0")}.exfilsink.example`,
      qtype_name: "A",
      rcode_name: "NOERROR",
    });
  }
  return jsonl(records);
}

const SCENARIOS: Scenario[] = [
  {
    id: "ransomware",
    title: "Ransomware kill chain",
    blurb:
      "Recon → exploit → external RDP → HTTP beacon → internal RDP fan-out → SMB tool transfer → cloud exfil. One source IP, ~30 minutes.",
    src: "10.0.0.42",
    generate: ransomwareScenario,
  },
  {
    id: "insider-dns",
    title: "DNS-only insider",
    blurb:
      "RMM resolution → DNS tunneling C2 → DNS exfiltration. Three distinct techniques on the same DNS sensor — the meta-detector chains them.",
    src: "10.0.0.77",
    generate: insiderDnsScenario,
  },
];

function formatRelativeSeconds(s: number): string {
  if (s < 1) return "0s";
  if (s < 60) return `${s.toFixed(0)}s`;
  if (s < 3600) return `${(s / 60).toFixed(1)}m`;
  if (s < 86_400) return `${(s / 3600).toFixed(1)}h`;
  return `${(s / 86_400).toFixed(1)}d`;
}

function tacticLabel(tactic: string): string {
  return tactic
    .split("-")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join(" ");
}

function ChainTimeline({ chain }: { chain: KillChainResult }) {
  const span = chain.duration_seconds || 1;
  return (
    <div className="killchain-card">
      <div className="killchain-card__head">
        <div>
          <div className="killchain-card__src">
            <code>{chain.src}</code>
          </div>
          <div className="killchain-card__meta">
            <span>
              <strong>{chain.technique_count}</strong> techniques
            </span>
            <span>
              <strong>{chain.tactic_count}</strong> tactics
            </span>
            <span>
              span <strong>{formatRelativeSeconds(chain.duration_seconds)}</strong>
            </span>
          </div>
        </div>
        <div className="killchain-card__tactics">
          {chain.tactics.map((t) => (
            <span
              key={t}
              className="killchain-tactic-pill"
              style={{ borderColor: tacticColor(t) }}
            >
              {tacticLabel(t)}
            </span>
          ))}
        </div>
      </div>

      <ol className="killchain-timeline">
        {chain.timeline.map((step, idx) => {
          const offset =
            chain.earliest_ts > 0 && step.timestamp > 0
              ? ((step.timestamp - chain.earliest_ts) / span) * 100
              : (idx / Math.max(1, chain.timeline.length - 1)) * 100;
          return (
            <li key={`${step.technique}-${idx}`} className="killchain-step">
              <div
                className="killchain-step__rail"
                style={{
                  background: tacticColor(step.tactic),
                  marginLeft: `${offset.toFixed(1)}%`,
                }}
              />
              <div className="killchain-step__body">
                <div className="killchain-step__head">
                  <span className="killchain-step__num">{idx + 1}</span>
                  <code className="killchain-step__tech">{step.technique}</code>
                  <Link to={`/case/${step.case_id}`} className="killchain-step__title">
                    {step.case_title}
                  </Link>
                  <span className="killchain-step__tactic">{tacticLabel(step.tactic)}</span>
                </div>
                <div className="killchain-step__detail">
                  <span className="muted">fired</span>{" "}
                  <code>{step.detector_function}</code>
                  {step.detail && <> · {step.detail}</>}
                </div>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export default function KillChain() {
  const [scenarioId, setScenarioId] = useState(SCENARIOS[0].id);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{
    chains: KillChainResult[];
    recordCount: number;
    durationMs: number;
  } | null>(null);

  const scenario = useMemo(
    () => SCENARIOS.find((s) => s.id === scenarioId) ?? SCENARIOS[0],
    [scenarioId],
  );
  const fixture = useMemo(() => scenario.generate(scenario.src), [scenario]);

  async function run() {
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const r = await runKillChain(fixture, setStatus);
      setResult(r);
      setStatus(`Ran ${r.recordCount.toLocaleString()} records in ${r.durationMs.toFixed(0)} ms.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStatus("");
    } finally {
      setRunning(false);
    }
  }

  // Auto-clear result on scenario change so the user knows to re-run.
  useEffect(() => {
    setResult(null);
    setStatus("");
    setError(null);
  }, [scenarioId]);

  return (
    <article>
      <div className="page-header">
        <h1>Kill-chain meta-detector</h1>
        <p className="muted" style={{ maxWidth: 760 }}>
          Each individual detection is useful, but the <em>sequence</em> is what tells
          a SOC analyst they're looking at a real intrusion and not a single-detector
          false positive. The kill-chain meta-detector runs every per-case detector
          against the input, groups alerts by source IP, and surfaces sources that
          fire two or more distinct ATT&amp;CK techniques inside a 24-hour window.
          Same logic ships as the <code>detlab_kill_chain</code> Splunk macro.
        </p>
      </div>

      <section className="killchain-controls">
        <div className="killchain-controls__row">
          <span className="killchain-controls__label">demo scenario</span>
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              type="button"
              className={`btn ${s.id === scenarioId ? "btn--primary" : ""}`}
              onClick={() => setScenarioId(s.id)}
            >
              {s.title}
            </button>
          ))}
        </div>
        <p className="muted" style={{ fontSize: 13, margin: "8px 0 12px" }}>
          {scenario.blurb} <span className="dim">source: <code>{scenario.src}</code></span>
        </p>
        <div className="killchain-controls__row">
          <button type="button" className="btn btn--primary" onClick={run} disabled={running}>
            {running ? "Running…" : "Run kill-chain analysis"}
          </button>
          {status && <span className="muted" style={{ fontSize: 13 }}>{status}</span>}
        </div>
      </section>

      {error && (
        <div className="empty-state">
          <p>Failed to run analysis: {error}</p>
        </div>
      )}

      {result && result.chains.length === 0 && (
        <div className="empty-state">
          <p>
            ✓ Detector returned 0 chains on this input — no source fired ≥2
            distinct techniques inside the window.
          </p>
        </div>
      )}

      {result && result.chains.length > 0 && (
        <section className="killchain-results">
          {result.chains.map((c) => (
            <ChainTimeline key={c.src} chain={c} />
          ))}
        </section>
      )}

      {!result && !running && (
        <ScenarioPreview scenario={scenario} fixture={fixture} />
      )}
    </article>
  );
}

function ScenarioPreview({ scenario, fixture }: { scenario: Scenario; fixture: string }) {
  const lineCount = fixture.split("\n").length;
  const sample = fixture.split("\n").slice(0, 3).join("\n");
  return (
    <section style={{ marginTop: 12 }}>
      <h3>What's in the input</h3>
      <p className="muted" style={{ fontSize: 13 }}>
        <strong>{lineCount.toLocaleString()}</strong> JSON records — synthetic Zeek and
        Suricata events that mirror a real {scenario.title.toLowerCase()}. The first
        three records:
      </p>
      <pre className="codeblock"><code>{sample}</code></pre>
    </section>
  );
}

