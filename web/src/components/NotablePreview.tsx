/* Splunk ES Notable Event preview.
 *
 * When a detlab correlation search fires in Splunk Enterprise Security,
 * the SOC analyst sees the alert in Incident Review — a one-row notable
 * event with status / urgency / owner / drilldowns. Most portfolio
 * sites describe this; this component *renders* it.
 *
 * Mocks the Incident Review chrome (status pill, urgency, contributing
 * risk, raw event, expand-for-fields, drilldown links) using the
 * actual case metadata so the visitor sees what the artifact looks like
 * end-to-end.
 *
 * Lives inside the "Run in Splunk" tab next to the dashboard preview.
 */

import { useState } from "react";

import { CaseFull } from "../lib/cases";

const URGENCY: Record<string, { label: string; color: string }> = {
  critical: { label: "Critical", color: "var(--danger)" },
  high:     { label: "High",     color: "#fb8c00" },
  medium:   { label: "Medium",   color: "var(--warn)" },
  low:      { label: "Low",      color: "#7cb342" },
};

function exampleSrc(c: CaseFull): string {
  // Pick a plausible source IP / username for the synthetic notable.
  if (c.risk?.object_type === "user") return "alex.davis@corp";
  return "10.0.42.18";
}

function formattedTime(): string {
  const d = new Date();
  d.setMinutes(d.getMinutes() - 14);
  return d.toISOString().slice(0, 19).replace("T", " ");
}

export default function NotablePreview({ c }: { c: CaseFull }) {
  const [open, setOpen] = useState(false);
  const urgency = URGENCY[c.severity] ?? URGENCY.medium;
  const src = exampleSrc(c);
  const ts = formattedTime();
  const risk = c.risk?.score ?? 0;
  const technique = c.mitre_technique;
  const tactic = c.mitre_tactic;

  return (
    <div className="notable">
      <div className="notable__chrome">
        <span className="notable__app">Splunk ES › Incident Review</span>
        <span className="notable__filter muted">
          status="new" earliest=-24h | urgency:{c.severity}
        </span>
      </div>

      <div className="notable__row" onClick={() => setOpen(!open)} role="button" tabIndex={0}>
        <div className="notable__cell notable__cell--time">
          <code>{ts}</code>
          <span className="muted" style={{ fontSize: 11 }}>−14m ago</span>
        </div>

        <div className="notable__cell notable__cell--main">
          <div className="notable__title">{c.title}</div>
          <div className="notable__meta">
            <code>{technique}</code>
            <span>·</span>
            <span>{tactic}</span>
            <span>·</span>
            <span>src=<code>{src}</code></span>
          </div>
        </div>

        <div className="notable__cell">
          <span
            className="notable__urgency"
            style={{ borderColor: urgency.color, color: urgency.color }}
          >
            {urgency.label}
          </span>
        </div>

        <div className="notable__cell">
          <span className="notable__status">New</span>
        </div>

        <div className="notable__cell">
          <span className="notable__owner muted">unassigned</span>
        </div>

        <div className="notable__cell notable__cell--right">
          <span className="notable__risk" title={`Risk score contribution: +${risk}`}>
            +{risk} risk
          </span>
        </div>

        <div className="notable__cell notable__cell--toggle" aria-hidden="true">
          {open ? "−" : "+"}
        </div>
      </div>

      {open && (
        <div className="notable__expand">
          <div className="notable__panel">
            <h4>Contributing event</h4>
            <pre className="notable__event">
{`_time: ${ts}
src: ${src}
mitre_technique: ${technique}
mitre_tactic: ${tactic}
case_id: ${c.id}
case_title: ${c.title}
severity: ${c.severity}
risk_score: ${risk}`}
            </pre>
          </div>

          <div className="notable__panel">
            <h4>Recommended actions</h4>
            <ol>
              {(c.triage?.steps ?? []).slice(0, 3).map((step, i) => (
                <li key={i}>{step}</li>
              ))}
              {(c.triage?.steps ?? []).length === 0 && (
                <li className="muted">Triage steps not yet authored.</li>
              )}
            </ol>
          </div>

          <div className="notable__panel">
            <h4>Drill-downs</h4>
            <ul className="notable__links">
              <li>
                <code>case_dashboard</code> — open the per-detection view (
                <code>{c.view_name}</code>)
              </li>
              <li>
                <code>asset_investigator</code> — pivot to all events involving{" "}
                <code>src={src}</code> in the last 24h
              </li>
              <li>
                <code>risk_history</code> — show recent risk-score contributions
                for <code>{src}</code>
              </li>
              <li>
                <code>kill_chain_view</code> — check whether this fires inside a
                broader chain via <code>detlab_kill_chain</code>
              </li>
            </ul>
          </div>
        </div>
      )}

      <p className="notable__caption">
        Mocked from this case's risk score, severity, and triage metadata —
        what an analyst sees in real Splunk ES Incident Review when the
        correlation search fires. Click the row to expand.
      </p>
    </div>
  );
}
