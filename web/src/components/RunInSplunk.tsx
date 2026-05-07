/* The "Run in Splunk" tab content. Three pieces:
 *
 *   1. Status — whether the user has configured a Splunk host
 *   2. Deep-link buttons — Open the case dashboard / run the SPL search
 *   3. Copy-pasteable SPL with a time-range picker
 *
 * If no Splunk host is configured, the deep-link buttons render disabled
 * with a hint pointing to the header settings cog. The SPL block is
 * always usable (copy + paste into any Splunk instance). */

import { useEffect, useMemo, useState } from "react";

import { CaseFull } from "../lib/cases";
import { dashboardUrl, getSplunkHost, searchUrl, stripSplComments } from "../lib/splunk";
import CodeBlock from "./CodeBlock";
import NotablePreview from "./NotablePreview";
import SplunkDashboardPreview from "./SplunkDashboardPreview";

const TIME_PRESETS: { label: string; earliest: string; latest: string }[] = [
  { label: "Last 24 hours", earliest: "-24h", latest: "now" },
  { label: "Last 7 days", earliest: "-7d", latest: "now" },
  { label: "Last 30 days", earliest: "-30d", latest: "now" },
  { label: "All time", earliest: "0", latest: "now" },
];

export default function RunInSplunk({ c }: { c: CaseFull }) {
  // Re-read the host on every mount + on storage events so the buttons
  // light up the moment the user fills in the settings cog.
  const [host, setHost] = useState(getSplunkHost());
  const [presetIdx, setPresetIdx] = useState(0);

  useEffect(() => {
    function refresh() {
      setHost(getSplunkHost());
    }
    window.addEventListener("storage", refresh);
    window.addEventListener("focus", refresh);
    const interval = window.setInterval(refresh, 1000);
    return () => {
      window.removeEventListener("storage", refresh);
      window.removeEventListener("focus", refresh);
      window.clearInterval(interval);
    };
  }, []);

  const preset = TIME_PRESETS[presetIdx];
  const splBody = useMemo(() => stripSplComments(c.detection.spl), [c.detection.spl]);
  const dashUrl = dashboardUrl(c.view_name);
  const sUrl = searchUrl(splBody, preset.earliest, preset.latest);

  return (
    <div>
      <div className={`splunk-status splunk-status--${host ? "configured" : "missing"}`}>
        {host ? (
          <>
            <span className="splunk-status__dot" /> Connected to{" "}
            <code>{host}</code> — every link below opens in your Splunk.
          </>
        ) : (
          <>
            <span className="splunk-status__dot" /> No Splunk host configured.
            Click <strong>⚙ Splunk</strong> in the top-right of this page to add yours;
            the SPL block below is still copy-pasteable.
          </>
        )}
      </div>

      <h3 style={{ marginTop: 24 }}>What an analyst sees in ES</h3>
      <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
        The notable event format Splunk Enterprise Security renders in
        Incident Review when this rule fires — urgency, status, owner,
        contributing risk, and the standard ES drill-downs. Click the row
        to expand contributing event, triage steps, and pivots.
      </p>
      <NotablePreview c={c} />

      <h3 style={{ marginTop: 24 }}>Dashboard preview</h3>
      <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
        What the case's per-detection dashboard would look like in your Splunk
        — populated from a live detector run on the bundled fixture, no Splunk
        install required.
      </p>
      <SplunkDashboardPreview c={c} />

      <h3 style={{ marginTop: 24 }}>Open the case dashboard</h3>
      <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
        The detlab Splunk app ships a per-case dashboard at{" "}
        <code>/{c.view_name}</code>. Once installed in your Splunk, this button
        opens it directly.
      </p>
      <div className="action-row">
        {dashUrl ? (
          <a className="btn btn--primary" href={dashUrl} target="_blank" rel="noreferrer">
            Open <code>{c.view_name}</code> dashboard ↗
          </a>
        ) : (
          <button className="btn" type="button" disabled title="Set your Splunk host first">
            Open dashboard (host not set)
          </button>
        )}
        <a
          className="btn"
          href="https://github.com/JacobRHess/detlab/releases"
          target="_blank"
          rel="noreferrer"
        >
          .spl release ↗
        </a>
      </div>

      <h3 style={{ marginTop: 24 }}>Run the saved search</h3>
      <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
        The SPL below is the production rule from{" "}
        <code>cases/{c.id}/detection/search.spl</code>. Pick a time range and
        either copy-paste it into Splunk Search &amp; Reporting or use the
        deep-link button.
      </p>

      <div className="splunk-time">
        <span className="splunk-time__label">time range</span>
        {TIME_PRESETS.map((p, i) => (
          <button
            key={p.label}
            type="button"
            className={`splunk-time__btn ${i === presetIdx ? "splunk-time__btn--on" : ""}`}
            onClick={() => setPresetIdx(i)}
          >
            {p.label}
          </button>
        ))}
        <div className="splunk-time__earliest">
          <code>earliest={preset.earliest}</code>
          <code>latest={preset.latest}</code>
        </div>
      </div>

      <CodeBlock label="search.spl — production rule" code={splBody} />

      <div className="action-row">
        {sUrl ? (
          <a className="btn btn--primary" href={sUrl} target="_blank" rel="noreferrer">
            Run in Splunk Search ↗
          </a>
        ) : (
          <button className="btn" type="button" disabled title="Set your Splunk host first">
            Run in Splunk (host not set)
          </button>
        )}
      </div>

      <h3 style={{ marginTop: 24 }}>Or drive it programmatically</h3>
      <p className="muted" style={{ fontSize: 13 }}>
        For the full end-to-end demo (HEC fixture-load + REST saved-search
        execution against your Splunk), use{" "}
        <a
          href="https://github.com/JacobRHess/detlab/blob/main/lab/SPLUNK_DEMO.md"
          target="_blank"
          rel="noreferrer"
        >
          <code>scripts/splunk_demo.py</code>
        </a>
        . That CLI ingests every case's positive fixture via HEC, fires every
        saved search, polls each job to completion, and prints alert counts.
      </p>
    </div>
  );
}
