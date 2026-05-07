/* Splunk macro library — every SPL macro the detlab app ships, in one
 * page. The Splunk admin's two questions when bolting a new content
 * pack into their environment are:
 *
 *   1. What macros does this define, and what do they do?
 *   2. How do I call them in my own searches?
 *
 * This page answers both: the shared rollup macros (detlab_kill_chain,
 * detlab_all_alerts, detlab_cim_*) up top, then every per-case macro
 * grouped by the case it belongs to. Each definition has a copy button
 * and renders the SPL with line breaks intact (Splunk's `\` continuation
 * is unfolded into multi-line for readability).
 */

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { dataset, MacroEntry } from "../lib/cases";

function copyToClipboard(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text);
  }
  return Promise.reject(new Error("clipboard unavailable"));
}

function MacroCard({ macro, idx }: { macro: MacroEntry; idx: number }) {
  const [copied, setCopied] = useState(false);
  const [open, setOpen] = useState(idx < 3); // expand the first few for visual heft

  function handleCopy() {
    copyToClipboard(macro.definition)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1400);
      })
      .catch(() => {
        /* clipboard blocked — silently no-op */
      });
  }

  const isShared = !macro.case_id;

  return (
    <div className={`macro-card ${isShared ? "macro-card--shared" : ""}`}>
      <div className="macro-card__head">
        <div className="macro-card__name">
          <span aria-hidden="true">`</span>
          {macro.name}
          <span aria-hidden="true">`</span>
          {isShared && <span className="macro-card__badge">shared</span>}
        </div>
        <div className="macro-card__actions">
          {macro.case_id && (
            <Link to={`/case/${macro.case_id}`} className="macro-card__action">
              open case ↗
            </Link>
          )}
          <button type="button" className="macro-card__action" onClick={handleCopy}>
            {copied ? "copied!" : "copy"}
          </button>
          <button
            type="button"
            className="macro-card__action"
            onClick={() => setOpen(!open)}
            aria-expanded={open}
          >
            {open ? "−" : "+"}
          </button>
        </div>
      </div>
      {macro.description && <p className="macro-card__desc">{macro.description}</p>}
      {open && (
        <pre className="macro-card__body">
          <code>{macro.definition || "(empty definition)"}</code>
        </pre>
      )}
    </div>
  );
}

export default function Macros() {
  const [filter, setFilter] = useState("");
  const all = dataset.macros;

  const sharedFiltered = useMemo(() => {
    if (!filter) return all.shared;
    const f = filter.toLowerCase();
    return all.shared.filter(
      (m) =>
        m.name.toLowerCase().includes(f) ||
        m.description.toLowerCase().includes(f) ||
        m.definition.toLowerCase().includes(f),
    );
  }, [filter, all.shared]);

  const perCaseFiltered = useMemo(() => {
    if (!filter) return all.per_case;
    const f = filter.toLowerCase();
    return all.per_case.filter(
      (m) =>
        m.name.toLowerCase().includes(f) ||
        m.description.toLowerCase().includes(f) ||
        m.definition.toLowerCase().includes(f) ||
        (m.case_id ?? "").toLowerCase().includes(f),
    );
  }, [filter, all.per_case]);

  return (
    <article>
      <div className="page-header">
        <h1>Splunk macro library</h1>
        <p className="muted" style={{ maxWidth: 760 }}>
          Every SPL macro the detlab app installs, in one place. The shared
          macros at the top compose every per-case detection into a single
          alert feed (<code>detlab_all_alerts</code>) and a kill-chain rollup
          (<code>detlab_kill_chain</code>); the CIM aliases let ES data models
          accelerate the content. Below, every per-case detection macro is
          grouped by its case so you can copy it straight into Splunk.
        </p>
      </div>

      <section className="kpi-strip" style={{ marginTop: 12 }}>
        <div className="kpi">
          <div className="kpi__value" style={{ color: "var(--accent)" }}>{all.shared.length}</div>
          <div className="kpi__label">Shared macros</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{all.per_case.length}</div>
          <div className="kpi__label">Per-case macros</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{dataset.cases.length}</div>
          <div className="kpi__label">Cases</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">2</div>
          <div className="kpi__label">CIM data models</div>
        </div>
      </section>

      <div className="macro-filter">
        <input
          type="search"
          placeholder="Search macros, descriptions, SPL fragments…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          autoFocus
        />
        {filter && (
          <button type="button" className="btn" onClick={() => setFilter("")}>
            clear
          </button>
        )}
        <span className="muted" style={{ fontSize: 12, marginLeft: "auto" }}>
          {sharedFiltered.length + perCaseFiltered.length} matching
        </span>
      </div>

      <div className="section-title" style={{ marginTop: 18 }}>
        <h2>Shared macros</h2>
        <span className="muted">cross-case rollups + CIM aliases</span>
      </div>
      <div className="macro-grid">
        {sharedFiltered.map((m, i) => (
          <MacroCard key={m.name} macro={m} idx={i} />
        ))}
      </div>

      <div className="section-title" style={{ marginTop: 28 }}>
        <h2>Per-case detection macros</h2>
        <span className="muted">one per shipped case — call from saved searches or ad-hoc</span>
      </div>
      <div className="macro-grid">
        {perCaseFiltered.map((m, i) => (
          <MacroCard key={`${m.case_id}/${m.name}`} macro={m} idx={i} />
        ))}
      </div>

      <h3 style={{ marginTop: 28 }}>How macros connect</h3>
      <p className="muted" style={{ fontSize: 13, maxWidth: 760 }}>
        Per-case macros each emit one detection's events, with a shared schema
        (<code>case_id</code>, <code>case_title</code>, <code>view_name</code>,{" "}
        <code>mitre_technique</code>, <code>mitre_tactic</code>,{" "}
        <code>severity</code>). <code>detlab_all_alerts</code> unions them all
        into the single alert stream the dashboards and ES correlation searches
        consume. <code>detlab_kill_chain</code> aggregates that union by{" "}
        <code>src</code> and surfaces sources firing 2+ techniques.
      </p>
    </article>
  );
}
