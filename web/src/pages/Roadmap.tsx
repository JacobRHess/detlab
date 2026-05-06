import { Link } from "react-router-dom";

import { dataset, tacticLabel } from "../lib/cases";

const EFFORT_COLORS: Record<string, string> = {
  S: "var(--shipped)",
  M: "var(--warn)",
  L: "var(--danger)",
};

const STATUS_LABELS: Record<string, string> = {
  covered: "covered",
  partial: "partial",
  planned: "planned",
  out_of_scope: "out of scope",
};

const STATUS_BADGES: Record<string, string> = {
  covered: "badge--shipped",
  partial: "badge--medium",
  planned: "badge--planned",
  out_of_scope: "badge--planned",
};

export default function Roadmap() {
  const planned = [...dataset.planned].sort((a, b) =>
    a.mitre_tactic === b.mitre_tactic
      ? a.mitre_technique.localeCompare(b.mitre_technique)
      : a.mitre_tactic.localeCompare(b.mitre_tactic),
  );

  const outOfScope = dataset.tactics.filter((t) => t.status === "out_of_scope");
  const partial = dataset.tactics.filter((t) => t.status === "partial");

  return (
    <>
      <section className="hero">
        <span className="hero__eyebrow">coverage planning · what's coming</span>
        <h1>Roadmap</h1>
        <p>
          detlab has a deliberately narrow charter — <em>network-visible</em> detections
          on Zeek and Suricata. This page makes the planning rigour public: what's
          queued for the next few releases (with effort estimates and detection sketches),
          which tactics are honestly out of scope and why, and where the lab is at
          today across the full Enterprise ATT&amp;CK matrix.
        </p>
      </section>

      <section className="section-block">
        <div className="section-block__title">
          <h3>Coverage by tactic</h3>
          <span className="muted">14 Enterprise tactics · click for detail</span>
        </div>
        <div className="tactic-summary-grid">
          {dataset.tactics.map((t) => (
            <Link
              key={t.slug}
              to={`/tactic/${t.slug}`}
              className={`tactic-summary tactic-summary--${t.status}`}
            >
              <div className="tactic-summary__head">
                <span className="tactic-summary__name">{t.name}</span>
                <span className={`badge ${STATUS_BADGES[t.status]}`}>
                  {STATUS_LABELS[t.status]}
                </span>
              </div>
              <div className="tactic-summary__counts">
                {t.shipped_count > 0 && (
                  <span>
                    <strong>{t.shipped_count}</strong> shipped
                  </span>
                )}
                {t.planned_count > 0 && (
                  <span>
                    <strong>{t.planned_count}</strong> planned
                  </span>
                )}
                {t.shipped_count === 0 && t.planned_count === 0 && (
                  <span className="muted">scoping rationale →</span>
                )}
              </div>
            </Link>
          ))}
        </div>
      </section>

      <section className="section-block">
        <div className="section-block__title">
          <h3>Planned cases ({planned.length})</h3>
          <span className="muted">grouped by tactic · effort = S/M/L</span>
        </div>
        {planned.length === 0 ? (
          <p className="muted">All planned cases have shipped. Roadmap is empty.</p>
        ) : (
          <table className="confusion-table roadmap-table">
            <thead>
              <tr>
                <th>ATT&amp;CK</th>
                <th>Tactic</th>
                <th>Title</th>
                <th>Effort</th>
                <th>Why ship it</th>
                <th>Detection sketch</th>
              </tr>
            </thead>
            <tbody>
              {planned.map((p) => (
                <tr key={p.mitre_technique}>
                  <td>
                    <a href={p.mitre_url} target="_blank" rel="noreferrer">
                      <code>{p.mitre_technique}</code>
                    </a>
                  </td>
                  <td>
                    <Link to={`/tactic/${p.mitre_tactic}`}>{tacticLabel(p.mitre_tactic)}</Link>
                  </td>
                  <td>{p.title}</td>
                  <td>
                    <span
                      className="badge"
                      style={{
                        background: "transparent",
                        border: `1px solid ${EFFORT_COLORS[p.effort]}`,
                        color: EFFORT_COLORS[p.effort],
                      }}
                    >
                      {p.effort}
                    </span>
                  </td>
                  <td className="muted-cell">{p.rationale}</td>
                  <td className="muted-cell roadmap-table__sketch">{p.detection_sketch}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {partial.length > 0 && (
        <section className="section-block">
          <div className="section-block__title">
            <h3>Partial coverage ({partial.length})</h3>
            <span className="muted">tactics with shipped cases AND queued plans</span>
          </div>
          <ul className="muted" style={{ paddingLeft: 22 }}>
            {partial.map((t) => (
              <li key={t.slug}>
                <Link to={`/tactic/${t.slug}`}>{t.name}</Link> — {t.shipped_count} shipped, {t.planned_count} planned. {t.scope_note}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="section-block">
        <div className="section-block__title">
          <h3>Out of scope ({outOfScope.length})</h3>
          <span className="muted">honest scoping · not gaps to fill</span>
        </div>
        <p className="muted" style={{ fontSize: 13 }}>
          detlab's charter is <em>network detection</em> on Zeek and Suricata. The
          tactics below need different telemetry — process events, AD logs,
          file-system audit, OSINT — and pretending otherwise would produce noisy
          rules that trip on benign traffic. Each cell explains the boundary.
        </p>
        <div className="gaps">
          {outOfScope.map((t) => (
            <div key={t.slug} className="gaps__item">
              <h4>{t.name}</h4>
              <p>
                <em>{t.description}</em>
              </p>
              <p style={{ marginTop: 8 }}>{t.scope_note}</p>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
