import { Link } from "react-router-dom";

import { dataset } from "../lib/cases";

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

  const covered = dataset.tactics.filter((t) => t.status === "covered");
  const partial = dataset.tactics.filter((t) => t.status === "partial");
  const outOfScope = dataset.tactics.filter((t) => t.status === "out_of_scope");
  const stillPlanned = dataset.tactics.filter((t) => t.status === "planned");

  const totalShipped = dataset.cases.length;
  const totalCovered = covered.length + partial.length;

  return (
    <>
      <section className="hero">
        <span className="hero__eyebrow">coverage map · across the matrix</span>
        <h1>Coverage at a glance</h1>
        <p>
          detlab's charter is <em>network-visible</em> detections on Zeek and Suricata. The
          tour below walks every Enterprise ATT&amp;CK tactic, the cases that ship today,
          and — where applicable — an honest scoping note for tactics where network
          telemetry isn't the right place to catch the activity.
        </p>
        <div className="coverage-headline">
          <div className="coverage-headline__stat">
            <div className="coverage-headline__big">{totalShipped}</div>
            <div className="coverage-headline__label">detections shipped</div>
          </div>
          <div className="coverage-headline__stat">
            <div className="coverage-headline__big">{totalCovered}</div>
            <div className="coverage-headline__label">tactics with shipped cases</div>
          </div>
          <div className="coverage-headline__stat">
            <div className="coverage-headline__big">{outOfScope.length}</div>
            <div className="coverage-headline__label">tactics out-of-scope (rationale below)</div>
          </div>
        </div>
      </section>

      <section className="section-block">
        <div className="section-block__title">
          <h3>All 14 Enterprise tactics</h3>
          <span className="muted">click any for the per-tactic detail page</span>
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

      {(planned.length > 0 || stillPlanned.length > 0) && (
        <section className="section-block">
          <div className="section-block__title">
            <h3>Planned cases ({planned.length})</h3>
            <span className="muted">queued for upcoming releases</span>
          </div>
          <p className="muted" style={{ marginTop: 0 }}>
            See <Link to="/tactic/lateral-movement">individual tactic pages</Link> for per-case rationale and detection sketches.
          </p>
        </section>
      )}

      <section className="section-block">
        <div className="section-block__title">
          <h3>Out-of-scope tactics ({outOfScope.length})</h3>
          <span className="muted">honest boundary, not a gap to fill</span>
        </div>
        <p style={{ marginTop: 0 }}>
          The tactics below need different telemetry — process events, AD logs,
          file-system audit, OSINT — and chasing them with network rules would
          produce noisy detections that trip on benign traffic. Each card explains
          the boundary.
        </p>
        {outOfScope.length === 0 ? (
          <p className="muted">
            None — every Enterprise tactic has at least one shipped case in this lab.
          </p>
        ) : (
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
        )}
      </section>
    </>
  );
}
