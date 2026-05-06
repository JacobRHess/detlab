import { Link, useParams } from "react-router-dom";

import { casesForTactic, getTactic, plannedForTactic } from "../lib/cases";

const STATUS_HINT: Record<string, string> = {
  covered: "Cases shipped. No items in the queue right now.",
  partial: "Cases shipped + plans queued. The mix below shows current vs incoming.",
  planned: "Nothing shipped yet. Items below describe how the lab will fill this column.",
  out_of_scope: "Out of scope by design. The note below explains why network telemetry isn't the right place to catch this.",
};

const STATUS_BADGES: Record<string, string> = {
  covered: "badge--shipped",
  partial: "badge--medium",
  planned: "badge--planned",
  out_of_scope: "badge--planned",
};

export default function TacticDetail() {
  const { slug } = useParams();
  const tactic = getTactic(slug);

  if (!tactic) {
    return (
      <div className="empty-state">
        <p>
          Unknown tactic: <code>{slug}</code>.
        </p>
        <p>
          <Link to="/roadmap">← Back to roadmap</Link>
        </p>
      </div>
    );
  }

  const shipped = casesForTactic(tactic.slug);
  const planned = plannedForTactic(tactic.slug);

  return (
    <article>
      <div className="case-header">
        <div className="case-header__crumbs">
          <Link to="/roadmap">Roadmap</Link> &nbsp;/&nbsp; Tactic
        </div>
        <h1>{tactic.name}</h1>
        <p className="muted" style={{ fontSize: 15, maxWidth: 720 }}>
          {tactic.description}
        </p>
        <div className="case-header__meta">
          <span className={`badge ${STATUS_BADGES[tactic.status]}`}>{tactic.status.replace("_", " ")}</span>
          <span className="muted">
            {tactic.shipped_count} shipped · {tactic.planned_count} planned
          </span>
          <a
            href={`https://attack.mitre.org/tactics/${tactic.slug.toUpperCase().replace("-", "_")}/`}
            target="_blank"
            rel="noreferrer"
          >
            attack.mitre.org ↗
          </a>
        </div>
      </div>

      <section className="section-block">
        <div className="section-block__title">
          <h3>Status — {tactic.status.replace("_", " ")}</h3>
        </div>
        <p className="muted" style={{ marginTop: 0 }}>
          {STATUS_HINT[tactic.status]}
        </p>
        <p>{tactic.scope_note}</p>
      </section>

      {shipped.length > 0 && (
        <section className="section-block">
          <div className="section-block__title">
            <h3>Shipped ({shipped.length})</h3>
            <span className="muted">click a case to drill in</span>
          </div>
          <div className="cards">
            {shipped.map((c) => (
              <Link key={c.id} to={`/case/${c.id}`} className="card tactic-case-card">
                <h3>
                  <code>{c.mitre_technique}</code> — {c.title}
                </h3>
                <p>
                  <span className={`badge badge--${c.severity}`}>{c.severity}</span>
                  &nbsp;
                  <span className="muted">
                    {c.fixture_record_counts.positive + c.fixture_record_counts.negative}{" "}
                    fixture records · detector{" "}
                    <code>{c.wiring.detector_function}</code>
                  </span>
                </p>
              </Link>
            ))}
          </div>
        </section>
      )}

      {planned.length > 0 && (
        <section className="section-block">
          <div className="section-block__title">
            <h3>Planned ({planned.length})</h3>
            <span className="muted">queued for upcoming releases</span>
          </div>
          <table className="confusion-table roadmap-table">
            <thead>
              <tr>
                <th>ATT&amp;CK</th>
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
                  <td>{p.title}</td>
                  <td>
                    <span className="badge badge--planned">{p.effort}</span>
                  </td>
                  <td className="muted-cell">{p.rationale}</td>
                  <td className="muted-cell roadmap-table__sketch">{p.detection_sketch}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {tactic.status === "out_of_scope" && (
        <section className="section-block">
          <div className="section-block__title">
            <h3>What you'd pair detlab with</h3>
          </div>
          <p>
            Most out-of-scope tactics are best caught with endpoint or identity
            telemetry rather than network captures. The detection content split
            looks roughly like this:
          </p>
          <ul>
            <li>
              <strong>Process telemetry</strong> (Sysmon, EDR Carbon Black,
              CrowdStrike Falcon, MS Defender) — Execution, Privilege Escalation,
              most Persistence, most Defense Evasion, most Collection.
            </li>
            <li>
              <strong>AD / identity logs</strong> (Active Directory audit,
              Okta / Azure AD, IdP) — most Credential Access, most Persistence
              involving accounts, Lateral Movement when you want kerberoasting
              detection.
            </li>
            <li>
              <strong>OSINT / CTI feeds</strong> — Resource Development entirely.
            </li>
          </ul>
          <p className="muted" style={{ fontSize: 13 }}>
            detlab's charter stays narrow on purpose so the rules that <em>do</em>{" "}
            ship are tight, well-tested, and honest about their false-positive
            profile.
          </p>
        </section>
      )}
    </article>
  );
}
