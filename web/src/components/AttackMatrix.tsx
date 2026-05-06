import { Link } from "react-router-dom";

import { dataset, tacticLabel } from "../lib/cases";

interface MatrixCell {
  status: "shipped" | "planned";
  tactic: string;
  title: string;
  technique: string;
  caseId?: string;
  severity?: string;
  url: string;
}

function bucketByTactic(): Record<string, MatrixCell[]> {
  const buckets: Record<string, MatrixCell[]> = {};
  const push = (tactic: string, cell: MatrixCell) => {
    buckets[tactic] ||= [];
    buckets[tactic].push(cell);
  };
  for (const c of dataset.cases) {
    push(c.mitre_tactic, {
      status: "shipped",
      tactic: c.mitre_tactic,
      title: c.title,
      technique: c.mitre_technique,
      caseId: c.id,
      severity: c.severity,
      url: c.mitre_url,
    });
  }
  for (const p of dataset.planned) {
    push(p.mitre_tactic, {
      status: "planned",
      tactic: p.mitre_tactic,
      title: p.title,
      technique: p.mitre_technique,
      url: p.mitre_url,
    });
  }
  return buckets;
}

function CellLink({ cell }: { cell: MatrixCell }) {
  const className = `tcell tcell--${cell.status}`;
  const meta = (
    <div className="tcell__meta">
      <span className={`badge badge--${cell.status}`}>{cell.status}</span>
      {cell.severity && <span className={`badge badge--${cell.severity}`}>{cell.severity}</span>}
    </div>
  );
  const body = (
    <>
      <div className="tcell__id">{cell.technique}</div>
      <div className="tcell__title">{cell.title}</div>
      {meta}
    </>
  );

  if (cell.status === "shipped" && cell.caseId) {
    return (
      <Link to={`/case/${cell.caseId}`} className={className}>
        {body}
      </Link>
    );
  }
  // Planned cells drill into the tactic page (rationale + sketch + sibling
  // planned items) rather than directly to attack.mitre.org — the lab
  // context is more useful than the raw technique page.
  return (
    <Link to={`/tactic/${cell.tactic}`} className={className} title="See planning rationale">
      {body}
    </Link>
  );
}

export default function AttackMatrix() {
  const buckets = bucketByTactic();
  const tactics = Object.keys(buckets).sort();

  return (
    <div className="matrix" role="list" aria-label="ATT&CK technique matrix">
      {tactics.map((tactic) => (
        <div key={tactic} className="tactic-col" role="listitem">
          <div className="tactic-col__head">{tacticLabel(tactic)}</div>
          <div className="tactic-col__cells">
            {buckets[tactic].map((cell) => (
              <CellLink key={`${cell.technique}-${cell.title}`} cell={cell} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
