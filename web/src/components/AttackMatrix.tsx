import { Link } from "react-router-dom";

import { dataset, tacticLabel } from "../lib/cases";

interface MatrixCell {
  status: "shipped" | "planned";
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
  return (
    <a href={cell.url} target="_blank" rel="noreferrer" className={className} title="View technique on attack.mitre.org">
      {body}
    </a>
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
