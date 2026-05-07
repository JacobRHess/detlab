/* Threat-group attribution page.
 *
 * Aggregates the per-case `threat_groups` arrays into a global view: which
 * adversary groups does the lab cover, and which detlab cases catch them?
 * The CTI-shaped story:
 *   1. lab catalogues real adversary groups
 *   2. each group is associated with techniques it's observed using
 *   3. each of those techniques maps to a shipped detlab detection
 *
 * The hand-curated profile registry lives in lib/threatGroups.ts so this
 * file stays focused on rendering.
 */

import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { CaseSummary, dataset, tacticLabel } from "../lib/cases";
import { GROUP_PROFILES, OriginBadge, originBadge } from "../lib/threatGroups";

interface GroupRow {
  name: string;
  cases: CaseSummary[];
  tactics: Set<string>;
  totalRisk: number;
  badge: OriginBadge;
}

type FilterValue = "all" | "apt" | "ecrime";

const FILTER_LABELS: Record<FilterValue, string> = {
  all: "All",
  apt: "State / APT",
  ecrime: "eCrime",
};

function buildRows(): GroupRow[] {
  const map = new Map<string, GroupRow>();
  for (const c of dataset.cases) {
    for (const name of c.threat_groups) {
      let row = map.get(name);
      if (!row) {
        row = {
          name,
          cases: [],
          tactics: new Set<string>(),
          totalRisk: 0,
          badge: originBadge(name),
        };
        map.set(name, row);
      }
      row.cases.push(c);
      row.tactics.add(c.mitre_tactic);
      row.totalRisk += c.risk_score;
    }
  }
  return Array.from(map.values()).sort((a, b) => b.cases.length - a.cases.length);
}

function useAnchorScroll() {
  useEffect(() => {
    if (!window.location.hash) return;
    const id = decodeURIComponent(window.location.hash.slice(1));
    const el = document.getElementById(`group-${id}`);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);
}

function ThreatCard({ row }: { row: GroupRow }) {
  const profile = GROUP_PROFILES[row.name];
  return (
    <div id={`group-${row.name}`} className={`threat-card threat-card--${row.badge}`}>
      <div className="threat-card__head">
        <h3>{row.name}</h3>
        <span className={`threat-card__badge threat-card__badge--${row.badge}`}>
          {row.badge.toUpperCase()}
        </span>
      </div>
      {profile && (
        <div className="threat-card__profile">
          <div>
            <span className="threat-card__label">aliases</span>
            <span>{profile.aliases || "—"}</span>
          </div>
          <div>
            <span className="threat-card__label">origin</span>
            <span>{profile.origin}</span>
          </div>
          <div>
            <span className="threat-card__label">motivation</span>
            <span>{profile.motivation}</span>
          </div>
        </div>
      )}
      <div className="threat-card__stats">
        <span>
          <strong>{row.cases.length}</strong> detection
          {row.cases.length === 1 ? "" : "s"}
        </span>
        <span>
          <strong>{row.tactics.size}</strong> tactic
          {row.tactics.size === 1 ? "" : "s"}
        </span>
        <span>
          <strong>{row.totalRisk}</strong> aggregate risk
        </span>
      </div>
      <div className="threat-card__cases">
        {row.cases.map((c) => (
          <Link key={c.id} to={`/case/${c.id}`} className="threat-case-chip" title={c.title}>
            <code>{c.mitre_technique}</code>
            <span>{tacticLabel(c.mitre_tactic)}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}

export default function ThreatGroups() {
  const rows = useMemo(buildRows, []);
  useAnchorScroll();

  const [filter, setFilter] = useState<FilterValue>("all");
  const filtered = useMemo(
    () => (filter === "all" ? rows : rows.filter((r) => r.badge === filter)),
    [filter, rows],
  );

  const aptCount = useMemo(() => rows.filter((r) => r.badge === "apt").length, [rows]);
  const ecrimeCount = useMemo(() => rows.filter((r) => r.badge === "ecrime").length, [rows]);

  return (
    <article>
      <div className="page-header">
        <h1>Threat-group coverage</h1>
        <p className="muted" style={{ maxWidth: 760 }}>
          Detection content is only as useful as the adversaries it catches. Each
          shipped detlab case lists the groups known to use that technique in the
          wild — sourced from MITRE ATT&amp;CK group pages, DFIR Report intrusion
          writeups, and vendor reporting (Mandiant, CrowdStrike, Microsoft). This
          page rolls those associations up so you can ask "would the detlab
          catalogue catch <em>group X</em>?"
        </p>
      </div>

      <section className="kpi-strip" style={{ marginTop: 12 }}>
        <div className="kpi">
          <div className="kpi__value" style={{ color: "var(--shipped)" }}>{rows.length}</div>
          <div className="kpi__label">Adversary groups covered</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{aptCount}</div>
          <div className="kpi__label">State / APT</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{ecrimeCount}</div>
          <div className="kpi__label">eCrime / RaaS</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{dataset.cases.length}</div>
          <div className="kpi__label">Detections cross-referenced</div>
        </div>
      </section>

      <div className="threat-filter">
        <span className="muted" style={{ fontSize: 12 }}>filter</span>
        {(Object.keys(FILTER_LABELS) as FilterValue[]).map((f) => (
          <button
            key={f}
            type="button"
            className={`btn ${filter === f ? "btn--primary" : ""}`}
            onClick={() => setFilter(f)}
          >
            {FILTER_LABELS[f]}
          </button>
        ))}
      </div>

      <div className="threat-grid">
        {filtered.map((row) => (
          <ThreatCard key={row.name} row={row} />
        ))}
      </div>
    </article>
  );
}
