/* Data-source coverage chart.
 *
 * Detection content is the visible artifact, but the *telemetry plan*
 * underneath is what makes it possible. This page shows which Zeek and
 * Suricata logs each detection consumes — the visitor can see at a glance
 * that the lab is anchored on Zeek conn/dns/http with Suricata for IDS
 * signal, and how heavily each source pulls weight.
 */

import { useMemo } from "react";
import { Link } from "react-router-dom";

import { CaseSummary, dataset, tacticLabel } from "../lib/cases";

interface SourceRow {
  id: string;
  label: string;
  category: string;
  description: string;
  cases: CaseSummary[];
}

const CATEGORY_ORDER = ["DNS", "Flow", "Application", "IDS", "Enrichment"];

export default function DataSources() {
  const rows = useMemo<SourceRow[]>(() => {
    return (dataset.data_sources ?? []).map((ds) => ({
      ...ds,
      cases: dataset.cases
        .filter((c) => c.data_sources.includes(ds.id))
        .sort((a, b) => b.risk_score - a.risk_score),
    }));
  }, []);

  const totalCases = dataset.cases.length;
  const maxCount = useMemo(() => Math.max(1, ...rows.map((r) => r.cases.length)), [rows]);

  const byCategory = useMemo(() => {
    const out: Record<string, SourceRow[]> = {};
    for (const r of rows) {
      out[r.category] = (out[r.category] ?? []).concat(r);
    }
    return out;
  }, [rows]);

  return (
    <article>
      <div className="page-header">
        <h1>Data sources & telemetry coverage</h1>
        <p className="muted" style={{ maxWidth: 760 }}>
          Every detection rests on a telemetry choice. Zeek's conn / dns / http
          logs are the workhorses; Suricata adds signature-based IDS coverage;
          a small set of enrichment lookups (RMM domains, Tor relays, NRD feed,
          cloud-storage IPs) sharpen the picture without adding sensor cost.
          The chart below shows how many shipped detections each source feeds.
        </p>
      </div>

      <section className="kpi-strip" style={{ marginTop: 12 }}>
        <div className="kpi">
          <div className="kpi__value">{rows.length}</div>
          <div className="kpi__label">Distinct sources</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{totalCases}</div>
          <div className="kpi__label">Detections fed</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{rows.find((r) => r.id === "zeek_conn")?.cases.length ?? 0}</div>
          <div className="kpi__label">Detections on conn.log</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{rows.find((r) => r.id === "zeek_dns")?.cases.length ?? 0}</div>
          <div className="kpi__label">Detections on dns.log</div>
        </div>
      </section>

      <div className="section-title" style={{ marginTop: 24 }}>
        <h2>Coverage by source</h2>
        <span className="muted">bars sized by number of detections fed</span>
      </div>

      <div className="datasource-bars">
        {rows
          .slice()
          .sort((a, b) => b.cases.length - a.cases.length)
          .map((row) => {
            const pct = (row.cases.length / maxCount) * 100;
            return (
              <div key={row.id} className="datasource-row">
                <div className="datasource-row__label">
                  <code className="datasource-row__id">{row.id}</code>
                  <span>{row.label}</span>
                  <span className="muted">{row.category}</span>
                </div>
                <div className="datasource-row__bar">
                  <div
                    className="datasource-row__fill"
                    style={{ width: `${pct}%` }}
                  />
                  <span className="datasource-row__count">{row.cases.length}</span>
                </div>
              </div>
            );
          })}
      </div>

      <div className="section-title" style={{ marginTop: 28 }}>
        <h2>By category</h2>
      </div>
      {CATEGORY_ORDER.filter((c) => byCategory[c]).map((cat) => (
        <section key={cat} className="datasource-category">
          <h3>{cat}</h3>
          <div className="datasource-category__cards">
            {byCategory[cat].map((row) => (
              <div key={row.id} className="datasource-card">
                <div className="datasource-card__head">
                  <code>{row.id}</code>
                  <span>{row.cases.length} detection{row.cases.length === 1 ? "" : "s"}</span>
                </div>
                <p>{row.description}</p>
                <div className="datasource-card__cases">
                  {row.cases.map((c) => (
                    <Link key={c.id} to={`/case/${c.id}`} className="datasource-case-chip" title={c.title}>
                      <code>{c.mitre_technique}</code>
                      <span>{tacticLabel(c.mitre_tactic)}</span>
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      ))}
    </article>
  );
}
