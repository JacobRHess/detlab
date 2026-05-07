/* Lookup-table library.
 *
 * The detlab Splunk app ships four CSV lookups under app/lookups/. Some
 * are static enrichment data (RMM domains, Tor relay IPs, cloud-storage
 * IP ranges); one is auto-generated content metadata (detlab_cases.csv).
 * Detection content references them via SPL `lookup` calls — without
 * the lookups, several detections degrade or stop firing entirely.
 *
 * This page surfaces:
 *   - filename, label, refresh cadence
 *   - row count and field schema (read at build time)
 *   - sample rows so the visitor sees the shape
 *   - which cases depend on each lookup
 *
 * Real Splunk admins do exactly this kind of audit when bolting an app
 * into their environment.
 */

import { useMemo } from "react";
import { Link } from "react-router-dom";

import { dataset, getCase, LookupEntry } from "../lib/cases";

function LookupCard({ lk }: { lk: LookupEntry }) {
  return (
    <div className="lookup-card">
      <div className="lookup-card__head">
        <div>
          <div className="lookup-card__filename">
            <code>app/lookups/{lk.filename}</code>
            {lk.missing && <span className="lookup-card__missing">missing</span>}
          </div>
          <div className="lookup-card__label">{lk.label}</div>
        </div>
        <div className="lookup-card__counts">
          <div className="lookup-card__count">
            <span className="lookup-card__count-num">{lk.row_count.toLocaleString()}</span>
            <span className="lookup-card__count-label">rows</span>
          </div>
          <div className="lookup-card__count">
            <span className="lookup-card__count-num">{lk.fields.length}</span>
            <span className="lookup-card__count-label">fields</span>
          </div>
        </div>
      </div>

      <p className="lookup-card__desc">{lk.description}</p>

      <div className="lookup-card__refresh">
        <span className="muted" style={{ fontSize: 11, letterSpacing: 1 }}>
          REFRESH
        </span>
        <span>{lk.refresh_cadence}</span>
      </div>

      <div className="lookup-card__used-by">
        <span className="muted" style={{ fontSize: 11, letterSpacing: 1 }}>
          USED BY
        </span>
        <div className="lookup-card__cases">
          {lk.used_by.map((id) => {
            const c = getCase(id);
            if (!c) {
              return (
                <span key={id} className="lookup-card__case-static">
                  {id}
                </span>
              );
            }
            return (
              <Link key={id} to={`/case/${c.id}`} className="lookup-card__case">
                <code>{c.mitre_technique}</code>
                <span>{c.title}</span>
              </Link>
            );
          })}
        </div>
      </div>

      {lk.fields.length > 0 && lk.sample_rows.length > 0 && (
        <div className="lookup-card__sample">
          <span className="muted" style={{ fontSize: 11, letterSpacing: 1 }}>
            SAMPLE
          </span>
          <div style={{ overflowX: "auto" }}>
            <table className="lookup-table">
              <thead>
                <tr>
                  {lk.fields.map((f) => (
                    <th key={f}>{f}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {lk.sample_rows.map((row, i) => (
                  <tr key={i}>
                    {row.map((v, j) => (
                      <td key={j}>{v || "—"}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Lookups() {
  const lookups = dataset.lookups ?? [];
  const totalRows = useMemo(
    () => lookups.reduce((s, lk) => s + lk.row_count, 0),
    [lookups],
  );
  const enrichmentLookups = lookups.filter((lk) => lk.filename !== "detlab_cases.csv");
  const enrichmentRows = enrichmentLookups.reduce((s, lk) => s + lk.row_count, 0);

  return (
    <article>
      <div className="page-header">
        <h1>Lookup library</h1>
        <p className="muted" style={{ maxWidth: 760 }}>
          Splunk lookups are how a detection content pack ships enrichment
          data and stays portable. The detlab app installs four CSVs under{" "}
          <code>app/lookups/</code>: three static enrichment tables (RMM
          domains, Tor relays, cloud-storage IPs) consumed by specific
          detections, plus the auto-generated <code>detlab_cases.csv</code>{" "}
          that powers every dashboard, RBA join, and SOC pivot.
        </p>
      </div>

      <section className="kpi-strip" style={{ marginTop: 12 }}>
        <div className="kpi">
          <div className="kpi__value">{lookups.length}</div>
          <div className="kpi__label">Lookup tables</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{totalRows.toLocaleString()}</div>
          <div className="kpi__label">Total rows</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{enrichmentLookups.length}</div>
          <div className="kpi__label">
            Enrichment <span className="muted">({enrichmentRows} rows)</span>
          </div>
        </div>
        <div className="kpi">
          <div className="kpi__value">1</div>
          <div className="kpi__label">Auto-generated</div>
        </div>
      </section>

      <div className="lookup-grid" style={{ marginTop: 18 }}>
        {lookups.map((lk) => (
          <LookupCard key={lk.filename} lk={lk} />
        ))}
      </div>
    </article>
  );
}
