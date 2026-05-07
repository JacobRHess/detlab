/* CIM Compliance dashboard.
 *
 * Splunk Enterprise Security accelerates content via CIM data models —
 * Network_Traffic, Network_Resolution, Web, Authentication,
 * Intrusion_Detection. A detection that aliases its fields onto a CIM
 * model "rides" the data model accelerations the customer already
 * paid for; one that doesn't has to do its own search-time work.
 *
 * This page surfaces the lab's CIM alignment up front:
 *   - Coverage % per data model (which models the catalogue feeds).
 *   - Coverage matrix — every case × every model, with a checkmark for
 *     where a case participates.
 *   - Field reference for each model — what CIM expects.
 *
 * The CIM aliases live in shared/macros.conf (`detlab_cim_zeek_conn`,
 * `detlab_cim_zeek_dns`); each per-case detection composes them via
 * pipeline so the events downstream are already CIM-shaped.
 */

import { useMemo } from "react";
import { Link } from "react-router-dom";

import { CaseSummary, dataset, tacticLabel } from "../lib/cases";

interface ModelStat {
  id: string;
  label: string;
  description: string;
  color: string;
  required_fields: string[];
  cases: CaseSummary[];
}

export default function CIM() {
  const models = useMemo<ModelStat[]>(() => {
    return (dataset.cim_data_models ?? []).map((m) => ({
      ...m,
      cases: dataset.cases.filter((c) => c.cim_data_models.includes(m.id)),
    }));
  }, []);

  const totalCases = dataset.cases.length;
  const cimAligned = dataset.cases.filter((c) => c.cim_data_models.length > 0).length;
  const multiModel = dataset.cases.filter((c) => c.cim_data_models.length > 1).length;

  const sortedCases = useMemo(
    () => [...dataset.cases].sort((a, b) => a.mitre_tactic.localeCompare(b.mitre_tactic)),
    [],
  );

  return (
    <article>
      <div className="page-header">
        <h1>CIM compliance</h1>
        <p className="muted" style={{ maxWidth: 760 }}>
          Splunk ES accelerates content via the Common Information Model —
          standard field names + data models that data-model acceleration
          ("DMA") indexes ahead of time. Detections that align to CIM ride
          those accelerations for free; detections that don't pay full
          search-time cost on every fire. The detlab catalogue ships
          CIM-aligning macros in <code>shared/macros.conf</code>; this page
          shows the coverage.
        </p>
      </div>

      <section className="kpi-strip" style={{ marginTop: 12 }}>
        <div className="kpi">
          <div className="kpi__value" style={{ color: "var(--shipped)" }}>
            {Math.round((cimAligned / totalCases) * 100)}
            <span style={{ fontSize: 18 }}>%</span>
          </div>
          <div className="kpi__label">Detections CIM-aligned</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{models.length}</div>
          <div className="kpi__label">CIM data models touched</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{multiModel}</div>
          <div className="kpi__label">Multi-model detections</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{cimAligned}</div>
          <div className="kpi__label">/ {totalCases} cases mapped</div>
        </div>
      </section>

      <div className="section-title" style={{ marginTop: 24 }}>
        <h2>Coverage by data model</h2>
        <span className="muted">how many shipped detections feed each CIM model</span>
      </div>
      <div className="cim-models">
        {models.map((m) => {
          const pct = (m.cases.length / Math.max(1, totalCases)) * 100;
          return (
            <div key={m.id} className="cim-model" style={{ borderLeftColor: m.color }}>
              <div className="cim-model__head">
                <h3>{m.label}</h3>
                <span className="cim-model__count">
                  {m.cases.length} of {totalCases}
                </span>
              </div>
              <p className="cim-model__desc">{m.description}</p>
              <div className="cim-model__bar">
                <div
                  className="cim-model__fill"
                  style={{ width: `${pct}%`, background: m.color }}
                />
              </div>
              <div className="cim-model__fields">
                <span className="muted" style={{ fontSize: 11, letterSpacing: 1 }}>
                  REQUIRED FIELDS
                </span>
                <div className="cim-model__field-list">
                  {m.required_fields.map((f) => (
                    <code key={f}>{f}</code>
                  ))}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="section-title" style={{ marginTop: 28 }}>
        <h2>Coverage matrix</h2>
        <span className="muted">every case × every CIM model</span>
      </div>
      <div className="cim-matrix">
        <div className="cim-matrix__head" style={{ gridTemplateColumns: gridCols(models.length) }}>
          <span>case</span>
          {models.map((m) => (
            <span key={m.id} title={m.label} className="cim-matrix__col-label">
              {shortLabel(m.label)}
            </span>
          ))}
        </div>
        {sortedCases.map((c) => (
          <Link
            key={c.id}
            to={`/case/${c.id}`}
            className="cim-matrix__row"
            style={{ gridTemplateColumns: gridCols(models.length) }}
          >
            <div>
              <div className="cim-matrix__title">{c.title}</div>
              <span className="cim-matrix__meta">
                <code>{c.mitre_technique}</code> · {tacticLabel(c.mitre_tactic)}
              </span>
            </div>
            {models.map((m) => {
              const aligned = c.cim_data_models.includes(m.id);
              return (
                <span
                  key={m.id}
                  className={`cim-cell ${aligned ? "cim-cell--on" : "cim-cell--off"}`}
                  style={aligned ? { color: m.color, borderColor: m.color } : undefined}
                  title={aligned ? `aligned to ${m.label}` : `not aligned to ${m.label}`}
                >
                  {aligned ? "✓" : "·"}
                </span>
              );
            })}
          </Link>
        ))}
      </div>

      <h3 style={{ marginTop: 28 }}>How alignment works in Splunk</h3>
      <p className="muted" style={{ fontSize: 13, maxWidth: 760 }}>
        The shared CIM aliasing macros (<code>detlab_cim_zeek_conn</code>,{" "}
        <code>detlab_cim_zeek_dns</code>) rename Zeek field names to CIM-standard
        ones (<code>id.orig_h</code> → <code>src</code>,{" "}
        <code>orig_bytes</code> → <code>bytes_out</code>) and derive
        compliance fields like <code>action</code>. Per-case macros append
        these aliases via pipeline so all downstream events are CIM-shaped
        and qualify for data-model acceleration. The{" "}
        <Link to="/macros">/macros</Link> page has the SPL.
      </p>
    </article>
  );
}

function shortLabel(label: string): string {
  // Network_Resolution -> Net.Resolution; Intrusion_Detection -> Intrusion
  return label
    .replace(/^Network /, "Net.")
    .replace(/Intrusion Detection/, "IDS")
    .replace(/Authentication/, "Auth.");
}

function gridCols(n: number): string {
  return `2.5fr ${"0.7fr ".repeat(n).trim()}`;
}
