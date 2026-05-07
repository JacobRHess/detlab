/* Per-case "Analyst Triage" tab.
 *
 * SOC analysts working a real alert want three things up front:
 *   1. What do I do first? (triage steps)
 *   2. Could this be benign? (false positives)
 *   3. If it's bad, how do I stop it? (containment actions)
 *
 * This tab makes those three explicit instead of burying them in the
 * README, which is what most detection-content repos do. */

import { CaseFull } from "../lib/cases";

interface SectionProps {
  title: string;
  items: string[];
  emptyHint: string;
  accent: string;
  icon: string;
}

function Section({ title, items, emptyHint, accent, icon }: SectionProps) {
  return (
    <div className="triage-section" style={{ borderLeftColor: accent }}>
      <div className="triage-section__head">
        <span className="triage-section__icon" aria-hidden="true">{icon}</span>
        <h3>{title}</h3>
        <span className="muted" style={{ fontSize: 12 }}>
          {items.length} {items.length === 1 ? "item" : "items"}
        </span>
      </div>
      {items.length === 0 ? (
        <p className="muted" style={{ fontSize: 13 }}>{emptyHint}</p>
      ) : (
        <ol className="triage-list">
          {items.map((item, i) => (
            <li key={i} className="triage-item">
              <span className="triage-item__num">{i + 1}</span>
              <span className="triage-item__body">{item}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

export default function AnalystTriage({ c }: { c: CaseFull }) {
  const t = c.triage ?? { steps: [], false_positives: [], containment: [] };
  const stepCount = t.steps.length;

  return (
    <div className="triage">
      <div className="triage__intro">
        <p>
          Imagine this rule just fired in your SIEM. The SOC analyst on shift
          opens the alert. These are the actions, common false positives, and
          containment steps for that workflow — the same content lives in{" "}
          <code>known_false_positives</code> on the ES correlation search and
          in the per-case workflow_actions.
        </p>
      </div>

      <div className="triage__grid">
        <Section
          title="Triage steps"
          items={t.steps}
          emptyHint="Triage steps haven't been authored for this case yet."
          accent="var(--accent)"
          icon="①"
        />
        <Section
          title="Common false positives"
          items={t.false_positives}
          emptyHint="No documented false-positive patterns yet — this rule is high-confidence."
          accent="var(--warn)"
          icon="⚠"
        />
        <Section
          title="Containment actions"
          items={t.containment}
          emptyHint="Containment actions haven't been authored for this case yet."
          accent="var(--danger)"
          icon="◉"
        />
      </div>

      <div className="triage__footer">
        <div className="triage-stat">
          <div className="triage-stat__value">{stepCount}</div>
          <div className="triage-stat__label">Triage steps</div>
        </div>
        <div className="triage-stat">
          <div className="triage-stat__value">{t.false_positives.length}</div>
          <div className="triage-stat__label">FP scenarios</div>
        </div>
        <div className="triage-stat">
          <div className="triage-stat__value">{t.containment.length}</div>
          <div className="triage-stat__label">Containment plays</div>
        </div>
        <div className="triage-stat">
          <div className="triage-stat__value">{c.risk?.score ?? 0}</div>
          <div className="triage-stat__label">Risk score</div>
        </div>
      </div>
    </div>
  );
}
