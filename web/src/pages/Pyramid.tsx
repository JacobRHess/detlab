/* Pyramid of Pain — David Bianco's classic detection-engineering model.
 *
 * Indicators sit at six tiers. The higher the tier, the more pain it
 * inflicts on the adversary to evade. A portfolio that catches mostly
 * tier-1 (hashes) is fragile; one anchored at tier-5 (tools) and tier-6
 * (TTPs) is durable.
 *
 * This page tiers every shipped detection and renders the classic
 * pyramid SVG with the case counts at each level — so the visitor sees
 * at a glance where the lab's resilience lives.
 */

import { useMemo } from "react";
import { Link } from "react-router-dom";

import { CaseSummary, dataset, tacticLabel } from "../lib/cases";

interface TieredCases {
  tier: number;
  label: string;
  color: string;
  description: string;
  cases: CaseSummary[];
}

const PYRAMID_HEIGHT = 360;
const PYRAMID_WIDTH = 720;
const PYRAMID_TOP_W = 200;

/** Compute the trapezoid points for tier `tier` (1=base, 6=apex). */
function trapezoidPoints(tier: number): string {
  const tiers = 6;
  const segH = PYRAMID_HEIGHT / tiers;
  const idxFromTop = tiers - tier; // tier 6 = top => idx 0; tier 1 = bottom => idx 5
  const yTop = idxFromTop * segH;
  const yBot = (idxFromTop + 1) * segH;
  // Linear interpolation: top width 200 at apex, full width at base.
  const widthAt = (y: number) => {
    const t = y / PYRAMID_HEIGHT; // 0 at top, 1 at base
    return PYRAMID_TOP_W + t * (PYRAMID_WIDTH - PYRAMID_TOP_W);
  };
  const w1 = widthAt(yTop);
  const w2 = widthAt(yBot);
  const cx = PYRAMID_WIDTH / 2;
  return [
    `${cx - w1 / 2},${yTop}`,
    `${cx + w1 / 2},${yTop}`,
    `${cx + w2 / 2},${yBot}`,
    `${cx - w2 / 2},${yBot}`,
  ].join(" ");
}

function tierLabelY(tier: number): number {
  const segH = PYRAMID_HEIGHT / 6;
  const idxFromTop = 6 - tier;
  return idxFromTop * segH + segH / 2 + 5;
}

export default function Pyramid() {
  const tiered = useMemo<TieredCases[]>(() => {
    const tiers = dataset.pyramid_tiers ?? [];
    return tiers
      .map((t) => ({
        tier: t.tier,
        label: t.label,
        color: t.color,
        description: t.description,
        cases: dataset.cases
          .filter((c) => c.pyramid_tier === t.tier)
          .sort((a, b) => b.risk_score - a.risk_score),
      }))
      .reverse(); // tier 6 first in vertical reading order
  }, []);

  const totalScored = dataset.cases.filter((c) => c.pyramid_tier > 0).length;
  const tierCounts = useMemo(() => {
    const out: Record<number, number> = {};
    for (const c of dataset.cases) {
      if (c.pyramid_tier > 0) out[c.pyramid_tier] = (out[c.pyramid_tier] ?? 0) + 1;
    }
    return out;
  }, []);

  // Resilience score: weighted sum (tier × count) / (max tier × total).
  // Higher = more detections at painful tiers.
  const resilience = useMemo(() => {
    const sum = Object.entries(tierCounts).reduce(
      (s, [tier, n]) => s + Number(tier) * n,
      0,
    );
    return totalScored === 0 ? 0 : Math.round((sum / (6 * totalScored)) * 100);
  }, [tierCounts, totalScored]);

  return (
    <article>
      <div className="page-header">
        <h1>Pyramid of Pain</h1>
        <p className="muted" style={{ maxWidth: 760 }}>
          David Bianco's model: indicators sit at six tiers, and the higher
          the tier the more <em>pain</em> a detection inflicts on the adversary
          when they try to evade it. Hashes flip in seconds; TTPs require
          rewriting how the operator works. A durable detection portfolio is
          weighted toward the apex.
        </p>
      </div>

      <section className="kpi-strip" style={{ marginTop: 12 }}>
        <div className="kpi">
          <div className="kpi__value" style={{ color: "var(--shipped)" }}>{resilience}<span style={{ fontSize: 18 }}>%</span></div>
          <div className="kpi__label">Resilience score <span className="muted">(tier-weighted)</span></div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{tierCounts[6] ?? 0}</div>
          <div className="kpi__label">TTP-tier (6) detections</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{tierCounts[5] ?? 0}</div>
          <div className="kpi__label">Tool-tier (5) detections</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{totalScored}</div>
          <div className="kpi__label">Tiered detections</div>
        </div>
      </section>

      <div className="pyramid-layout">
        <svg
          className="pyramid-svg"
          viewBox={`0 0 ${PYRAMID_WIDTH} ${PYRAMID_HEIGHT}`}
          role="img"
          aria-label="Pyramid of Pain — detection portfolio breakdown"
        >
          {tiered.map((t) => (
            <g key={t.tier}>
              <polygon
                points={trapezoidPoints(t.tier)}
                fill={t.color}
                fillOpacity={0.18}
                stroke={t.color}
                strokeWidth={1.5}
              />
              <text
                x={PYRAMID_WIDTH / 2}
                y={tierLabelY(t.tier)}
                textAnchor="middle"
                fontFamily="var(--font-sans)"
                fontWeight={600}
                fontSize={14}
                fill="var(--text)"
              >
                {t.label}
                <tspan fill="var(--text-muted)" fontSize={12} fontWeight={400}>
                  {"  "}· {t.cases.length} detection{t.cases.length === 1 ? "" : "s"}
                </tspan>
              </text>
            </g>
          ))}
        </svg>

        <ol className="pyramid-tier-list">
          {tiered.map((t) => (
            <li key={t.tier} className="pyramid-tier-row" style={{ borderLeftColor: t.color }}>
              <div className="pyramid-tier-row__head">
                <span className="pyramid-tier-row__num" style={{ background: t.color }}>{t.tier}</span>
                <h3>{t.label}</h3>
                <span className="muted" style={{ fontSize: 12 }}>{t.description}</span>
              </div>
              {t.cases.length === 0 ? (
                <p className="muted" style={{ fontSize: 13 }}>No detections at this tier.</p>
              ) : (
                <div className="pyramid-tier-row__cases">
                  {t.cases.map((c) => (
                    <Link key={c.id} to={`/case/${c.id}`} className="pyramid-case-chip" title={c.title}>
                      <code>{c.mitre_technique}</code>
                      <span>{tacticLabel(c.mitre_tactic)}</span>
                      <span className="pyramid-case-chip__risk">risk {c.risk_score}</span>
                    </Link>
                  ))}
                </div>
              )}
            </li>
          ))}
        </ol>
      </div>
    </article>
  );
}
