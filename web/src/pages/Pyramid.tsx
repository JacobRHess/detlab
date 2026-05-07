/* Pyramid of Pain — David Bianco's classic detection-engineering model.
 *
 * Indicators sit at six tiers. The higher the tier, the more pain it
 * inflicts on the adversary to evade. A portfolio that catches mostly
 * tier-1 (hashes) is fragile; one anchored at tier-5 (tools) and tier-6
 * (TTPs) is durable.
 *
 * Layout:
 *   - Wide SVG pyramid on the left, each band labeled with the
 *     short tier name + a count badge. Long full-name labels and
 *     descriptions live in the side rail / detail list to keep the
 *     pyramid clean.
 *   - Side rail aligned to the SVG bands shows count + label + tier
 *     number, connected to its band by a leader line.
 *   - Below the pyramid: per-tier expandable rows with the actual
 *     detections at that tier.
 */

import { useMemo } from "react";
import { Link } from "react-router-dom";

import { CaseSummary, dataset, tacticLabel } from "../lib/cases";

interface TieredCases {
  tier: number;
  label: string;
  shortLabel: string;
  color: string;
  description: string;
  cases: CaseSummary[];
}

// Short labels used inside the pyramid bands (long ones overflow).
const SHORT_LABELS: Record<number, string> = {
  1: "Hashes",
  2: "IPs",
  3: "Domains",
  4: "Artifacts",
  5: "Tools",
  6: "TTPs",
};

const PYRAMID_WIDTH = 520;
const PYRAMID_HEIGHT = 440;
const PYRAMID_TOP_W = 120;
const PYRAMID_PAD = 30;

/** Geometry helper: width of the pyramid at vertical offset y (0 at apex). */
function widthAt(y: number): number {
  const t = y / PYRAMID_HEIGHT;
  return PYRAMID_TOP_W + t * (PYRAMID_WIDTH - PYRAMID_TOP_W);
}

interface BandGeo {
  yTop: number;
  yMid: number;
  yBot: number;
  wTop: number;
  wMid: number;
  wBot: number;
}

function bandGeo(tier: number): BandGeo {
  const segH = PYRAMID_HEIGHT / 6;
  const idxFromTop = 6 - tier;
  const yTop = idxFromTop * segH;
  const yBot = (idxFromTop + 1) * segH;
  const yMid = (yTop + yBot) / 2;
  return {
    yTop,
    yMid,
    yBot,
    wTop: widthAt(yTop),
    wMid: widthAt(yMid),
    wBot: widthAt(yBot),
  };
}

function trapezoidPoints(tier: number): string {
  const g = bandGeo(tier);
  const cx = PYRAMID_WIDTH / 2 + PYRAMID_PAD;
  return [
    `${cx - g.wTop / 2},${g.yTop + PYRAMID_PAD}`,
    `${cx + g.wTop / 2},${g.yTop + PYRAMID_PAD}`,
    `${cx + g.wBot / 2},${g.yBot + PYRAMID_PAD}`,
    `${cx - g.wBot / 2},${g.yBot + PYRAMID_PAD}`,
  ].join(" ");
}

const SVG_W = PYRAMID_WIDTH + 2 * PYRAMID_PAD;
const SVG_H = PYRAMID_HEIGHT + 2 * PYRAMID_PAD;

export default function Pyramid() {
  const tiered = useMemo<TieredCases[]>(() => {
    const tiers = dataset.pyramid_tiers ?? [];
    return tiers
      .map((t) => ({
        tier: t.tier,
        label: t.label,
        shortLabel: SHORT_LABELS[t.tier] ?? t.label,
        color: t.color,
        description: t.description,
        cases: dataset.cases
          .filter((c) => c.pyramid_tier === t.tier)
          .sort((a, b) => b.risk_score - a.risk_score),
      }))
      .reverse(); // tier 6 first
  }, []);

  const totalScored = dataset.cases.filter((c) => c.pyramid_tier > 0).length;
  const tierCounts = useMemo(() => {
    const out: Record<number, number> = {};
    for (const c of dataset.cases) {
      if (c.pyramid_tier > 0) out[c.pyramid_tier] = (out[c.pyramid_tier] ?? 0) + 1;
    }
    return out;
  }, []);

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
          <div className="kpi__value" style={{ color: "var(--shipped)" }}>
            {resilience}
            <span style={{ fontSize: 18 }}>%</span>
          </div>
          <div className="kpi__label">
            Resilience score <span className="muted">(tier-weighted)</span>
          </div>
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

      <div className="pyramid-board">
        <PyramidSVG tiered={tiered} />
        <div className="pyramid-rail" aria-hidden="true">
          {tiered.map((t) => (
            <div key={t.tier} className="pyramid-rail__band" style={{ borderLeftColor: t.color }}>
              <div className="pyramid-rail__head">
                <span className="pyramid-rail__count">{t.cases.length}</span>
                <div>
                  <div className="pyramid-rail__label">{t.label}</div>
                  <div className="pyramid-rail__desc">{t.description}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="section-title" style={{ marginTop: 28 }}>
        <h2>Detections by tier</h2>
        <span className="muted">click a chip to open the case</span>
      </div>
      <ol className="pyramid-tier-list">
        {tiered.map((t) => (
          <li key={t.tier} className="pyramid-tier-row" style={{ borderLeftColor: t.color }}>
            <div className="pyramid-tier-row__head">
              <span className="pyramid-tier-row__num" style={{ background: t.color }}>
                {t.tier}
              </span>
              <h3>{t.label}</h3>
              <span className="muted" style={{ fontSize: 12 }}>
                {t.description}
              </span>
              <span className="pyramid-tier-row__count">
                {t.cases.length} detection{t.cases.length === 1 ? "" : "s"}
              </span>
            </div>
            {t.cases.length === 0 ? (
              <p className="muted" style={{ fontSize: 13 }}>
                No detections at this tier.
              </p>
            ) : (
              <div className="pyramid-tier-row__cases">
                {t.cases.map((c) => (
                  <Link
                    key={c.id}
                    to={`/case/${c.id}`}
                    className="pyramid-case-chip"
                    title={c.title}
                  >
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
    </article>
  );
}

function PyramidSVG({ tiered }: { tiered: TieredCases[] }) {
  const cx = PYRAMID_WIDTH / 2 + PYRAMID_PAD;
  return (
    <svg
      className="pyramid-svg"
      viewBox={`0 0 ${SVG_W} ${SVG_H}`}
      role="img"
      aria-label="Pyramid of Pain — detection portfolio breakdown"
    >
      {tiered.map((t) => {
        const g = bandGeo(t.tier);
        const yMidAbs = g.yMid + PYRAMID_PAD;
        const labelFontSize = t.tier >= 5 ? 12 : 13;
        return (
          <g key={t.tier}>
            <polygon
              points={trapezoidPoints(t.tier)}
              fill={t.color}
              fillOpacity={0.22}
              stroke={t.color}
              strokeWidth={1.5}
            />
            <text
              x={cx}
              y={yMidAbs - 2}
              textAnchor="middle"
              fontFamily="var(--font-sans)"
              fontWeight={600}
              fontSize={labelFontSize}
              fill="var(--text)"
            >
              {t.shortLabel}
            </text>
            <text
              x={cx}
              y={yMidAbs + labelFontSize + 1}
              textAnchor="middle"
              fontFamily="var(--font-mono)"
              fontSize={11}
              fill="var(--text-muted)"
            >
              {t.cases.length} detection{t.cases.length === 1 ? "" : "s"}
            </text>
          </g>
        );
      })}
      <text
        x={cx}
        y={SVG_H - 8}
        textAnchor="middle"
        fontFamily="var(--font-sans)"
        fontSize={11}
        fill="var(--text-dim)"
        letterSpacing={1.2}
      >
        ← MORE PAIN TO ADVERSARY    LESS PAIN →
      </text>
    </svg>
  );
}
