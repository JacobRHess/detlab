/* Alert timeline sparkline — shown after a successful detector run.
 *
 * Each alert dataclass carries a `window_start` (unix seconds) field;
 * we bin them across 36 buckets and render a horizontal bar chart so
 * the user can see *when* the alerts cluster, not just how many fired.
 *
 * Some alert dataclasses (BeaconAlert, TunnelAlert, C2ExfilAlert,
 * LateralToolTransferAlert) aggregate over the full input and don't
 * carry a per-alert timestamp; those are rendered as a single "no
 * temporal axis" badge so the user knows why the chart is empty
 * instead of seeing a confusing zero-row chart.
 */

import { useMemo } from "react";

interface Props {
  alerts: Record<string, unknown>[];
}

function alertTimestamp(a: Record<string, unknown>): number | null {
  const v = a.window_start;
  if (typeof v === "number" && v > 0) return v;
  return null;
}

function fmtTime(ts: number): string {
  if (ts <= 0) return "—";
  const d = new Date(ts * 1000);
  return `${d.toISOString().slice(11, 19)}`;
}

function fmtDuration(seconds: number): string {
  if (seconds < 1) return "<1s";
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

export default function AlertTimeline({ alerts }: Props) {
  const timestamped = useMemo(
    () => alerts.map(alertTimestamp).filter((t): t is number => t !== null),
    [alerts],
  );

  const stats = useMemo(() => {
    if (timestamped.length === 0) return null;
    const min = Math.min(...timestamped);
    const max = Math.max(...timestamped);
    const span = Math.max(1, max - min);
    const buckets = 36;
    const counts = new Array<number>(buckets).fill(0);
    for (const t of timestamped) {
      const idx = Math.min(buckets - 1, Math.floor(((t - min) / span) * buckets));
      counts[idx]++;
    }
    const peak = Math.max(...counts);
    return { min, max, span, counts, peak };
  }, [timestamped]);

  if (alerts.length === 0) return null;

  if (stats === null) {
    return (
      <div className="alert-timeline alert-timeline--empty">
        <span className="alert-timeline__title">Alert timeline</span>
        <p className="muted" style={{ fontSize: 12, margin: 0 }}>
          This detector aggregates over the full input window and doesn't carry
          a per-alert timestamp, so a temporal chart isn't applicable. The{" "}
          <strong>{alerts.length}</strong> alert
          {alerts.length === 1 ? "" : "s"} below summarize the entire input.
        </p>
      </div>
    );
  }

  const W = 720;
  const H = 90;
  const PAD_X = 48;
  const PAD_Y_TOP = 14;
  const PAD_Y_BOT = 26;
  const innerW = W - 2 * PAD_X;
  const innerH = H - PAD_Y_TOP - PAD_Y_BOT;
  const barW = innerW / stats.counts.length;

  return (
    <div className="alert-timeline">
      <div className="alert-timeline__head">
        <span className="alert-timeline__title">Alert timeline</span>
        <span className="alert-timeline__meta">
          {alerts.length} alerts · span {fmtDuration(stats.span)} · peak {stats.peak}/bucket
        </span>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-label="Distribution of alerts across the input time window"
        className="alert-timeline__svg"
      >
        {/* baseline */}
        <line
          x1={PAD_X}
          y1={H - PAD_Y_BOT}
          x2={W - PAD_X}
          y2={H - PAD_Y_BOT}
          stroke="var(--border-strong)"
          strokeWidth={1}
        />
        {/* bars */}
        {stats.counts.map((n, i) => {
          if (n === 0) return null;
          const h = (n / stats.peak) * innerH;
          const x = PAD_X + i * barW + 1;
          return (
            <rect
              key={i}
              x={x}
              y={H - PAD_Y_BOT - h}
              width={Math.max(2, barW - 2)}
              height={h}
              fill="var(--accent)"
              fillOpacity={0.7}
            >
              <title>{`bucket ${i + 1}/${stats.counts.length}: ${n} alert${n === 1 ? "" : "s"}`}</title>
            </rect>
          );
        })}
        {/* peak label */}
        <text
          x={PAD_X - 6}
          y={PAD_Y_TOP + 6}
          fontSize={10}
          fontFamily="var(--font-mono)"
          fill="var(--text-dim)"
          textAnchor="end"
        >
          {stats.peak}
        </text>
        <text
          x={PAD_X - 6}
          y={H - PAD_Y_BOT + 2}
          fontSize={10}
          fontFamily="var(--font-mono)"
          fill="var(--text-dim)"
          textAnchor="end"
        >
          0
        </text>
        {/* axis labels: min & max time */}
        <text
          x={PAD_X}
          y={H - 6}
          fontSize={10}
          fontFamily="var(--font-mono)"
          fill="var(--text-muted)"
        >
          {fmtTime(stats.min)}
        </text>
        <text
          x={W - PAD_X}
          y={H - 6}
          fontSize={10}
          fontFamily="var(--font-mono)"
          fill="var(--text-muted)"
          textAnchor="end"
        >
          {fmtTime(stats.max)}
        </text>
      </svg>
    </div>
  );
}
