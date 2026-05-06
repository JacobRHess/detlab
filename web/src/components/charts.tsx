/* Hand-rolled SVG chart primitives. Zero deps so the bundle stays small.
   Designed for the dark cyber palette already in styles.css. */

import { ReactNode } from "react";

// ---------- Bar chart (horizontal) ----------

export interface BarDatum {
  label: string;
  value: number;
  color?: string;
  href?: string;
}

interface BarChartProps {
  data: BarDatum[];
  formatValue?: (v: number) => string;
  rowHeight?: number;
  maxValue?: number;
}

export function BarChart({
  data,
  formatValue = (v) => v.toLocaleString(),
  rowHeight = 28,
  maxValue,
}: BarChartProps) {
  const max = maxValue ?? Math.max(1, ...data.map((d) => d.value));
  return (
    <div className="bar-chart">
      {data.map((d, i) => {
        const pct = (d.value / max) * 100;
        const color = d.color ?? "var(--accent)";
        return (
          <div className="bar-chart__row" key={`${d.label}-${i}`} style={{ height: rowHeight }}>
            <div className="bar-chart__label" title={d.label}>
              {d.label}
            </div>
            <div className="bar-chart__track">
              <div
                className="bar-chart__fill"
                style={{ width: `${pct}%`, background: color }}
                title={`${d.label}: ${formatValue(d.value)}`}
              />
            </div>
            <div className="bar-chart__value">{formatValue(d.value)}</div>
          </div>
        );
      })}
    </div>
  );
}

// ---------- Donut chart ----------

export interface DonutDatum {
  label: string;
  value: number;
  color: string;
}

interface DonutProps {
  data: DonutDatum[];
  size?: number;
  thickness?: number;
  centerLabel?: ReactNode;
  centerValue?: ReactNode;
}

export function Donut({
  data,
  size = 160,
  thickness = 18,
  centerLabel,
  centerValue,
}: DonutProps) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const radius = size / 2 - thickness / 2;
  const circumference = 2 * Math.PI * radius;

  let offset = 0;
  const segments = data.map((d, i) => {
    const frac = total === 0 ? 0 : d.value / total;
    const length = circumference * frac;
    const seg = (
      <circle
        key={`${d.label}-${i}`}
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={d.color}
        strokeWidth={thickness}
        strokeDasharray={`${length} ${circumference - length}`}
        strokeDashoffset={-offset}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      >
        <title>{`${d.label}: ${d.value}`}</title>
      </circle>
    );
    offset += length;
    return seg;
  });

  return (
    <div className="donut">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--surface-2)"
          strokeWidth={thickness}
        />
        {segments}
      </svg>
      <div className="donut__center">
        {centerValue !== undefined && <div className="donut__value">{centerValue}</div>}
        {centerLabel !== undefined && <div className="donut__label">{centerLabel}</div>}
      </div>
      <ul className="donut__legend">
        {data.map((d) => (
          <li key={d.label}>
            <span className="donut__swatch" style={{ background: d.color }} />
            <span className="donut__legend-label">{d.label}</span>
            <span className="donut__legend-value">{d.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------- Sparkline ----------

interface SparklineProps {
  values: number[];
  width?: number;
  height?: number;
  color?: string;
  fill?: string;
  showDots?: boolean;
}

export function Sparkline({
  values,
  width = 120,
  height = 32,
  color = "var(--accent)",
  fill = "rgba(92, 200, 255, 0.15)",
  showDots = false,
}: SparklineProps) {
  if (values.length < 2) {
    return (
      <svg width={width} height={height} aria-label="Sparkline (insufficient data)">
        <line x1={0} y1={height / 2} x2={width} y2={height / 2} stroke="var(--border)" />
      </svg>
    );
  }
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const stepX = width / (values.length - 1);
  const points = values.map((v, i) => {
    const x = i * stepX;
    const y = height - ((v - min) / range) * height;
    return [x, y] as const;
  });
  const path = points.map(([x, y], i) => (i === 0 ? `M ${x} ${y}` : `L ${x} ${y}`)).join(" ");
  const fillPath = `${path} L ${width} ${height} L 0 ${height} Z`;
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
      <path d={fillPath} fill={fill} />
      <path d={path} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" />
      {showDots &&
        points.map(([x, y], i) => (
          <circle key={i} cx={x} cy={y} r={2} fill={color} />
        ))}
    </svg>
  );
}

// ---------- ATT&CK Heatmap ----------

export interface HeatmapCell {
  id: string;
  label: string;
  href?: string;
  intensity: number; // 0–1
  status: "shipped" | "planned" | "uncovered";
  meta?: ReactNode;
}

export interface HeatmapColumn {
  title: string;
  cells: HeatmapCell[];
}

interface HeatmapProps {
  columns: HeatmapColumn[];
  onCellClick?: (cell: HeatmapCell) => void;
}

const STATUS_BG: Record<HeatmapCell["status"], string> = {
  shipped: "var(--shipped)",
  planned: "var(--warn)",
  uncovered: "var(--surface-2)",
};

export function Heatmap({ columns, onCellClick }: HeatmapProps) {
  return (
    <div className="heatmap">
      {columns.map((col) => (
        <div className="heatmap__col" key={col.title}>
          <div className="heatmap__col-head">{col.title}</div>
          <div className="heatmap__cells">
            {col.cells.map((cell) => {
              const bg = STATUS_BG[cell.status];
              const opacity = cell.status === "uncovered" ? 1 : 0.45 + cell.intensity * 0.55;
              const Inner = (
                <>
                  <div className="heatmap__cell-id">{cell.id}</div>
                  <div className="heatmap__cell-label">{cell.label}</div>
                </>
              );
              const baseProps = {
                className: `heatmap__cell heatmap__cell--${cell.status}`,
                style: { background: bg, opacity },
                title: `${cell.id} · ${cell.label} · ${cell.status}`,
              };
              if (cell.href) {
                return (
                  <a key={cell.id} href={cell.href} {...baseProps}>
                    {Inner}
                  </a>
                );
              }
              if (onCellClick) {
                return (
                  <button
                    key={cell.id}
                    type="button"
                    onClick={() => onCellClick(cell)}
                    {...baseProps}
                  >
                    {Inner}
                  </button>
                );
              }
              return (
                <div key={cell.id} {...baseProps}>
                  {Inner}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------- Stat card ----------

interface StatCardProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  trend?: number[];
  accent?: string;
}

export function StatCard({ label, value, hint, trend, accent }: StatCardProps) {
  return (
    <div className="stat-card">
      <div className="stat-card__value" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      <div className="stat-card__label">{label}</div>
      {hint !== undefined && <div className="stat-card__hint">{hint}</div>}
      {trend && trend.length >= 2 && (
        <div className="stat-card__trend">
          <Sparkline values={trend} width={120} height={28} color={accent ?? "var(--accent)"} />
        </div>
      )}
    </div>
  );
}
