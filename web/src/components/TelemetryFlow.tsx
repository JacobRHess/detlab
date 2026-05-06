/* End-to-end architecture diagram for detlab.
 *
 * SVG-only — no chart library, no images. Renders the full data path:
 *
 *   network → sensors (Zeek + Suricata) → Splunk indexes → detlab macros
 *           → detlab_all_alerts → savedsearches + ES integration files
 *           → ES Incident Review · risk-based alerting
 *
 * Designed for the dark cyber palette in styles.css. Use on /about. */

const W = 980;
const H = 600;

interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
  title: string;
  subtitle?: string;
  fill?: string;
  stroke?: string;
}

const SENSOR: Box[] = [
  {
    x: 30,
    y: 60,
    w: 180,
    h: 80,
    title: "Zeek sensor",
    subtitle: "dns / conn / http / ssl",
    stroke: "var(--shipped)",
  },
  {
    x: 30,
    y: 170,
    w: 180,
    h: 80,
    title: "Suricata IDS",
    subtitle: "eve.json (alert + flow + dns)",
    stroke: "var(--accent)",
  },
];

const INDEXES: Box[] = [
  {
    x: 280,
    y: 60,
    w: 170,
    h: 80,
    title: "index=zeek",
    subtitle: "props.conf + field aliases",
    stroke: "var(--shipped)",
  },
  {
    x: 280,
    y: 170,
    w: 170,
    h: 80,
    title: "index=suricata",
    subtitle: "props.conf + flat field extracts",
    stroke: "var(--accent)",
  },
];

const MACROS: Box = {
  x: 510,
  y: 60,
  w: 200,
  h: 190,
  title: "detlab macros (14)",
  subtitle:
    "per-case SPL — aggregation, " +
    "CoV, IOC enrichment, entropy, chained",
  stroke: "var(--warn)",
};

const ALL_ALERTS: Box = {
  x: 770,
  y: 110,
  w: 180,
  h: 90,
  title: "detlab_all_alerts",
  subtitle: "shared macro · unified output",
  stroke: "var(--warn)",
};

const ES_BLOCKS: Box[] = [
  {
    x: 30,
    y: 320,
    w: 180,
    h: 70,
    title: "savedsearches.conf",
    subtitle: "scheduled rules",
  },
  {
    x: 230,
    y: 320,
    w: 200,
    h: 70,
    title: "correlationsearches.conf",
    subtitle: "ES Incident Review",
  },
  {
    x: 450,
    y: 320,
    w: 180,
    h: 70,
    title: "analyticstories.conf",
    subtitle: "per-tactic stories",
  },
  {
    x: 650,
    y: 320,
    w: 130,
    h: 70,
    title: "eventtypes",
    subtitle: "+ tags.conf",
  },
  {
    x: 800,
    y: 320,
    w: 150,
    h: 70,
    title: "workflow_actions",
    subtitle: "SOC pivots",
  },
];

const SOC: Box = {
  x: 280,
  y: 460,
  w: 420,
  h: 90,
  title: "Splunk ES — Incident Review · Risk-Based Alerting",
  subtitle: "notable events · per-host risk score · CIM data models",
  stroke: "var(--danger)",
};

function BoxNode(props: Box) {
  const stroke = props.stroke ?? "var(--border-strong)";
  return (
    <g>
      <rect
        x={props.x}
        y={props.y}
        width={props.w}
        height={props.h}
        rx={6}
        ry={6}
        fill="var(--surface)"
        stroke={stroke}
        strokeWidth={1.5}
      />
      <text
        x={props.x + props.w / 2}
        y={props.y + (props.subtitle ? 30 : props.h / 2 + 5)}
        textAnchor="middle"
        fill="var(--text)"
        fontFamily="var(--font-sans)"
        fontWeight={600}
        fontSize={14}
      >
        {props.title}
      </text>
      {props.subtitle && (
        <text
          x={props.x + props.w / 2}
          y={props.y + 52}
          textAnchor="middle"
          fill="var(--text-muted)"
          fontFamily="var(--font-mono)"
          fontSize={10.5}
        >
          {props.subtitle}
        </text>
      )}
    </g>
  );
}

function Arrow({ x1, y1, x2, y2 }: { x1: number; y1: number; x2: number; y2: number }) {
  return <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--text-dim)" strokeWidth={1.4} markerEnd="url(#arrow)" />;
}

export default function TelemetryFlow() {
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label="detlab telemetry flow architecture"
      style={{ width: "100%", height: "auto", maxHeight: 600 }}
    >
      <defs>
        <marker
          id="arrow"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 Z" fill="var(--text-dim)" />
        </marker>
      </defs>

      {/* Phase labels along the top */}
      {(
        [
          { x: 120, label: "1. Sensors" },
          { x: 365, label: "2. Indexes" },
          { x: 610, label: "3. Detection content" },
          { x: 860, label: "4. Aggregation" },
        ] as { x: number; label: string }[]
      ).map((p) => (
        <text
          key={p.label}
          x={p.x}
          y={28}
          textAnchor="middle"
          fill="var(--text-muted)"
          fontFamily="var(--font-sans)"
          fontSize={11}
          fontWeight={500}
          letterSpacing={1.4}
          textRendering="geometricPrecision"
        >
          {p.label.toUpperCase()}
        </text>
      ))}

      {/* Phase 1 → 2 */}
      {SENSOR.map((b) => (
        <BoxNode key={b.title} {...b} />
      ))}
      {INDEXES.map((b) => (
        <BoxNode key={b.title} {...b} />
      ))}
      <Arrow x1={210} y1={100} x2={278} y2={100} />
      <Arrow x1={210} y1={210} x2={278} y2={210} />

      {/* Phase 2 → 3 */}
      <BoxNode {...MACROS} />
      <Arrow x1={450} y1={100} x2={508} y2={130} />
      <Arrow x1={450} y1={210} x2={508} y2={180} />

      {/* Phase 3 → 4 */}
      <BoxNode {...ALL_ALERTS} />
      <Arrow x1={710} y1={155} x2={768} y2={155} />

      {/* Phase 5: ES integration */}
      <text
        x={W / 2}
        y={295}
        textAnchor="middle"
        fill="var(--text-muted)"
        fontFamily="var(--font-sans)"
        fontSize={11}
        fontWeight={500}
        letterSpacing={1.4}
      >
        5. SPLUNK ENTERPRISE SECURITY INTEGRATION (auto-generated)
      </text>
      {ES_BLOCKS.map((b) => (
        <BoxNode key={b.title} {...b} />
      ))}
      {/* fan-out arrows from detlab_all_alerts */}
      {ES_BLOCKS.map((b) => (
        <Arrow
          key={`arrow-${b.title}`}
          x1={860}
          y1={200}
          x2={b.x + b.w / 2}
          y2={b.y}
        />
      ))}

      {/* Phase 6: SOC */}
      <text
        x={W / 2}
        y={435}
        textAnchor="middle"
        fill="var(--text-muted)"
        fontFamily="var(--font-sans)"
        fontSize={11}
        fontWeight={500}
        letterSpacing={1.4}
      >
        6. SOC SURFACE
      </text>
      <BoxNode {...SOC} />
      {ES_BLOCKS.slice(1, 4).map((b) => (
        <Arrow
          key={`soc-arrow-${b.title}`}
          x1={b.x + b.w / 2}
          y1={b.y + b.h}
          x2={SOC.x + SOC.w / 2 + (b.x - 360) * 0.4}
          y2={SOC.y}
        />
      ))}
    </svg>
  );
}
