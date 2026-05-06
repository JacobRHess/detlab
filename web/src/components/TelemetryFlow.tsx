/* End-to-end architecture diagram for detlab.
 *
 * Vertical flow, six phases. Box widths are fixed and subtitles are
 * deliberately short so nothing overflows. Use on /about. */

interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
  title: string;
  subtitle?: string;
  accent?: string;
}

const W = 920;
const ROW = 90;
const GAP = 24;
const PHASE_LABEL_X = 20;

// Phase 1: sensors
const PHASE1_Y = 80;
const SENSORS: Box[] = [
  {
    x: 220,
    y: PHASE1_Y,
    w: 220,
    h: ROW,
    title: "Zeek sensor",
    subtitle: "dns · conn · http · ssl",
    accent: "var(--shipped)",
  },
  {
    x: 480,
    y: PHASE1_Y,
    w: 220,
    h: ROW,
    title: "Suricata IDS",
    subtitle: "eve.json (alerts)",
    accent: "var(--accent)",
  },
];

// Phase 2: Splunk indexes
const PHASE2_Y = PHASE1_Y + ROW + GAP;
const INDEXES: Box[] = [
  {
    x: 220,
    y: PHASE2_Y,
    w: 220,
    h: ROW,
    title: "index=zeek",
    subtitle: "props.conf field aliases",
    accent: "var(--shipped)",
  },
  {
    x: 480,
    y: PHASE2_Y,
    w: 220,
    h: ROW,
    title: "index=suricata",
    subtitle: "flat alert subfields",
    accent: "var(--accent)",
  },
];

// Phase 3: detlab macros
const PHASE3_Y = PHASE2_Y + ROW + GAP;
const MACROS: Box = {
  x: 160,
  y: PHASE3_Y,
  w: 600,
  h: ROW,
  title: "detlab macros (per-case SPL)",
  subtitle: "14 detections · 6 styles · CIM-aliased",
  accent: "var(--warn)",
};

// Phase 4: detlab_all_alerts
const PHASE4_Y = PHASE3_Y + ROW + GAP;
const ALL_ALERTS: Box = {
  x: 320,
  y: PHASE4_Y,
  w: 280,
  h: ROW,
  title: "detlab_all_alerts",
  subtitle: "shared aggregation macro",
  accent: "var(--warn)",
};

// Phase 5: ES integration outputs (5 narrow boxes, evenly spaced).
const PHASE5_Y = PHASE4_Y + ROW + GAP;
const ES_BOX_W = 168;
const ES_BOX_GAP = 12;
const ES_BOX_TOTAL = 5 * ES_BOX_W + 4 * ES_BOX_GAP;
const ES_X0 = (W - ES_BOX_TOTAL) / 2;
const ES_BLOCKS: Box[] = [
  "savedsearches.conf",
  "correlationsearches.conf",
  "analyticstories.conf",
  "eventtypes + tags",
  "workflow_actions.conf",
].map((title, i) => ({
  x: ES_X0 + i * (ES_BOX_W + ES_BOX_GAP),
  y: PHASE5_Y,
  w: ES_BOX_W,
  h: ROW,
  title,
  subtitle: "auto-generated",
  accent: "var(--accent)",
}));

// Phase 6: SOC outcome
const PHASE6_Y = PHASE5_Y + ROW + GAP;
const SOC: Box = {
  x: 160,
  y: PHASE6_Y,
  w: 600,
  h: ROW,
  title: "Splunk ES — Incident Review",
  subtitle: "notable events · risk-based alerting · CIM data models",
  accent: "var(--danger)",
};

const H = PHASE6_Y + ROW + 30;

const PHASES: { y: number; label: string }[] = [
  { y: PHASE1_Y, label: "1 · SENSORS" },
  { y: PHASE2_Y, label: "2 · INDEXES" },
  { y: PHASE3_Y, label: "3 · DETECTION CONTENT" },
  { y: PHASE4_Y, label: "4 · AGGREGATION" },
  { y: PHASE5_Y, label: "5 · ES INTEGRATION" },
  { y: PHASE6_Y, label: "6 · SOC SURFACE" },
];

function BoxNode({ box }: { box: Box }) {
  const stroke = box.accent ?? "var(--border-strong)";
  return (
    <g>
      <rect
        x={box.x}
        y={box.y}
        width={box.w}
        height={box.h}
        rx={6}
        ry={6}
        fill="var(--surface)"
        stroke={stroke}
        strokeWidth={1.5}
      />
      <text
        x={box.x + box.w / 2}
        y={box.y + (box.subtitle ? 38 : box.h / 2 + 5)}
        textAnchor="middle"
        fill="var(--text)"
        fontFamily="var(--font-sans)"
        fontWeight={600}
        fontSize={14}
      >
        {box.title}
      </text>
      {box.subtitle && (
        <text
          x={box.x + box.w / 2}
          y={box.y + 60}
          textAnchor="middle"
          fill="var(--text-muted)"
          fontFamily="var(--font-mono)"
          fontSize={11}
        >
          {box.subtitle}
        </text>
      )}
    </g>
  );
}

function Arrow({ x1, y1, x2, y2 }: { x1: number; y1: number; x2: number; y2: number }) {
  return (
    <line
      x1={x1}
      y1={y1}
      x2={x2}
      y2={y2}
      stroke="var(--text-dim)"
      strokeWidth={1.4}
      markerEnd="url(#tf-arrow)"
    />
  );
}

export default function TelemetryFlow() {
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label="detlab telemetry flow architecture"
      style={{ width: "100%", height: "auto", display: "block" }}
    >
      <defs>
        <marker
          id="tf-arrow"
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

      {/* Phase labels along the left margin */}
      {PHASES.map((p) => (
        <text
          key={p.label}
          x={PHASE_LABEL_X}
          y={p.y + 22}
          fill="var(--text-muted)"
          fontFamily="var(--font-sans)"
          fontSize={10}
          fontWeight={600}
          letterSpacing={1.2}
        >
          {p.label}
        </text>
      ))}

      {/* Phase 1: sensors */}
      {SENSORS.map((b) => (
        <BoxNode key={b.title} box={b} />
      ))}

      {/* Phase 1 → 2 (vertical) */}
      <Arrow x1={330} y1={PHASE1_Y + ROW} x2={330} y2={PHASE2_Y} />
      <Arrow x1={590} y1={PHASE1_Y + ROW} x2={590} y2={PHASE2_Y} />

      {/* Phase 2: indexes */}
      {INDEXES.map((b) => (
        <BoxNode key={b.title} box={b} />
      ))}

      {/* Phase 2 → 3 (converge into the macros box) */}
      <Arrow x1={330} y1={PHASE2_Y + ROW} x2={400} y2={PHASE3_Y} />
      <Arrow x1={590} y1={PHASE2_Y + ROW} x2={520} y2={PHASE3_Y} />

      {/* Phase 3: macros */}
      <BoxNode box={MACROS} />

      {/* Phase 3 → 4 (vertical) */}
      <Arrow x1={460} y1={PHASE3_Y + ROW} x2={460} y2={PHASE4_Y} />

      {/* Phase 4: aggregation */}
      <BoxNode box={ALL_ALERTS} />

      {/* Phase 4 → 5: fan out from detlab_all_alerts */}
      {ES_BLOCKS.map((b) => (
        <Arrow
          key={`fan-${b.title}`}
          x1={460}
          y1={PHASE4_Y + ROW}
          x2={b.x + b.w / 2}
          y2={PHASE5_Y}
        />
      ))}

      {/* Phase 5: ES outputs */}
      {ES_BLOCKS.map((b) => (
        <BoxNode key={b.title} box={b} />
      ))}

      {/* Phase 5 → 6: only the middle three feed the SOC view */}
      {[ES_BLOCKS[1], ES_BLOCKS[2], ES_BLOCKS[3]].map((b) => (
        <Arrow
          key={`soc-${b.title}`}
          x1={b.x + b.w / 2}
          y1={PHASE5_Y + ROW}
          x2={SOC.x + SOC.w / 2}
          y2={PHASE6_Y}
        />
      ))}

      {/* Phase 6: outcome */}
      <BoxNode box={SOC} />
    </svg>
  );
}
