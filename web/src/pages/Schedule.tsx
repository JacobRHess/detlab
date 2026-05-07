/* Saved-search schedule visualizer.
 *
 * Every shipped detlab case ships a `cron_schedule` directive in its
 * generated savedsearches.conf. This page parses each cron expression
 * (via lib/cron.ts) and renders two views:
 *
 *   1. Aggregate density strip — 24h × 5-minute bins, coloured by total
 *      firings across all detections. Shows the SOC's "load" through
 *      the day.
 *   2. Per-search rows — each saved search gets its own 24h strip with
 *      tick marks at every firing minute, plus the cron expression and
 *      lookback window that produced it.
 *
 * Real Splunk admins eyeball this kind of view to tune cadence vs
 * search-head load — too many concurrent fires at :00 wastes capacity.
 */

import { useMemo } from "react";
import { Link } from "react-router-dom";

import { CaseSummary, dataset, ScheduleMeta, tacticLabel } from "../lib/cases";
import { firingsPerDay, parseCron, ParsedCron } from "../lib/cron";

interface SearchRow {
  case: CaseSummary;
  meta: ScheduleMeta;
  parsed: ParsedCron;
}

const BUCKET_MINUTES = 5;
const BUCKETS_PER_DAY = (24 * 60) / BUCKET_MINUTES; // 288

function bucketIndex(minute: number): number {
  return Math.floor(minute / BUCKET_MINUTES);
}

function buildAggregate(rows: SearchRow[]): number[] {
  const counts = new Array<number>(BUCKETS_PER_DAY).fill(0);
  for (const r of rows) {
    for (const m of r.parsed.minutes) counts[bucketIndex(m)]++;
  }
  return counts;
}

function PerSearchRow({ row, peak }: { row: SearchRow; peak: number }) {
  const counts = useMemo(() => {
    const c = new Array<number>(BUCKETS_PER_DAY).fill(0);
    for (const m of row.parsed.minutes) c[bucketIndex(m)] = 1;
    return c;
  }, [row]);
  void peak;
  return (
    <div className="schedule-row">
      <div className="schedule-row__meta">
        <Link to={`/case/${row.case.id}`} className="schedule-row__title">
          {row.case.title}
        </Link>
        <code className="schedule-row__cron">{row.meta.cron}</code>
        <span className="schedule-row__cadence muted">{row.parsed.cadence}</span>
        <span className="schedule-row__lookback muted">
          earliest {row.meta.earliest || "—"}
        </span>
      </div>
      <div
        className="schedule-row__strip"
        role="img"
        aria-label={`${row.case.title} firing schedule across 24 hours`}
      >
        {counts.map((n, i) => (
          <span
            key={i}
            className={`schedule-tick ${n > 0 ? "schedule-tick--on" : ""}`}
            style={n > 0 ? { background: "var(--accent)" } : undefined}
            title={n > 0 ? `${formatMinute(i * BUCKET_MINUTES)} fires` : undefined}
          />
        ))}
      </div>
    </div>
  );
}

function formatMinute(m: number): string {
  const h = Math.floor(m / 60);
  const min = m % 60;
  return `${h.toString().padStart(2, "0")}:${min.toString().padStart(2, "0")}`;
}

function AggregateBar({ counts }: { counts: number[] }) {
  const peak = Math.max(1, ...counts);
  return (
    <div className="schedule-aggregate">
      <div className="schedule-aggregate__strip">
        {counts.map((n, i) => {
          const height = (n / peak) * 100;
          return (
            <div
              key={i}
              className="schedule-aggregate__bar"
              style={{
                height: `${height.toFixed(1)}%`,
                background: n > 0 ? "var(--accent)" : "transparent",
                opacity: n === 0 ? 0 : 0.45 + 0.55 * (n / peak),
              }}
              title={`${formatMinute(i * BUCKET_MINUTES)} — ${n} search${n === 1 ? "" : "es"} firing`}
            />
          );
        })}
      </div>
      <div className="schedule-axis">
        {[0, 6, 12, 18, 24].map((h) => (
          <span key={h} style={{ left: `${(h / 24) * 100}%` }}>
            {h.toString().padStart(2, "0")}:00
          </span>
        ))}
      </div>
    </div>
  );
}

export default function Schedule() {
  const rows = useMemo<SearchRow[]>(() => {
    return dataset.cases
      .filter((c) => c.schedule !== null)
      .map((c) => ({
        case: c,
        meta: c.schedule as ScheduleMeta,
        parsed: parseCron((c.schedule as ScheduleMeta).cron),
      }))
      .sort((a, b) => b.parsed.minutes.length - a.parsed.minutes.length);
  }, []);

  const aggregate = useMemo(() => buildAggregate(rows), [rows]);
  const peak = useMemo(() => Math.max(0, ...aggregate), [aggregate]);
  const totalDailyFires = useMemo(
    () => rows.reduce((s, r) => s + r.parsed.minutes.length, 0),
    [rows],
  );
  const concurrent = useMemo(
    () => aggregate.filter((n) => n > 1).length,
    [aggregate],
  );

  return (
    <article>
      <div className="page-header">
        <h1>Search-schedule heatmap</h1>
        <p className="muted" style={{ maxWidth: 760 }}>
          Splunk runs each correlation search on a cron schedule shipped in{" "}
          <code>savedsearches.conf</code>. The mix of <code>*/1</code>,{" "}
          <code>*/5</code>, <code>*/10</code>, and <code>*/15</code> cadences
          across the detlab catalogue produces a daily fingerprint of
          search-head load. Concurrent fires at <code>:00</code> minutes are
          where capacity-tuning matters — the chart below makes them visible.
        </p>
      </div>

      <section className="kpi-strip" style={{ marginTop: 12 }}>
        <div className="kpi">
          <div className="kpi__value" style={{ color: "var(--accent)" }}>{rows.length}</div>
          <div className="kpi__label">Scheduled searches</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{totalDailyFires.toLocaleString()}</div>
          <div className="kpi__label">Total daily firings</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{peak}</div>
          <div className="kpi__label">Peak concurrency</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{concurrent}</div>
          <div className="kpi__label">Slots with ≥2 firing</div>
        </div>
      </section>

      <div className="section-title" style={{ marginTop: 24 }}>
        <h2>Aggregate density</h2>
        <span className="muted">5-minute bins · 24h cycle (height = concurrent fires)</span>
      </div>
      <AggregateBar counts={aggregate} />

      <div className="section-title" style={{ marginTop: 28 }}>
        <h2>Per-search schedule</h2>
        <span className="muted">click a row to open the case</span>
      </div>
      <div className="schedule-rows">
        {rows.map((row) => (
          <PerSearchRow key={row.case.id} row={row} peak={peak} />
        ))}
      </div>

      <h3 style={{ marginTop: 28 }}>Tuning notes</h3>
      <p className="muted" style={{ fontSize: 13, maxWidth: 760 }}>
        The catalogue intentionally staggers cadences by signal urgency:
        volumetric flood fires every minute (impact); DNS C2 / port scan /
        beaconing fire every 5 minutes (active intrusion); the slower
        lateral-movement &amp; exfil rules fire every 10–15 minutes (lower
        signal-to-noise). Aggregate firing-rate today:{" "}
        <strong>{(totalDailyFires / 1440).toFixed(1)}</strong> searches/min
        average across 24h — well within search-head capacity for a small
        Splunk install. Mixing in extra <code>cron_schedule = 1-59/N * * * *</code>{" "}
        offsets would smooth the <code>:00</code> spike further.
      </p>

      <h3 style={{ marginTop: 24 }}>Lookback by tactic</h3>
      <p className="muted" style={{ fontSize: 13, maxWidth: 760 }}>
        Each search's <code>dispatch.earliest_time</code> defines its
        lookback window — long enough to catch the slowest signal in the
        rule, short enough to keep the search cheap. detlab spans:
      </p>
      <div className="schedule-lookback">
        {rows.map((row) => (
          <Link key={row.case.id} to={`/case/${row.case.id}`} className="schedule-lookback__pill">
            <code>{row.meta.earliest || "—"}</code>
            <span>{row.case.title}</span>
            <span className="muted">{tacticLabel(row.case.mitre_tactic)}</span>
          </Link>
        ))}
      </div>

      <h3 style={{ marginTop: 24 }}>Daily cadence (firings/day)</h3>
      <p className="muted" style={{ fontSize: 13 }}>
        Sanity check — how many times the catalogue hits Splunk's scheduler:
      </p>
      <div className="schedule-cadence">
        {rows.map((row) => (
          <div key={row.case.id} className="schedule-cadence__row">
            <span className="schedule-cadence__name">{row.case.title}</span>
            <code className="schedule-cadence__count">
              {firingsPerDay(row.meta.cron).toLocaleString()}/day
            </code>
          </div>
        ))}
      </div>
    </article>
  );
}
