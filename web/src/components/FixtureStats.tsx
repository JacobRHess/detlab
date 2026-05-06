import { useMemo } from "react";

import { Case } from "../lib/cases";
import { FixtureSummary, histogramBuckets, summarize, topN } from "../lib/fixtureStats";
import { BarChart, Donut, StatCard } from "./charts";

const QTYPE_COLOR: Record<string, string> = {
  A: "#5cc8ff",
  AAAA: "#7cd6ff",
  TXT: "#dc4e41",
  MX: "#f8be34",
  CNAME: "#9b6bff",
  NULL: "#999999",
};

const RCODE_COLOR: Record<string, string> = {
  NOERROR: "#53a051",
  NXDOMAIN: "#dc4e41",
  SERVFAIL: "#f8be34",
};

interface PanelProps {
  c: Case;
}

interface Section {
  summary: FixtureSummary;
  label: string;
}

function buildSections(c: Case): Section[] {
  const out: Section[] = [];
  if (c.fixtures.positive) out.push({ summary: summarize(c.fixtures.positive.content), label: "positive" });
  if (c.fixtures.negative) out.push({ summary: summarize(c.fixtures.negative.content), label: "negative" });
  return out;
}

function colorFor(table: Record<string, string>, key: string): string {
  return table[key] ?? "var(--accent)";
}

export default function FixtureStats({ c }: PanelProps) {
  const sections = useMemo(() => buildSections(c), [c]);

  if (!sections.length) return null;

  return (
    <>
      <p className="muted" style={{ fontSize: 13 }}>
        Computed live from the fixture in your browser — no server, no Pyodide
        for this view. The same content also feeds the detector playground above.
      </p>
      {sections.map((s) => (
        <div className="fixture-stats" key={s.label}>
          <div className="fixture-stats__panel" style={{ gridColumn: "1 / -1" }}>
            <h4>{s.label} fixture · summary</h4>
            <div className="stats-grid" style={{ marginBottom: 0 }}>
              <StatCard label="Records" value={s.summary.recordCount.toLocaleString()} />
              <StatCard label="Distinct sources" value={s.summary.distinctSources} />
              <StatCard label="Distinct destinations" value={s.summary.distinctDests} />
              {s.summary.hasDns && (
                <StatCard
                  label="Avg subdomain length"
                  value={
                    s.summary.subdomainLengths.length
                      ? Math.round(
                          (s.summary.subdomainLengths.reduce((a, b) => a + b, 0) /
                            s.summary.subdomainLengths.length) * 10,
                        ) / 10
                      : 0
                  }
                  hint="leftmost label, chars"
                />
              )}
              {s.summary.hasConn && (
                <StatCard
                  label="Avg duration"
                  value={
                    s.summary.durations.length
                      ? `${(s.summary.durations.reduce((a, b) => a + b, 0) / s.summary.durations.length).toFixed(2)} s`
                      : "—"
                  }
                />
              )}
              {s.summary.hasConn && s.summary.totalBytes.length > 0 && (
                <StatCard
                  label="Total bytes"
                  value={`${(s.summary.totalBytes.reduce((a, b) => a + b, 0) / 1024 / 1024).toFixed(1)} MB`}
                  hint="orig + resp, summed"
                />
              )}
            </div>
          </div>

          {Object.keys(s.summary.qtypeCounts).length > 0 && (
            <div className="fixture-stats__panel">
              <h4>DNS qtypes</h4>
              <Donut
                data={topN(s.summary.qtypeCounts, 6).map(([k, v]) => ({
                  label: k,
                  value: v,
                  color: colorFor(QTYPE_COLOR, k),
                }))}
                size={140}
                thickness={16}
                centerValue={s.summary.recordCount}
                centerLabel="queries"
              />
            </div>
          )}

          {Object.keys(s.summary.rcodeCounts).length > 0 && (
            <div className="fixture-stats__panel">
              <h4>DNS response codes</h4>
              <Donut
                data={topN(s.summary.rcodeCounts, 6).map(([k, v]) => ({
                  label: k,
                  value: v,
                  color: colorFor(RCODE_COLOR, k),
                }))}
                size={140}
                thickness={16}
                centerValue={s.summary.recordCount}
                centerLabel="responses"
              />
            </div>
          )}

          {Object.keys(s.summary.portCounts).length > 0 && (
            <div className="fixture-stats__panel">
              <h4>Top destination ports</h4>
              <BarChart
                data={topN(s.summary.portCounts, 6).map(([k, v]) => ({
                  label: `:${k}`,
                  value: v,
                  color: "var(--accent)",
                }))}
              />
            </div>
          )}

          {s.summary.subdomainLengths.length > 10 && (
            <div className="fixture-stats__panel">
              <h4>Subdomain length distribution</h4>
              <BarChart
                data={histogramBuckets(s.summary.subdomainLengths, 8, 64).map((count, i) => ({
                  label: `${Math.round((i * 64) / 8)}–${Math.round(((i + 1) * 64) / 8)}`,
                  value: count,
                  color: "var(--accent)",
                }))}
              />
            </div>
          )}

          {s.summary.durations.length > 5 && (
            <div className="fixture-stats__panel">
              <h4>Duration histogram (s)</h4>
              <BarChart
                data={(() => {
                  const max = Math.max(...s.summary.durations, 1);
                  return histogramBuckets(s.summary.durations, 8, max).map((count, i) => ({
                    label: `${((i * max) / 8).toFixed(1)}–${(((i + 1) * max) / 8).toFixed(1)}`,
                    value: count,
                    color: "var(--accent)",
                  }));
                })()}
              />
            </div>
          )}
        </div>
      ))}
    </>
  );
}
