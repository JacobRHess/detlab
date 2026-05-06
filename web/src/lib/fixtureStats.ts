/* Compute summary stats from a fixture's JSON-lines content. The site already
   ships every fixture inline in cases.json, so these run client-side without
   network or Pyodide. Used by both the per-case Fixtures tab and the Stats
   page to render distributions. */

export interface FixtureSummary {
  recordCount: number;
  parseErrors: number;
  distinctSources: number;
  distinctDests: number;
  qtypeCounts: Record<string, number>;
  portCounts: Record<number, number>;
  rcodeCounts: Record<string, number>;
  hasDns: boolean;
  hasConn: boolean;
  /** Subdomain-length distribution for DNS records (max-label only). */
  subdomainLengths: number[];
  /** Conn duration distribution in seconds. */
  durations: number[];
  /** Total bytes (orig + resp) per record, for conn.log. */
  totalBytes: number[];
}

function parseLines(content: string): unknown[] {
  const out: unknown[] = [];
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      out.push(null);
    }
  }
  return out;
}

function leftLabel(query: string): string {
  return query.split(".")[0] ?? "";
}

export function summarize(content: string): FixtureSummary {
  const records = parseLines(content);
  const summary: FixtureSummary = {
    recordCount: 0,
    parseErrors: 0,
    distinctSources: 0,
    distinctDests: 0,
    qtypeCounts: {},
    portCounts: {},
    rcodeCounts: {},
    hasDns: false,
    hasConn: false,
    subdomainLengths: [],
    durations: [],
    totalBytes: [],
  };

  const sources = new Set<string>();
  const dests = new Set<string>();

  for (const r of records) {
    if (!r || typeof r !== "object") {
      summary.parseErrors++;
      continue;
    }
    summary.recordCount++;
    const rec = r as Record<string, unknown>;
    const src = (rec["id.orig_h"] ?? rec["src"]) as string | undefined;
    const dest = (rec["id.resp_h"] ?? rec["dest"]) as string | undefined;
    if (src) sources.add(src);
    if (dest) dests.add(dest);

    const port = rec["id.resp_p"];
    if (typeof port === "number") {
      summary.portCounts[port] = (summary.portCounts[port] ?? 0) + 1;
    }

    const qtype = rec.qtype_name;
    if (typeof qtype === "string" && qtype) {
      summary.qtypeCounts[qtype] = (summary.qtypeCounts[qtype] ?? 0) + 1;
      summary.hasDns = true;
    }

    const rcode = rec.rcode_name;
    if (typeof rcode === "string" && rcode) {
      summary.rcodeCounts[rcode] = (summary.rcodeCounts[rcode] ?? 0) + 1;
    }

    const query = rec.query;
    if (typeof query === "string" && query) {
      summary.subdomainLengths.push(leftLabel(query).length);
      summary.hasDns = true;
    }

    const duration = rec.duration;
    if (typeof duration === "number") {
      summary.durations.push(duration);
      summary.hasConn = true;
    }

    const orig = rec.orig_bytes;
    const resp = rec.resp_bytes;
    if (typeof orig === "number" || typeof resp === "number") {
      summary.totalBytes.push((typeof orig === "number" ? orig : 0) + (typeof resp === "number" ? resp : 0));
    }
  }

  summary.distinctSources = sources.size;
  summary.distinctDests = dests.size;
  return summary;
}

export function topN<K extends string | number>(
  counts: Record<K, number>,
  n: number,
): [K, number][] {
  return (Object.entries(counts) as [K, number][])
    .sort((a, b) => b[1] - a[1])
    .slice(0, n);
}

export function histogramBuckets(values: number[], buckets: number, max?: number): number[] {
  if (!values.length) return new Array(buckets).fill(0);
  const lo = 0;
  const hi = max ?? Math.max(...values);
  if (hi === lo) return [values.length, ...new Array(buckets - 1).fill(0)];
  const span = (hi - lo) / buckets;
  const counts = new Array(buckets).fill(0);
  for (const v of values) {
    const idx = Math.min(buckets - 1, Math.max(0, Math.floor((v - lo) / span)));
    counts[idx]++;
  }
  return counts;
}
