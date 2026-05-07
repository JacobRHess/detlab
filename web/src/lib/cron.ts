/* Tiny cron-expression parser, scoped to the patterns the detlab saved
 * searches actually use — the standard `step / star-slash` pattern that
 * means "fire every N minutes, all hours, all days". Returns the set
 * of UTC minutes-of-day at which a search fires within a 24-hour
 * window. Anything we don't recognise falls back to "never fires" and
 * the caller decides how to render it. Keeping this narrow on purpose;
 * extend the field-token parser when a new cadence shape ships. */

export interface ParsedCron {
  /** Sorted, deduped list of minutes-of-day (0..1439) at which the search fires. */
  minutes: number[];
  /** Human-readable cadence label. */
  cadence: string;
}

const STAR_SLASH = /^\*\/(\d+)$/;
const NUMERIC = /^\d+$/;
const RANGE = /^(\d+)-(\d+)$/;

function expandField(token: string, max: number): number[] {
  if (token === "*") {
    const out: number[] = [];
    for (let i = 0; i < max; i++) out.push(i);
    return out;
  }
  const slash = STAR_SLASH.exec(token);
  if (slash) {
    const step = Number(slash[1]);
    if (step <= 0) return [];
    const out: number[] = [];
    for (let i = 0; i < max; i += step) out.push(i);
    return out;
  }
  if (NUMERIC.test(token)) {
    return [Number(token)];
  }
  const range = RANGE.exec(token);
  if (range) {
    const lo = Number(range[1]);
    const hi = Number(range[2]);
    const out: number[] = [];
    for (let i = lo; i <= hi && i < max; i++) out.push(i);
    return out;
  }
  // Fallback: comma list.
  if (token.includes(",")) {
    return token
      .split(",")
      .flatMap((part) => expandField(part, max))
      .filter((n) => n < max);
  }
  return [];
}

export function parseCron(expr: string): ParsedCron {
  const fields = expr.trim().split(/\s+/);
  if (fields.length < 5) return { minutes: [], cadence: "(invalid)" };
  const [minute, hour] = fields;
  const minutes = expandField(minute, 60);
  const hours = expandField(hour, 24);
  if (!minutes.length || !hours.length) return { minutes: [], cadence: "(invalid)" };

  const set = new Set<number>();
  for (const h of hours) for (const m of minutes) set.add(h * 60 + m);
  const sorted = Array.from(set).sort((a, b) => a - b);

  return { minutes: sorted, cadence: cadenceLabel(expr, sorted.length) };
}

function cadenceLabel(expr: string, dailyCount: number): string {
  const slash = STAR_SLASH.exec(expr.trim().split(/\s+/)[0] ?? "");
  if (slash) {
    const step = Number(slash[1]);
    if (step === 1) return "every minute";
    return `every ${step} minutes`;
  }
  if (dailyCount === 24) return "hourly";
  if (dailyCount === 1) return "daily";
  return `${dailyCount}x / day`;
}

/** Daily firing count for the cron expression — convenience for KPIs. */
export function firingsPerDay(expr: string): number {
  return parseCron(expr).minutes.length;
}
