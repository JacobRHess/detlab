/* Case data access.
 *
 * `dataset` is a small bundle that ships with the site — every page can
 * read it synchronously. Per-case detail (README, SPL, fixtures) is heavier
 * and lives at /cases/<id>.json; `loadCase` fetches it on demand and caches
 * the result, so navigating between cases reads from memory after the first
 * visit. Keep heavy fields out of the summary so the bundle stays small as
 * the lab grows. */

import raw from "../data/cases.json";

export type Severity = "low" | "medium" | "high" | "critical";

export interface Fixture {
  filename: string;
  line_count: number;
  content: string;
}

export interface CaseWiring {
  detector_function?: string;
  fixture_kind?: string;
}

export interface Detection {
  spl: string;
  macros_conf: string;
  savedsearches_conf: string;
  sigma_yaml: string;
}

export interface FixtureRecordCounts {
  positive: number;
  negative: number;
}

/** Lightweight, bundled. Used by Home, Stats, AttackMatrix. */
export interface CaseSummary {
  id: string;
  title: string;
  view_name: string;
  mitre_technique: string;
  mitre_tactic: string;
  mitre_url: string;
  severity: Severity;
  status: "shipped";
  fixture_record_counts: FixtureRecordCounts;
  wiring: CaseWiring;
}

/** Heavy, fetched on demand. Used by CaseDetail. */
export interface CaseFull extends CaseSummary {
  readme_md: string;
  attack_md: string;
  detection: Detection;
  fixtures: { positive: Fixture | null; negative: Fixture | null };
}

export interface PlannedCase {
  title: string;
  mitre_technique: string;
  mitre_tactic: string;
  mitre_url: string;
  status: "planned";
}

export interface Dataset {
  schema_version: number;
  generated_at: string;
  cases: CaseSummary[];
  planned: PlannedCase[];
}

export const dataset: Dataset = raw as Dataset;

export function getCase(id: string | undefined): CaseSummary | undefined {
  return dataset.cases.find((c) => c.id === id);
}

export function tacticLabel(t: string): string {
  return t
    .split("-")
    .map((w) => (w[0]?.toUpperCase() ?? "") + w.slice(1))
    .join(" ");
}

// ---------- Async per-case loader ----------

const cache = new Map<string, CaseFull>();
const inFlight = new Map<string, Promise<CaseFull | null>>();

interface PerCaseDetail {
  id: string;
  readme_md: string;
  attack_md: string;
  detection: Detection;
  fixtures: { positive: Fixture | null; negative: Fixture | null };
}

export async function loadCase(id: string): Promise<CaseFull | null> {
  const cached = cache.get(id);
  if (cached) return cached;

  const pending = inFlight.get(id);
  if (pending) return pending;

  const summary = getCase(id);
  if (!summary) return null;

  const url = `${import.meta.env.BASE_URL}cases/${id}.json`;
  const promise = (async () => {
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`fetch ${url}: ${response.status}`);
      }
      const detail = (await response.json()) as PerCaseDetail;
      const full: CaseFull = { ...summary, ...detail };
      cache.set(id, full);
      return full;
    } finally {
      inFlight.delete(id);
    }
  })();

  inFlight.set(id, promise);
  return promise;
}
