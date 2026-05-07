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

export interface TriageMeta {
  steps: string[];
  false_positives: string[];
  containment: string[];
}

export interface RiskMeta {
  score: number;
  object_type: "system" | "user" | "other";
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
  /** Risk-Based Alerting score 0-100 (0 = unset). */
  risk_score: number;
  /** Which entity type the risk gets attributed to in Splunk ES. */
  risk_object_type: "system" | "user" | "other";
  /** Pyramid of Pain tier 1-6 (0 = unset). */
  pyramid_tier: number;
  data_sources: string[];
  threat_groups: string[];
  /** Splunk CIM data models the detection participates in. */
  cim_data_models: string[];
}

/** Heavy, fetched on demand. Used by CaseDetail. */
export interface CaseFull extends CaseSummary {
  readme_md: string;
  attack_md: string;
  detection: Detection;
  fixtures: { positive: Fixture | null; negative: Fixture | null };
  /** Pulled out of the case's sigma.yml at build time. */
  references: string[];
  risk: RiskMeta;
  triage: TriageMeta;
}

export interface PlannedCase {
  title: string;
  mitre_technique: string;
  mitre_tactic: string;
  mitre_url: string;
  status: "planned";
  /** S / M / L effort estimate. */
  effort: "S" | "M" | "L";
  rationale: string;
  detection_sketch: string;
}

export type TacticStatus = "covered" | "partial" | "planned" | "out_of_scope";

export interface TacticMeta {
  slug: string;
  name: string;
  description: string;
  scope_note: string;
  status: TacticStatus;
  shipped_count: number;
  planned_count: number;
}

export interface PyramidTierMeta {
  tier: number;
  label: string;
  color: string;
  description: string;
}

export interface DataSourceMeta {
  id: string;
  label: string;
  category: string;
  description: string;
}

export interface MacroEntry {
  name: string;
  definition: string;
  description: string;
  /** Only present for per-case macros. */
  case_id?: string;
}

export interface MacrosCatalogue {
  shared: MacroEntry[];
  per_case: MacroEntry[];
}

export interface CimDataModel {
  id: string;
  label: string;
  description: string;
  color: string;
  required_fields: string[];
}

export interface LookupEntry {
  filename: string;
  label: string;
  description: string;
  refresh_cadence: string;
  used_by: string[];
  row_count: number;
  fields: string[];
  sample_rows: string[][];
  missing: boolean;
}

export interface Dataset {
  schema_version: number;
  generated_at: string;
  cases: CaseSummary[];
  planned: PlannedCase[];
  tactics: TacticMeta[];
  pyramid_tiers: PyramidTierMeta[];
  data_sources: DataSourceMeta[];
  macros: MacrosCatalogue;
  cim_data_models: CimDataModel[];
  lookups: LookupEntry[];
}

export const dataset: Dataset = raw as Dataset;

export function getCase(id: string | undefined): CaseSummary | undefined {
  return dataset.cases.find((c) => c.id === id);
}

export function getTactic(slug: string | undefined): TacticMeta | undefined {
  return dataset.tactics.find((t) => t.slug === slug);
}

export function casesForTactic(slug: string): CaseSummary[] {
  return dataset.cases.filter((c) => c.mitre_tactic === slug);
}

export function plannedForTactic(slug: string): PlannedCase[] {
  return dataset.planned.filter((p) => p.mitre_tactic === slug);
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
  references: string[];
  risk: RiskMeta;
  triage: TriageMeta;
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
