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

export interface Case {
  id: string;
  title: string;
  view_name: string;
  mitre_technique: string;
  mitre_tactic: string;
  mitre_url: string;
  severity: Severity;
  status: "shipped";
  readme_md: string;
  attack_md: string;
  detection: Detection;
  fixtures: { positive: Fixture | null; negative: Fixture | null };
  wiring: CaseWiring;
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
  cases: Case[];
  planned: PlannedCase[];
}

export const dataset: Dataset = raw as Dataset;

export function getCase(id: string | undefined): Case | undefined {
  return dataset.cases.find((c) => c.id === id);
}

export function tacticLabel(t: string): string {
  return t.split("-").map((w) => w[0]?.toUpperCase() + w.slice(1)).join(" ");
}
