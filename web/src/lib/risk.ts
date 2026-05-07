/* Risk-score bucketing — one shared definition used by every page that
 * surfaces RBA scores (Risk leaderboard, case meta strip, ES Notable).
 *
 * The score scale is the standard SOC 0-100 RBA convention:
 *   90+  critical (page someone)
 *   70-89 high    (work it today)
 *   50-69 medium  (review by EOD)
 *   1-49  low     (background)
 *   0     unset   (case has no risk metadata)
 */

export type RiskBucketName = "critical" | "high" | "medium" | "low" | "none";

export interface RiskBucket {
  name: RiskBucketName;
  label: string;
  color: string;
}

const BUCKETS: { min: number; bucket: RiskBucket }[] = [
  { min: 90, bucket: { name: "critical", label: "Critical", color: "var(--danger)" } },
  { min: 70, bucket: { name: "high",     label: "High",     color: "#fb8c00" } },
  { min: 50, bucket: { name: "medium",   label: "Medium",   color: "var(--warn)" } },
  { min: 1,  bucket: { name: "low",      label: "Low",      color: "#7cb342" } },
];

const NONE: RiskBucket = { name: "none", label: "Unset", color: "var(--text-muted)" };

export function riskBucket(score: number): RiskBucket {
  if (score <= 0) return NONE;
  for (const { min, bucket } of BUCKETS) {
    if (score >= min) return bucket;
  }
  return NONE;
}

/** Short slug suitable for use in CSS class names. */
export function riskClass(score: number): RiskBucketName {
  return riskBucket(score).name;
}
