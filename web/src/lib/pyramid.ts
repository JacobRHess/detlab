/* Pyramid of Pain — short-label registry shared between the dedicated
 * /pyramid page and the per-case meta strip on CaseDetail.
 *
 * The full labels ("Tactics, Techniques, Procedures") are too wide to
 * render inside compact UI; the short forms below are the convention
 * the rest of the detection-engineering literature uses. */

export const PYRAMID_SHORT: Record<number, string> = {
  1: "hash",
  2: "IP",
  3: "domain",
  4: "artifact",
  5: "tool",
  6: "TTP",
};

export const PYRAMID_SHORT_PLURAL: Record<number, string> = {
  1: "Hashes",
  2: "IPs",
  3: "Domains",
  4: "Artifacts",
  5: "Tools",
  6: "TTPs",
};

export function pyramidShortLabel(tier: number): string {
  return PYRAMID_SHORT[tier] ?? "unknown";
}

export function pyramidShortPlural(tier: number): string {
  return PYRAMID_SHORT_PLURAL[tier] ?? "Unknown";
}
