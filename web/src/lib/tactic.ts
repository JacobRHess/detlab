/* MITRE ATT&CK tactic colours.
 *
 * One canonical map used by every visualization that colours by tactic
 * (kill-chain timeline today, more later). Keeping this in one place
 * prevents the palette from drifting between pages — a recon technique
 * should be the same blue everywhere.
 */

export const TACTIC_COLOR: Record<string, string> = {
  reconnaissance:           "var(--accent)",
  "resource-development":   "#8b6cef",
  "initial-access":         "#f8be34",
  execution:                "#f8be34",
  persistence:              "#7cd6ff",
  "privilege-escalation":   "#dc4e41",
  "credential-access":      "#dc4e41",
  "defense-evasion":        "#9aa0a8",
  discovery:                "var(--accent)",
  "lateral-movement":       "#5cc8ff",
  collection:               "#7cd6ff",
  "command-and-control":    "#f8be34",
  exfiltration:             "#dc4e41",
  impact:                   "#dc4e41",
  /** Synthetic "multi-tactic" badge used by the kill-chain detector. */
  multi:                    "#dc4e41",
};

const FALLBACK = "var(--border-strong)";

export function tacticColor(tactic: string): string {
  return TACTIC_COLOR[tactic] ?? FALLBACK;
}
