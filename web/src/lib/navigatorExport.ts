/* Build a MITRE ATT&CK Navigator layer JSON describing detlab's coverage.
 * The shape follows the v4.5 layer schema so the file imports cleanly into
 * https://mitre-attack.github.io/attack-navigator/. */

import { dataset } from "./cases";

const SEVERITY_COLOR: Record<string, string> = {
  low: "#5cc8ff",
  medium: "#f8be34",
  high: "#dc4e41",
  critical: "#dc4e41",
};

interface NavigatorTechnique {
  techniqueID: string;
  color: string;
  comment: string;
  enabled: boolean;
  metadata?: { name: string; value: string }[];
}

export function buildNavigatorLayer() {
  const techniques: NavigatorTechnique[] = dataset.cases.map((c) => ({
    techniqueID: c.mitre_technique,
    color: SEVERITY_COLOR[c.severity] ?? "#53a051",
    comment: `${c.title} · severity ${c.severity}`,
    enabled: true,
    metadata: [
      { name: "case", value: c.id },
      { name: "view", value: c.view_name },
      { name: "detector", value: c.wiring.detector_function ?? "" },
    ],
  }));

  for (const p of dataset.planned) {
    techniques.push({
      techniqueID: p.mitre_technique,
      color: "#9aa0a8",
      comment: `${p.title} · planned`,
      enabled: false,
    });
  }

  return {
    name: "detlab coverage",
    versions: { attack: "14", navigator: "4.9.1", layer: "4.5" },
    domain: "enterprise-attack",
    description:
      "Network-detection coverage produced by detlab " +
      "(github.com/JacobRHess/detlab). Generated " +
      new Date().toISOString().slice(0, 10) +
      ".",
    sorting: 0,
    layout: { layout: "side", showName: true, showID: true },
    hideDisabled: false,
    techniques,
    gradient: {
      colors: ["#ffffff", "#dc4e41"],
      minValue: 0,
      maxValue: 1,
    },
    legendItems: [
      { label: "low severity", color: SEVERITY_COLOR.low },
      { label: "medium severity", color: SEVERITY_COLOR.medium },
      { label: "high / critical severity", color: SEVERITY_COLOR.high },
      { label: "planned (disabled)", color: "#9aa0a8" },
    ],
    showTacticRowBackground: false,
    selectTechniquesAcrossTactics: true,
  };
}

export function downloadNavigatorLayer() {
  const layer = buildNavigatorLayer();
  const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "detlab-coverage.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
