/* Threat-group attribution page.
 *
 * Aggregates the per-case `threat_groups` arrays into a global view: which
 * adversary groups does the lab cover, and which detlab cases catch them?
 * The CTI-shaped story:
 *   - 1. lab catalogues real adversary groups
 *   - 2. each group is associated with techniques it's observed using
 *   - 3. each of those techniques maps to a shipped detlab detection
 *
 * That last step is the value the lab adds — every group pin on the page
 * resolves to "yes, we'd catch them."
 */

import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { CaseSummary, dataset, tacticLabel } from "../lib/cases";

interface GroupRow {
  name: string;
  cases: CaseSummary[];
  tactics: Set<string>;
  totalRisk: number;
}

/** Hand-curated short profiles for the headline adversaries the lab
 * touches. Sourced from MITRE ATT&CK group pages + DFIR Report public
 * intrusion writeups + Mandiant / CrowdStrike public reporting. Keys
 * must match strings in CASE_METADATA[*].threat_groups exactly. */
const GROUP_PROFILES: Record<string, { aliases: string; origin: string; motivation: string }> = {
  "APT29": {
    aliases: "Cozy Bear / NOBELIUM / Midnight Blizzard",
    origin: "Russia (SVR)",
    motivation: "State-sponsored espionage",
  },
  "NOBELIUM/APT29": {
    aliases: "Cozy Bear / Midnight Blizzard",
    origin: "Russia (SVR)",
    motivation: "State-sponsored espionage",
  },
  "APT41": {
    aliases: "Winnti / BARIUM / Wicked Panda",
    origin: "China (MSS-aligned)",
    motivation: "Espionage + financial",
  },
  "APT34": {
    aliases: "OilRig / HelixKitten",
    origin: "Iran",
    motivation: "Regional espionage",
  },
  "OilRig/APT34": {
    aliases: "HelixKitten",
    origin: "Iran",
    motivation: "Regional espionage",
  },
  "MuddyWater": {
    aliases: "TEMP.Zagros / Static Kitten",
    origin: "Iran (MOIS)",
    motivation: "Regional espionage",
  },
  "Volt Typhoon": {
    aliases: "VOLTZITE",
    origin: "China",
    motivation: "Critical-infrastructure pre-positioning",
  },
  "Sandworm": {
    aliases: "Voodoo Bear / IRIDIUM",
    origin: "Russia (GRU 74455)",
    motivation: "Disruption / espionage",
  },
  "Lazarus": {
    aliases: "HIDDEN COBRA / Diamond Sleet",
    origin: "North Korea",
    motivation: "Financial + espionage",
  },
  "FIN7": {
    aliases: "Carbanak / Sangria Tempest",
    origin: "eCrime",
    motivation: "Financial (POS, ransomware affiliate)",
  },
  "FIN11": {
    aliases: "TA505 / CL0P operators",
    origin: "eCrime",
    motivation: "Financial / extortion",
  },
  "Conti": {
    aliases: "Wizard Spider lineage",
    origin: "eCrime (Russia-aligned)",
    motivation: "Ransomware",
  },
  "Wizard Spider": {
    aliases: "TrickBot / Conti / Ryuk operator",
    origin: "eCrime",
    motivation: "Ransomware + banking trojan",
  },
  "Ryuk": {
    aliases: "Wizard Spider ransomware payload",
    origin: "eCrime",
    motivation: "Ransomware",
  },
  "BlackCat": {
    aliases: "ALPHV / Noberus",
    origin: "eCrime (RaaS)",
    motivation: "Ransomware",
  },
  "LockBit": {
    aliases: "Bitwise Spider",
    origin: "eCrime (RaaS)",
    motivation: "Ransomware",
  },
  "Akira": {
    aliases: "—",
    origin: "eCrime (RaaS)",
    motivation: "Ransomware",
  },
  "Hive": {
    aliases: "—",
    origin: "eCrime (RaaS, disrupted 2023)",
    motivation: "Ransomware",
  },
  "Vice Society": {
    aliases: "—",
    origin: "eCrime",
    motivation: "Ransomware (education / healthcare)",
  },
  "LAPSUS$": {
    aliases: "DEV-0537 / Strawberry Tempest",
    origin: "eCrime",
    motivation: "Extortion + brand humiliation",
  },
  "TrickBot operators": {
    aliases: "Wizard Spider",
    origin: "eCrime",
    motivation: "Banking trojan + access broker",
  },
  "Qakbot": {
    aliases: "QBot / Qakbot operators",
    origin: "eCrime (disrupted 2023)",
    motivation: "Loader / banking trojan",
  },
  "Qakbot operators": {
    aliases: "QBot",
    origin: "eCrime",
    motivation: "Loader / banking trojan",
  },
  "Emotet": {
    aliases: "Mealybug",
    origin: "eCrime",
    motivation: "Loader",
  },
  "BumbleBee": {
    aliases: "Loader successor to BazarLoader",
    origin: "eCrime",
    motivation: "Loader / initial access broker",
  },
  "Cobalt Strike operators": {
    aliases: "(commodity tool, multiple groups)",
    origin: "eCrime + APT (commodity)",
    motivation: "Post-exploitation framework",
  },
  "Mirai operators": {
    aliases: "Mirai variants (Moobot, Hajime…)",
    origin: "eCrime",
    motivation: "DDoS botnet",
  },
  "Outlaw": {
    aliases: "Shellbot / PerlBot",
    origin: "eCrime",
    motivation: "Crypto-mining + IRC botnet",
  },
  "TeamTNT": {
    aliases: "—",
    origin: "eCrime",
    motivation: "Cloud crypto-mining",
  },
  "KillNet": {
    aliases: "—",
    origin: "Hacktivist (pro-Russian)",
    motivation: "DDoS / influence",
  },
  "Anonymous-affiliated": {
    aliases: "—",
    origin: "Hacktivist",
    motivation: "Disruption / influence",
  },
  "Insider threats": {
    aliases: "—",
    origin: "Internal",
    motivation: "Data theft / sabotage",
  },
};

function originBadge(origin: string): string {
  if (origin.toLowerCase().includes("ecrime")) return "ecrime";
  if (origin.toLowerCase().includes("hacktivist")) return "hacktivist";
  if (origin.toLowerCase().includes("internal")) return "internal";
  return "apt";
}

export default function ThreatGroups() {
  const rows = useMemo<GroupRow[]>(() => {
    const map = new Map<string, GroupRow>();
    for (const c of dataset.cases) {
      for (const g of c.threat_groups) {
        const row =
          map.get(g) ??
          ({
            name: g,
            cases: [],
            tactics: new Set<string>(),
            totalRisk: 0,
          } as GroupRow);
        row.cases.push(c);
        row.tactics.add(c.mitre_tactic);
        row.totalRisk += c.risk_score;
        map.set(g, row);
      }
    }
    return Array.from(map.values()).sort((a, b) => b.cases.length - a.cases.length);
  }, []);

  // Anchor scroll on initial load if URL has #group-name (linked from cases)
  useEffect(() => {
    if (!window.location.hash) return;
    const id = decodeURIComponent(window.location.hash.slice(1));
    const el = document.getElementById(`group-${id}`);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  const totalGroups = rows.length;
  const apt = rows.filter((r) => originBadge(GROUP_PROFILES[r.name]?.origin ?? "") === "apt").length;
  const ecrime = rows.filter(
    (r) => originBadge(GROUP_PROFILES[r.name]?.origin ?? "") === "ecrime",
  ).length;

  const [filter, setFilter] = useState<"all" | "apt" | "ecrime">("all");
  const filtered = useMemo(() => {
    if (filter === "all") return rows;
    return rows.filter(
      (r) => originBadge(GROUP_PROFILES[r.name]?.origin ?? "") === filter,
    );
  }, [filter, rows]);

  return (
    <article>
      <div className="page-header">
        <h1>Threat-group coverage</h1>
        <p className="muted" style={{ maxWidth: 760 }}>
          Detection content is only as useful as the adversaries it catches. Each
          shipped detlab case lists the groups known to use that technique in the
          wild — sourced from MITRE ATT&amp;CK group pages, DFIR Report intrusion
          writeups, and vendor reporting (Mandiant, CrowdStrike, Microsoft). This
          page rolls those associations up so you can ask "would the detlab
          catalogue catch <em>group X</em>?"
        </p>
      </div>

      <section className="kpi-strip" style={{ marginTop: 12 }}>
        <div className="kpi">
          <div className="kpi__value" style={{ color: "var(--shipped)" }}>{totalGroups}</div>
          <div className="kpi__label">Adversary groups covered</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{apt}</div>
          <div className="kpi__label">State / APT</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{ecrime}</div>
          <div className="kpi__label">eCrime / RaaS</div>
        </div>
        <div className="kpi">
          <div className="kpi__value">{dataset.cases.length}</div>
          <div className="kpi__label">Detections cross-referenced</div>
        </div>
      </section>

      <div className="threat-filter">
        <span className="muted" style={{ fontSize: 12 }}>filter</span>
        {(["all", "apt", "ecrime"] as const).map((f) => (
          <button
            key={f}
            type="button"
            className={`btn ${filter === f ? "btn--primary" : ""}`}
            onClick={() => setFilter(f)}
          >
            {f === "all" ? "All" : f === "apt" ? "State / APT" : "eCrime"}
          </button>
        ))}
      </div>

      <div className="threat-grid">
        {filtered.map((row) => {
          const profile = GROUP_PROFILES[row.name];
          const badge = originBadge(profile?.origin ?? "");
          return (
            <div key={row.name} id={`group-${row.name}`} className={`threat-card threat-card--${badge}`}>
              <div className="threat-card__head">
                <h3>{row.name}</h3>
                <span className={`threat-card__badge threat-card__badge--${badge}`}>
                  {badge.toUpperCase()}
                </span>
              </div>
              {profile && (
                <div className="threat-card__profile">
                  <div>
                    <span className="threat-card__label">aliases</span>
                    <span>{profile.aliases || "—"}</span>
                  </div>
                  <div>
                    <span className="threat-card__label">origin</span>
                    <span>{profile.origin}</span>
                  </div>
                  <div>
                    <span className="threat-card__label">motivation</span>
                    <span>{profile.motivation}</span>
                  </div>
                </div>
              )}
              <div className="threat-card__stats">
                <span><strong>{row.cases.length}</strong> detection{row.cases.length === 1 ? "" : "s"}</span>
                <span><strong>{row.tactics.size}</strong> tactic{row.tactics.size === 1 ? "" : "s"}</span>
                <span><strong>{row.totalRisk}</strong> aggregate risk</span>
              </div>
              <div className="threat-card__cases">
                {row.cases.map((c) => (
                  <Link key={c.id} to={`/case/${c.id}`} className="threat-case-chip" title={c.title}>
                    <code>{c.mitre_technique}</code>
                    <span>{tacticLabel(c.mitre_tactic)}</span>
                  </Link>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </article>
  );
}
