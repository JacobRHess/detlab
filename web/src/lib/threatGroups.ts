/* Adversary-group profile registry.
 *
 * Hand-curated short profiles for every group surfaced by the
 * `case.threat_groups` arrays. Sourced from MITRE ATT&CK group pages,
 * DFIR Report public intrusion writeups, and vendor reporting
 * (Mandiant, CrowdStrike, Microsoft DCU).
 *
 * Keys must match the strings in scripts/case_metadata.CASE_METADATA
 * (`threat_groups` lists) exactly — drift here means a group renders
 * with the "unknown" badge on the /threat-groups page.
 */

export type OriginBadge = "apt" | "ecrime" | "hacktivist" | "internal" | "unknown";

export interface GroupProfile {
  aliases: string;
  origin: string;
  motivation: string;
}

export const GROUP_PROFILES: Record<string, GroupProfile> = {
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

/** Map a group's free-text origin string to a stable badge slug. Groups
 * without a profile get "unknown" rather than silently classifying as
 * APT (which is what the substring-match fallback used to do). */
export function originBadge(name: string): OriginBadge {
  const profile = GROUP_PROFILES[name];
  if (!profile) return "unknown";
  const origin = profile.origin.toLowerCase();
  if (origin.includes("ecrime")) return "ecrime";
  if (origin.includes("hacktivist")) return "hacktivist";
  if (origin.includes("internal")) return "internal";
  return "apt";
}
