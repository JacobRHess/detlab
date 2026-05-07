/* "Open in your Splunk" — bridges the static portfolio site to the user's
 * own Splunk Web. Hostname is stored in localStorage; a small settings UI
 * in the App header lets the user set/clear it.
 *
 * Once set, every per-case dashboard link and SPL preview gets a clickable
 * deep link to <host>/en-US/app/detlab/<view> or
 * <host>/en-US/app/search/search?q=<spl>.
 *
 * The Splunk hostname stays client-side — no analytics, nothing leaves
 * the browser. */

const STORAGE_KEY = "detlab.splunk_host";

/** Read the saved Splunk Web URL (e.g., "https://splunk.example:8000").
 * Empty string means "not configured". */
export function getSplunkHost(): string {
  if (typeof window === "undefined") return "";
  try {
    return window.localStorage.getItem(STORAGE_KEY) || "";
  } catch {
    return "";
  }
}

export function setSplunkHost(host: string): void {
  if (typeof window === "undefined") return;
  const trimmed = host.trim().replace(/\/$/, "");
  try {
    if (trimmed) window.localStorage.setItem(STORAGE_KEY, trimmed);
    else window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* localStorage unavailable (private mode, quota) — silently no-op */
  }
}

/** Build a deep link to a Splunk Web dashboard view inside the detlab app.
 * Returns null if no host is configured. */
export function dashboardUrl(viewName: string): string | null {
  const host = getSplunkHost();
  if (!host || !viewName) return null;
  return `${host}/en-US/app/detlab/${encodeURIComponent(viewName)}`;
}

/** Build a deep link that opens the Splunk Search & Reporting app with a
 * pre-populated search string. Time range tokens are filled in via the
 * `earliest` / `latest` query parameters Splunk Web understands. */
export function searchUrl(spl: string, earliest = "-24h", latest = "now"): string | null {
  const host = getSplunkHost();
  if (!host) return null;
  const q = encodeURIComponent(spl);
  const e = encodeURIComponent(earliest);
  const l = encodeURIComponent(latest);
  return `${host}/en-US/app/search/search?q=${q}&earliest=${e}&latest=${l}`;
}

/** Strip the SPL search-comment block (``` ... ```) from a per-case
 * search.spl file. The remaining body is what you copy-paste into Splunk. */
export function stripSplComments(spl: string): string {
  return spl
    .replace(/```[\s\S]*?```\s*\n?/g, "")
    .replace(/^\s*```\s*$/gm, "")
    .trim();
}
