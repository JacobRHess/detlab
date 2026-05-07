/* Header-level settings popover for the "Open in your Splunk" feature.
 *
 * Renders as an icon button in the site nav. Clicking opens a small
 * controlled-input form for the user's Splunk Web URL; the value lives in
 * localStorage so it persists across sessions but never leaves the browser.
 *
 * Visual feedback:
 *   - cog icon plain when not configured
 *   - cog icon green when a host is set ("you've wired up Splunk")
 */

import { useEffect, useState } from "react";

import { getSplunkHost, setSplunkHost } from "../lib/splunk";

export default function SplunkSettings() {
  const [open, setOpen] = useState(false);
  const [host, setHost] = useState("");
  const [saved, setSaved] = useState("");

  useEffect(() => {
    setSaved(getSplunkHost());
    setHost(getSplunkHost());
  }, [open]);

  function save() {
    setSplunkHost(host);
    setSaved(host.trim().replace(/\/$/, ""));
    setOpen(false);
  }

  function clear() {
    setSplunkHost("");
    setSaved("");
    setHost("");
  }

  const isConfigured = saved.length > 0;

  return (
    <div className="splunk-settings">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className={`splunk-settings__btn ${isConfigured ? "splunk-settings__btn--on" : ""}`}
        title={isConfigured ? `Splunk: ${saved}` : "Open in your Splunk — click to configure"}
        aria-label="Splunk settings"
        aria-expanded={open}
      >
        ⚙ Splunk
      </button>
      {open && (
        <div className="splunk-settings__pop" role="dialog" aria-label="Splunk host configuration">
          <div className="splunk-settings__head">Open in your Splunk</div>
          <p className="splunk-settings__hint">
            Once you set your Splunk Web URL, every dashboard link and SPL preview
            on this site becomes clickable to <em>your</em> Splunk. Saved in your
            browser only — nothing leaves the page.
          </p>
          <label className="splunk-settings__label">
            <span>Splunk Web URL</span>
            <input
              type="url"
              placeholder="https://splunk.example.com:8000"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              autoFocus
            />
          </label>
          <div className="splunk-settings__actions">
            {saved && (
              <button type="button" className="btn" onClick={clear}>
                clear
              </button>
            )}
            <button type="button" className="btn btn--primary" onClick={save}>
              save
            </button>
          </div>
          {saved && (
            <div className="splunk-settings__current">
              currently: <code>{saved}</code>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
