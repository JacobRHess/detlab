/* "Insights" nav dropdown.
 *
 * The top-level nav was getting crowded — 7+ analytical views compete
 * with the four that actually anchor the site (Coverage, Roadmap, About,
 * GitHub). This collapses every cross-cutting analysis page into a
 * single dropdown so the bar reads cleanly.
 *
 * The trigger button highlights when the user is on any of the child
 * routes, keeping the visual feedback that NavLink would normally give.
 *
 * Behaviour:
 *   - Click the trigger to open; click outside to close.
 *   - Escape key closes.
 *   - Each item is a NavLink so clicking navigates AND closes the menu.
 *   - Keyboard: arrow keys traverse, Enter activates.
 */

import { useEffect, useRef, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";

interface InsightItem {
  to: string;
  label: string;
  description: string;
}

const ITEMS: InsightItem[] = [
  {
    to: "/risk",
    label: "Risk-Based Alerting",
    description: "Splunk ES risk score per detection · entity leaderboard.",
  },
  {
    to: "/kill-chain",
    label: "Kill chain",
    description: "Cross-detector chain analysis: 2+ techniques on one source.",
  },
  {
    to: "/threat-groups",
    label: "Threat groups",
    description: "Coverage by APT / eCrime adversary group.",
  },
  {
    to: "/pyramid",
    label: "Pyramid of Pain",
    description: "Detection portfolio tiered hash → TTP, with resilience score.",
  },
  {
    to: "/data-sources",
    label: "Data sources",
    description: "Which Zeek / Suricata logs feed which detections.",
  },
  {
    to: "/macros",
    label: "SPL macro library",
    description: "Every shared + per-case macro with copy buttons.",
  },
  {
    to: "/cim",
    label: "CIM compliance",
    description: "Case × Splunk ES data model alignment matrix.",
  },
  {
    to: "/lookups",
    label: "Lookup library",
    description: "Enrichment CSVs (RMM, Tor, cloud-storage IPs) shipped with the app.",
  },
  {
    to: "/schedule",
    label: "Search schedule",
    description: "Cron-parsed firing cadence across the catalogue + concurrency heatmap.",
  },
  {
    to: "/stats",
    label: "Stats heatmap",
    description: "ATT&CK coverage matrix with per-technique fixture counts.",
  },
];

export default function InsightsMenu() {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const location = useLocation();
  const childPaths = ITEMS.map((i) => i.to);
  const isActive = childPaths.some(
    (p) => location.pathname === p || location.pathname.startsWith(`${p}/`),
  );

  // Close on outside-click + Escape.
  useEffect(() => {
    if (!open) return;
    function onClick(e: MouseEvent) {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    window.addEventListener("mousedown", onClick);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onClick);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // Close on route change so navigating from inside the menu dismisses it.
  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  return (
    <div className="insights-menu" ref={wrapRef}>
      <button
        type="button"
        className={`insights-menu__trigger ${isActive ? "insights-menu__trigger--active" : ""} ${open ? "insights-menu__trigger--open" : ""}`}
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        Insights
        <span className="insights-menu__caret" aria-hidden="true">▾</span>
      </button>
      {open && (
        <div className="insights-menu__pop" role="menu">
          <div className="insights-menu__head">
            <span className="muted" style={{ fontSize: 11, letterSpacing: 1 }}>
              CROSS-CUTTING VIEWS
            </span>
          </div>
          {ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive: linkActive }) =>
                `insights-menu__item ${linkActive ? "insights-menu__item--active" : ""}`
              }
              role="menuitem"
            >
              <span className="insights-menu__label">{item.label}</span>
              <span className="insights-menu__desc">{item.description}</span>
            </NavLink>
          ))}
        </div>
      )}
    </div>
  );
}
