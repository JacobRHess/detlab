import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import CodeBlock from "../components/CodeBlock";
import DetectorPlayground from "../components/DetectorPlayground";
import FixtureViewer from "../components/FixtureViewer";
import Markdown from "../components/Markdown";
import { getCase, tacticLabel } from "../lib/cases";

type Tab = "attack" | "detection" | "fixtures" | "playground" | "spec";

const TABS: { id: Tab; label: string }[] = [
  { id: "attack", label: "Attack" },
  { id: "detection", label: "Detection" },
  { id: "fixtures", label: "Fixtures" },
  { id: "playground", label: "Try it" },
  { id: "spec", label: "Spec" },
];

export default function CaseDetail() {
  const { caseId } = useParams();
  const c = getCase(caseId);
  const [tab, setTab] = useState<Tab>("playground");

  if (!c) {
    return (
      <div className="empty-state">
        <p>Unknown case: <code>{caseId}</code>.</p>
        <p>
          <Link to="/">← Back to coverage</Link>
        </p>
      </div>
    );
  }

  return (
    <article>
      <div className="case-header">
        <div className="case-header__crumbs">
          <Link to="/">Coverage</Link> &nbsp;/&nbsp;{tacticLabel(c.mitre_tactic)}
        </div>
        <h1>{c.title}</h1>
        <div className="case-header__meta">
          <code>{c.mitre_technique}</code>
          <span className={`badge badge--${c.severity}`}>{c.severity}</span>
          <span className="badge badge--shipped">shipped</span>
          <a href={c.mitre_url} target="_blank" rel="noreferrer">attack.mitre.org ↗</a>
          <a
            href={`https://github.com/JacobRHess/detlab/tree/main/cases/${c.id}`}
            target="_blank"
            rel="noreferrer"
          >
            source ↗
          </a>
        </div>
      </div>

      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={`tab ${tab === t.id ? "tab--active" : ""}`}
            onClick={() => setTab(t.id)}
            type="button"
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "playground" && (
        <>
          <DetectorPlayground c={c} />
          <p className="muted" style={{ fontSize: 13 }}>
            Pyodide downloads ~8&nbsp;MB on first run, then caches. The runtime imports
            <code> detlab.detector</code> and calls <code>{c.wiring.detector_function}</code> on
            the records you paste above. CI runs the exact same function on the exact same
            fixtures.
          </p>
        </>
      )}

      {tab === "attack" && (
        <>
          {c.attack_md ? <Markdown>{c.attack_md}</Markdown> : <p className="muted">No attack reproduction notes.</p>}
        </>
      )}

      {tab === "detection" && (
        <>
          <CodeBlock label="search.spl — canonical detection" code={c.detection.spl} />
          <CodeBlock label="macros.conf — production macro" code={c.detection.macros_conf} />
          <CodeBlock label="sigma.yml — cross-platform reference" code={c.detection.sigma_yaml} />
          {c.detection.savedsearches_conf && (
            <CodeBlock label="savedsearches.conf — schedule + alert action" code={c.detection.savedsearches_conf} />
          )}
        </>
      )}

      {tab === "fixtures" && (
        <>
          <p className="muted">
            Trimmed Zeek log fixtures. Positive fixtures fire the detection in CI; negative fixtures must stay silent.
          </p>
          <h3>Positive</h3>
          <FixtureViewer label="positive" fixture={c.fixtures.positive} />
          <h3>Negative</h3>
          <FixtureViewer label="negative" fixture={c.fixtures.negative} />
        </>
      )}

      {tab === "spec" && <Markdown>{c.readme_md}</Markdown>}
    </article>
  );
}
