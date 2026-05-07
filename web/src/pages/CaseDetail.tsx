import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import CodeBlock from "../components/CodeBlock";
import DetectorPlayground from "../components/DetectorPlayground";
import FixtureStats from "../components/FixtureStats";
import FixtureViewer from "../components/FixtureViewer";
import Markdown from "../components/Markdown";
import PipelineDiagram from "../components/PipelineDiagram";
import RunInSplunk from "../components/RunInSplunk";
import { CaseFull, getCase, loadCase, tacticLabel } from "../lib/cases";

type Tab = "attack" | "how" | "detection" | "fixtures" | "playground" | "spec" | "splunk";

const TABS: { id: Tab; label: string }[] = [
  { id: "playground", label: "Try it" },
  { id: "how", label: "How it works" },
  { id: "splunk", label: "Run in Splunk" },
  { id: "attack", label: "Attack" },
  { id: "detection", label: "Detection" },
  { id: "fixtures", label: "Fixtures" },
  { id: "spec", label: "Spec" },
];

type LoadState =
  | { status: "loading" }
  | { status: "loaded"; data: CaseFull }
  | { status: "error"; error: string };

export default function CaseDetail() {
  const { caseId } = useParams();
  const summary = getCase(caseId);
  const [tab, setTab] = useState<Tab>("playground");
  const [load, setLoad] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    if (!caseId) return;
    let cancelled = false;
    setLoad({ status: "loading" });
    loadCase(caseId)
      .then((c) => {
        if (cancelled) return;
        if (!c) {
          setLoad({ status: "error", error: `not found: ${caseId}` });
          return;
        }
        setLoad({ status: "loaded", data: c });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setLoad({ status: "error", error: err instanceof Error ? err.message : String(err) });
      });
    return () => {
      cancelled = true;
    };
  }, [caseId]);

  if (!summary) {
    return (
      <div className="empty-state">
        <p>
          Unknown case: <code>{caseId}</code>.
        </p>
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
          <Link to="/">Coverage</Link> &nbsp;/&nbsp;{tacticLabel(summary.mitre_tactic)}
        </div>
        <h1>{summary.title}</h1>
        <div className="case-header__meta">
          <code>{summary.mitre_technique}</code>
          <span className={`badge badge--${summary.severity}`}>{summary.severity}</span>
          <span className="badge badge--shipped">shipped</span>
          <a href={summary.mitre_url} target="_blank" rel="noreferrer">
            attack.mitre.org ↗
          </a>
          <a
            href={`https://github.com/JacobRHess/detlab/tree/main/cases/${summary.id}`}
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

      {load.status === "loaded" && load.data.references.length > 0 && (
        <ReferencesBar refs={load.data.references} />
      )}

      {load.status === "loading" && <CaseLoading />}
      {load.status === "error" && (
        <div className="empty-state">
          <p>Failed to load case data: {load.error}</p>
        </div>
      )}
      {load.status === "loaded" && <CaseTabs tab={tab} c={load.data} />}
    </article>
  );
}

/** Show the case's sigma.yml `references:` block as a horizontal pill bar
 * under the case header. Each reference is a clickable link, with the
 * domain rendered prominently and the path muted. Catches DFIR Report
 * incidents, ATT&CK group pages, vendor docs — the "where this comes from"
 * context that anchors the case in the real world. */
function ReferencesBar({ refs }: { refs: string[] }) {
  return (
    <div className="references-bar">
      <span className="references-bar__label">References</span>
      <div className="references-bar__pills">
        {refs.map((url) => {
          let host = "";
          let path = "";
          try {
            const u = new URL(url);
            host = u.hostname.replace(/^www\./, "");
            path = (u.pathname + u.search).replace(/\/$/, "") || "/";
          } catch {
            host = url;
          }
          return (
            <a
              key={url}
              href={url}
              target="_blank"
              rel="noreferrer"
              className="references-bar__pill"
              title={url}
            >
              <span className="references-bar__host">{host}</span>
              {path && path !== "/" && (
                <span className="references-bar__path">{path}</span>
              )}
            </a>
          );
        })}
      </div>
    </div>
  );
}

function CaseLoading() {
  return (
    <div className="empty-state" aria-busy="true">
      <p className="muted">Loading case detail…</p>
    </div>
  );
}

function CaseTabs({ tab, c }: { tab: Tab; c: CaseFull }) {
  return (
    <>
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

      {tab === "attack" &&
        (c.attack_md ? (
          <Markdown>{c.attack_md}</Markdown>
        ) : (
          <p className="muted">No attack reproduction notes.</p>
        ))}

      {tab === "detection" && (
        <>
          <CodeBlock label="search.spl — canonical detection" code={c.detection.spl} />
          <CodeBlock label="macros.conf — production macro" code={c.detection.macros_conf} />
          <CodeBlock label="sigma.yml — cross-platform reference" code={c.detection.sigma_yaml} />
          {c.detection.savedsearches_conf && (
            <CodeBlock
              label="savedsearches.conf — schedule + alert action"
              code={c.detection.savedsearches_conf}
            />
          )}
        </>
      )}

      {tab === "how" && (
        <>
          {c.wiring.detector_function && (
            <>
              <h3 style={{ marginTop: 4 }}>Pipeline</h3>
              <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
                What the detector does on every record set, top to bottom.
              </p>
              <PipelineDiagram detectorFunction={c.wiring.detector_function} />
            </>
          )}
          <h3>What you'd see in real data</h3>
          <p className="muted" style={{ fontSize: 13 }}>
            The fixture below is synthetic — the byte-level shape exactly mirrors what
            Zeek emits in the lab.
          </p>
          <FixtureStats c={c} />
        </>
      )}

      {tab === "fixtures" && (
        <>
          <p className="muted">
            Trimmed Zeek log fixtures. Positive fixtures fire the detection in CI; negative
            fixtures must stay silent.
          </p>
          <h3>Positive</h3>
          <FixtureViewer label="positive" fixture={c.fixtures.positive} />
          <h3>Negative</h3>
          <FixtureViewer label="negative" fixture={c.fixtures.negative} />
        </>
      )}

      {tab === "splunk" && <RunInSplunk c={c} />}

      {tab === "spec" && <Markdown>{c.readme_md}</Markdown>}
    </>
  );
}
