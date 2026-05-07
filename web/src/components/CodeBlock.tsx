import { useMemo, useState } from "react";

import { tokenizeSpl } from "../lib/splHighlight";

interface Props {
  label: string;
  code: string;
  language?: "spl" | "yaml" | "conf" | "json" | "plain";
}

export default function CodeBlock({ label, code, language }: Props) {
  const [copied, setCopied] = useState(false);
  const inferred = language ?? inferLanguage(label);
  const highlighted = useMemo(
    () => (inferred === "spl" ? <SplCode code={code} /> : <code>{code}</code>),
    [code, inferred],
  );

  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard not available; ignore */
    }
  }

  return (
    <div className="code">
      <div className="code__head">
        <span>{label}</span>
        <button className="code__copy" onClick={copy} type="button">
          {copied ? "copied" : "copy"}
        </button>
      </div>
      <pre>{highlighted}</pre>
    </div>
  );
}

function inferLanguage(label: string): Props["language"] {
  const lower = label.toLowerCase();
  if (lower.includes(".spl") || lower.includes("spl") || lower.includes("search")) return "spl";
  if (lower.includes(".yml") || lower.includes(".yaml") || lower.includes("sigma")) return "yaml";
  if (lower.includes(".conf") || lower.includes("macros") || lower.includes("savedsearches")) return "conf";
  if (lower.includes(".json")) return "json";
  return "plain";
}

function SplCode({ code }: { code: string }) {
  const tokens = useMemo(() => tokenizeSpl(code), [code]);
  return (
    <code>
      {tokens.map((t, i) => (
        <span key={i} className={`spl-tok spl-tok--${t.kind}`}>
          {t.value}
        </span>
      ))}
    </code>
  );
}
