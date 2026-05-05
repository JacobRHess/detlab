import { useState } from "react";

interface Props {
  label: string;
  code: string;
  language?: string;
}

export default function CodeBlock({ label, code }: Props) {
  const [copied, setCopied] = useState(false);

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
      <pre>
        <code>{code}</code>
      </pre>
    </div>
  );
}
