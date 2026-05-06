import { Fixture } from "../lib/cases";

interface Props {
  label: string;
  fixture: Fixture | null;
}

const PREVIEW_LINES = 6;

export default function FixtureViewer({ label, fixture }: Props) {
  if (!fixture) {
    return <div className="fixture muted">No {label} fixture.</div>;
  }
  const lines = fixture.content.split("\n");
  const preview = lines.slice(0, PREVIEW_LINES).join("\n");
  const remaining = Math.max(0, fixture.line_count - PREVIEW_LINES);

  return (
    <div className="fixture">
      <div className="fixture__head">
        <span className="fixture__title">{fixture.filename}</span>
        <span className="muted">
          {fixture.line_count} record{fixture.line_count === 1 ? "" : "s"}
        </span>
      </div>
      <div className="fixture__body">{preview}</div>
      {remaining > 0 && (
        <div className="fixture__head" style={{ borderTop: "1px solid var(--border)", borderBottom: "none" }}>
          <span className="dim">… {remaining} more line{remaining === 1 ? "" : "s"} not shown</span>
        </div>
      )}
    </div>
  );
}
