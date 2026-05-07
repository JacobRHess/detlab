/* Minimal SPL (Splunk Search Processing Language) tokenizer.
 *
 * Goal: render the SPL CodeBlocks on /case/* and /macros with
 * meaningful colour (commands distinct from functions distinct from
 * macros distinct from strings) without pulling in a full syntax
 * library. The token vocabulary covers the SPL idioms detlab actually
 * uses — adding more is just adding entries to KEYWORDS / FUNCTIONS.
 */

export type SplTokenKind =
  | "keyword"
  | "function"
  | "macro"
  | "string"
  | "comment"
  | "number"
  | "operator"
  | "field"
  | "plain";

export interface SplToken {
  kind: SplTokenKind;
  value: string;
}

const KEYWORDS = new Set([
  "search", "where", "stats", "eval", "rename", "table", "fields", "fillnull",
  "lookup", "inputlookup", "outputlookup", "rex", "regex", "spath", "extract",
  "sort", "head", "tail", "dedup", "uniq", "join", "append", "appendcols",
  "transaction", "bin", "bucket", "timechart", "chart", "geom", "geostats",
  "iplocation", "tstats", "datamodel", "from", "by", "as", "AS", "BY",
  "case", "if", "true", "false", "null", "AND", "OR", "NOT", "and", "or", "not",
  "earliest", "latest", "index", "sourcetype", "source", "host", "addinfo",
  "format", "delta", "streamstats", "eventstats", "untable", "xyseries",
  "convert", "tojson", "fromjson", "makemv", "mvexpand", "mvfilter",
  "anomalydetection", "predict", "abstract", "diff",
]);

const FUNCTIONS = new Set([
  "count", "dc", "values", "list", "sum", "avg", "min", "max", "stdev", "stdevp",
  "var", "varp", "mean", "median", "mode", "perc", "p50", "p90", "p95", "p99",
  "earliest_time", "latest_time", "len", "length", "lower", "upper",
  "substr", "split", "trim", "ltrim", "rtrim", "replace", "round", "floor",
  "ceiling", "abs", "exp", "log", "pow", "sqrt", "if", "case", "coalesce",
  "isnull", "isnotnull", "match", "in", "like", "searchmatch", "nullif",
  "tonumber", "tostring", "strftime", "strptime", "now", "relative_time",
  "printf", "sigfig", "validate",
]);

// Order matters — pick longer patterns first.
const COMMENT_BLOCK = /^```[\s\S]*?```/;
const STRING_DOUBLE = /^"(?:\\.|[^"\\])*"/;
const STRING_SINGLE = /^'(?:\\.|[^'\\])*'/;
const MACRO_CALL = /^`[a-zA-Z_][\w]*`/;
const NUMBER = /^\d+(?:\.\d+)?[smhd]?\b/;
const FIELD = /^[a-zA-Z_][\w.]*/; // identifiers (incl dotted Zeek style)
const OPERATOR = /^(?:\|=|>=|<=|==|!=|=|<|>|\|)/;
const WHITESPACE = /^\s+/;

export function tokenizeSpl(input: string): SplToken[] {
  const tokens: SplToken[] = [];
  let pos = 0;
  while (pos < input.length) {
    const rest = input.slice(pos);

    if (rest.startsWith("```")) {
      const m = COMMENT_BLOCK.exec(rest);
      if (m) {
        tokens.push({ kind: "comment", value: m[0] });
        pos += m[0].length;
        continue;
      }
    }

    const ws = WHITESPACE.exec(rest);
    if (ws) {
      tokens.push({ kind: "plain", value: ws[0] });
      pos += ws[0].length;
      continue;
    }

    const m1 = STRING_DOUBLE.exec(rest);
    if (m1) {
      tokens.push({ kind: "string", value: m1[0] });
      pos += m1[0].length;
      continue;
    }
    const m2 = STRING_SINGLE.exec(rest);
    if (m2) {
      tokens.push({ kind: "string", value: m2[0] });
      pos += m2[0].length;
      continue;
    }

    const m3 = MACRO_CALL.exec(rest);
    if (m3) {
      tokens.push({ kind: "macro", value: m3[0] });
      pos += m3[0].length;
      continue;
    }

    const m4 = NUMBER.exec(rest);
    if (m4) {
      tokens.push({ kind: "number", value: m4[0] });
      pos += m4[0].length;
      continue;
    }

    const m5 = OPERATOR.exec(rest);
    if (m5) {
      tokens.push({ kind: "operator", value: m5[0] });
      pos += m5[0].length;
      continue;
    }

    const m6 = FIELD.exec(rest);
    if (m6) {
      const word = m6[0];
      let kind: SplTokenKind;
      if (KEYWORDS.has(word)) kind = "keyword";
      else if (FUNCTIONS.has(word)) kind = "function";
      else kind = "field";
      tokens.push({ kind, value: word });
      pos += word.length;
      continue;
    }

    // Unknown char — emit verbatim and keep scanning so we never spin.
    tokens.push({ kind: "plain", value: rest[0] });
    pos += 1;
  }
  return tokens;
}
