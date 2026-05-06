import { Link } from "react-router-dom";

import { dataset } from "../lib/cases";

interface DetectionStyle {
  id: string;
  name: string;
  oneLiner: string;
  description: string;
  pseudoCode: string;
  /** Detector-function names from src/detlab/detector.py that use this style. */
  detectors: string[];
  pros: string[];
  cons: string[];
}

const STYLES: DetectionStyle[] = [
  {
    id: "aggregate-threshold",
    name: "Aggregation + threshold",
    oneLiner: "Group records over a window, count / sum / avg, threshold.",
    description:
      "The workhorse style — most rules in this lab are some shape of this. " +
      "The cost is variance: you have to pick the right grouping key and the " +
      "right threshold, and tune both per environment. The reward is determinism: " +
      "given the same fixture, the rule fires deterministically every time.",
    pseudoCode: `groups = defaultdict(list)
for r in records:
    bucket = floor(r.ts / window_seconds) * window_seconds
    groups[(bucket, r.src, r.base_domain)].append(r)

for (bucket, src, bd), recs in groups.items():
    if len(recs) >= MIN_QUERY_COUNT \\
            and avg(len(label) for r in recs) >= MIN_AVG_SUB_LEN \\
            and avg(entropy(label) for r in recs) >= MIN_AVG_ENTROPY:
        emit_alert(...)`,
    detectors: [
      "detect_dns_tunnel",
      "detect_dns_exfil",
      "detect_port_scan",
      "detect_ssh_brute_force",
      "detect_dga_domains",
      "detect_volumetric_flood",
    ],
    pros: [
      "Easy to reason about — every threshold has an obvious interpretation",
      "Fixtures + ablation tests catch tuning regressions trivially",
      "Composes well — chained detections layer aggregations on top of each other",
    ],
    cons: [
      "Sensitive to time-window alignment — fixtures and tests need bucket-aligned ts",
      "Per-environment tuning is real work; blind defaults produce noise",
    ],
  },
  {
    id: "timing-variance",
    name: "Timing variance / coefficient of variation",
    oneLiner: "stddev(intervals) / mean(intervals) — low CoV = beacon.",
    description:
      "When the signal is *regularity*, not volume. Sliver / Cobalt Strike / " +
      "Empire all default to a metronome cadence; the coefficient of variation " +
      "of inter-connection intervals is a single number that captures it. " +
      "Operators counter with jitter, which trades cadence for hopefully-not-too-much randomness.",
    pseudoCode: `intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
mean = average(intervals)
stddev = standard_deviation(intervals)
cov = stddev / mean

if connection_count >= 30 and cov <= 0.1 and duration >= 600:
    emit_alert(...)`,
    detectors: ["detect_beaconing"],
    pros: [
      "One number expresses the entire signal — easy to explain in a runbook",
      "Catches a wide family of beacons including unfamiliar tools",
    ],
    cons: [
      "Jittered beacons (Sliver --jitter 30) push CoV past 0.1 and dodge the rule",
      "Low-volume / short-lived beacons miss the 30-connection floor",
    ],
  },
  {
    id: "per-record-threshold",
    name: "Per-record threshold",
    oneLiner: "Single-event signal — no aggregation needed.",
    description:
      "Sometimes one row of conn.log is the alert. A 2-hour, 200 MB flow on " +
      "port 443 is a tunnel, full stop. The cheapest detection style — no " +
      "windowing, no group-by, no state. Limited to signals that are " +
      "self-evident at one record's worth of data.",
    pseudoCode: `for r in records:
    if (r.dest_port in COMMON_HTTP_PORTS
            and r.duration >= MIN_DURATION
            and r.orig_bytes + r.resp_bytes >= MIN_BYTES):
        emit_alert(...)`,
    detectors: ["detect_protocol_tunnel"],
    pros: [
      "Stateless — no time-window concerns, no fixture-alignment issues",
      "Trivially fast on streaming data; tstats-friendly",
    ],
    cons: [
      "Most network signal isn't visible at one-record granularity",
      "Hard to tune false-positive rate without breaking the simplicity",
    ],
  },
  {
    id: "ioc-enrichment",
    name: "IOC enrichment via lookup",
    oneLiner: "Match dest IP / domain against a refreshed IOC feed.",
    description:
      "When you have a list of known-bad addresses, the detection collapses " +
      "to 'is this in the list?'. The lab ships three lookup files — " +
      "tor_relays.csv, rmm_domains.csv, cloud_storage_ips.csv — each with a " +
      "synthetic lab set for tests and a production-refresh path documented in " +
      "the case README. The detection's quality is the lookup's quality.",
    pseudoCode: `for r in records:
    service = IOC_LOOKUP.get(r.dest_ip)  # or r.query base_domain
    if not service:
        continue
    # Optional: combine with another signal (volume, count)
    groups[(window, r.src, service)].append(r)

for key, recs in groups.items():
    if len(recs) >= MIN_DISTINCT_HITS:
        emit_alert(matched_service=service, ...)`,
    detectors: [
      "detect_tor_relay_use",
      "detect_rmm_tool_use",
      "detect_cloud_exfil",
    ],
    pros: [
      "High precision when the lookup is well-curated",
      "Easy to distribute / standardise across teams (just ship the .csv)",
      "Pairs naturally with cron-refresh automation (scripts/refresh_tor_relays.py)",
    ],
    cons: [
      "Lookup staleness == silent detection failure",
      "Vendor IPs rotate — IP-based lookups age fast; domain-based age slower",
    ],
  },
  {
    id: "entropy-structure",
    name: "Entropy + structural shape",
    oneLiner: "Shannon entropy of labels / queries / payloads.",
    description:
      "Encoded data looks random (high entropy); English-like text looks " +
      "non-random (low entropy). dnscat2's TXT subdomains are uniformly random " +
      "base32; benign domain labels are mostly word-like. Combined with " +
      "structural gates (label length, qtype, NXDOMAIN fraction), entropy " +
      "becomes a sharp filter.",
    pseudoCode: `def entropy(s):
    counts = Counter(s)
    n = len(s)
    return -sum((c/n) * log2(c/n) for c in counts.values())

# Per (window, src, base_domain) aggregation:
avg_label_entropy = average(entropy(leftmost_label(q)) for q in queries)

if avg_label_entropy >= 3.5 and avg_label_length >= 20:
    emit_alert(...)`,
    detectors: ["detect_dns_tunnel", "detect_dga_domains"],
    pros: [
      "Catches encoding-shape signals that defeat simple keyword rules",
      "Composes well with structural gates (qtype, label length, NXDOMAIN rate)",
    ],
    cons: [
      "Compute cost on hot-path searches — Splunk SPL has no native entropy " +
        "primitive (the lab uses unique-char-count as a cheap proxy)",
      "False positives from CDN tokenisation, DNSBL, antivirus reputation",
    ],
  },
  {
    id: "chained",
    name: "Chained / composed detection",
    oneLiner: "One rule's output becomes another rule's input.",
    description:
      "The most powerful pattern in mature SOC content. detlab's T1041 " +
      "(Exfiltration over C2 Channel) is a chained rule: it joins the beacon " +
      "rule's output with high-orig-bytes records on the same (src, dest) pair. " +
      "Splunk does this idiomatically with `join type=inner` over a subsearch. " +
      "The result is a 'risk accumulation' alert combining behavioural + " +
      "volumetric evidence.",
    pseudoCode: `# Stage 1: cheap behavioural signal
beacons = detect_beaconing(records, max_cov=0.15)  # loose
beacon_pairs = {(b.src, b.dest) for b in beacons}

# Stage 2: high-confidence volume signal among beacon pairs
exfil = defaultdict(int)
for r in records:
    if (r.src, r.dest) not in beacon_pairs:
        continue
    if r.orig_bytes >= 10_000:
        exfil[(r.src, r.dest)] += r.orig_bytes

for pair, total in exfil.items():
    if total >= 100_000:
        emit_alert(severity="critical", evidence=[beacon, total_uplink])`,
    detectors: ["detect_c2_exfil"],
    pros: [
      "Multiplicative precision — combining two medium-confidence signals " +
        "produces a high-confidence alert",
      "Splunk Enterprise Security's risk-based alerting is built around this pattern",
    ],
    cons: [
      "Reasoning gets harder — you have to debug both stages on a false positive",
      "Subsearch performance can hurt; in production, summary indexes help",
    ],
  },
];

function caseTitlesForDetector(detectorFn: string): { id: string; title: string }[] {
  return dataset.cases
    .filter((c) => c.wiring.detector_function === detectorFn)
    .map((c) => ({ id: c.id, title: c.title }));
}

export default function Styles() {
  return (
    <>
      <section className="hero">
        <span className="hero__eyebrow">how detlab thinks · craft</span>
        <h1>Detection styles</h1>
        <p>
          Six recurring patterns that cover every shipped rule in detlab. Knowing
          which style a detection falls under tells you (a) what kind of false
          positive to expect, (b) how to tune it, and (c) which knobs are worth
          exposing in the playground. This page makes the lab's craft explicit
          for anyone reading the code or the dashboards.
        </p>
      </section>

      {STYLES.map((style) => (
        <section key={style.id} className="section-block">
          <div className="section-block__title">
            <h3>{style.name}</h3>
            <span className="muted">{style.oneLiner}</span>
          </div>
          <p>{style.description}</p>

          <div className="code">
            <div className="code__head">
              <span>Pseudocode</span>
            </div>
            <pre>
              <code>{style.pseudoCode}</code>
            </pre>
          </div>

          <div className="style-pros-cons">
            <div className="style-pros-cons__col">
              <h4>Where it shines</h4>
              <ul>
                {style.pros.map((p, i) => (
                  <li key={i}>{p}</li>
                ))}
              </ul>
            </div>
            <div className="style-pros-cons__col">
              <h4>Where it leaks</h4>
              <ul>
                {style.cons.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            </div>
          </div>

          <h4 style={{ marginTop: 18, marginBottom: 8 }}>Cases that use this style</h4>
          <div className="cards">
            {style.detectors.flatMap((fn) => {
              const cases = caseTitlesForDetector(fn);
              if (cases.length === 0) {
                return [
                  <div key={fn} className="card style-detector-card">
                    <code>{fn}</code>
                    <p className="muted" style={{ marginTop: 4 }}>
                      no shipped case yet
                    </p>
                  </div>,
                ];
              }
              return cases.map((c) => (
                <Link
                  key={c.id}
                  to={`/case/${c.id}`}
                  className="card style-detector-card"
                >
                  <h3>{c.title}</h3>
                  <p>
                    <code>{fn}</code>
                  </p>
                </Link>
              ));
            })}
          </div>
        </section>
      ))}

      <section className="section-block">
        <div className="section-block__title">
          <h3>Picking a style for a new case</h3>
        </div>
        <ol>
          <li>
            <strong>Is the signal visible in one record?</strong> →{" "}
            <em>Per-record threshold</em>. Cheapest possible style.
          </li>
          <li>
            <strong>Do you have a known-bad list?</strong> →{" "}
            <em>IOC enrichment</em>. Quality bound by lookup quality.
          </li>
          <li>
            <strong>Is the signal a count / sum / avg over a window?</strong> →{" "}
            <em>Aggregation + threshold</em>. The default for most network rules.
          </li>
          <li>
            <strong>Is the signal regularity?</strong> → <em>Timing variance</em>.
            Specifically beacons.
          </li>
          <li>
            <strong>Is the signal randomness?</strong> →{" "}
            <em>Entropy + structural shape</em>. DNS tunnels, DGAs, encoded payloads.
          </li>
          <li>
            <strong>Need to combine two medium-confidence signals?</strong> →{" "}
            <em>Chained / composed</em>. The way mature SOCs reduce false positives.
          </li>
        </ol>
      </section>
    </>
  );
}
