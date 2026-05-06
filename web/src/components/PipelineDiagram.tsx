/* Per-detector pipeline diagram. The exact steps depend on which detector
   the case wires up; we map detector_function -> a small ordered list of
   steps that mirrors the SPL/Python logic. Educational, not generated. */

interface Step {
  num: number;
  title: string;
  detail: string;
}

const PIPELINES: Record<string, Step[]> = {
  detect_dns_tunnel: [
    { num: 1, title: "Read Zeek dns.log", detail: "JSON-lines records emitted by the lab sensor" },
    { num: 2, title: "Bucket by 5-min window", detail: "floor(ts / 300) * 300" },
    { num: 3, title: "Group by (src, base_domain)", detail: "split query, take last two labels" },
    { num: 4, title: "Aggregate", detail: "count, dc(query), avg sub_len, avg entropy, qtypes" },
    { num: 5, title: "Threshold", detail: ">=50 queries, >=20 chars, >=3.5 bits, >=30 unique, suspicious qtype" },
  ],
  detect_beaconing: [
    { num: 1, title: "Read conn/http.log", detail: "Zeek connection summaries" },
    { num: 2, title: "Group by (src, dest)", detail: "host header preferred, else id.resp_h" },
    { num: 3, title: "Compute intervals", detail: "consecutive timestamps -> deltas" },
    { num: 4, title: "Coefficient of variation", detail: "stddev(intervals) / mean(intervals)" },
    { num: 5, title: "Threshold", detail: "CoV <= 0.1, count >= 30, duration >= 600s" },
  ],
  detect_port_scan: [
    { num: 1, title: "Read conn.log", detail: "all TCP connection summaries" },
    { num: 2, title: "Bucket by 60-s window", detail: "tight enough to catch nmap default rate" },
    { num: 3, title: "Group by (src, dest)", detail: "one source touching one host" },
    { num: 4, title: "Aggregate", detail: "dc(dest_port), count, fraction with conn_state in S0/REJ/RST*" },
    { num: 5, title: "Threshold", detail: ">=100 distinct ports, >=70% incomplete handshakes" },
  ],
  detect_protocol_tunnel: [
    { num: 1, title: "Read conn.log", detail: "per-record, no aggregation needed" },
    { num: 2, title: "Filter by port", detail: "id.resp_p in {80, 443, 8080, 8443}" },
    { num: 3, title: "Compute total_bytes", detail: "orig_bytes + resp_bytes" },
    { num: 4, title: "Threshold", detail: "duration >= 600 s and total_bytes >= 10 MB" },
    { num: 5, title: "Emit alert", detail: "single conn.log record carries all fields" },
  ],
  detect_tor_relay_use: [
    { num: 1, title: "Read conn.log", detail: "Zeek connection summaries" },
    { num: 2, title: "Enrich with lookup", detail: "match id.resp_h against tor_relays.csv" },
    { num: 3, title: "Bucket by 1-h window", detail: "Tor circuits rebuild every ~10 min" },
    { num: 4, title: "Group by src", detail: "count distinct relay IPs per source" },
    { num: 5, title: "Threshold", detail: ">= 3 distinct relays touched in window" },
  ],
  detect_dns_exfil: [
    { num: 1, title: "Read dns.log", detail: "all DNS queries, qtype-agnostic" },
    { num: 2, title: "Bucket by 60-s window", detail: "tight enough to catch a burst" },
    { num: 3, title: "Group by (src, base_domain)", detail: "where bytes are heading" },
    { num: 4, title: "Sum subdomain bytes", detail: "len of leftmost label per query" },
    { num: 5, title: "Threshold", detail: ">=30 queries, >=30 KB total, >=50 char avg label" },
  ],
  detect_ssh_brute_force: [
    { num: 1, title: "Read conn.log", detail: "filter to id.resp_p = 22" },
    { num: 2, title: "Bucket by 60-s window", detail: "hydra hits ~16/s by default" },
    { num: 3, title: "Group by (src, dest)", detail: "one attacker attacking one host" },
    { num: 4, title: "Aggregate", detail: "count, avg(duration), SF fraction" },
    { num: 5, title: "Threshold", detail: ">=20 attempts and avg duration <= 5 s" },
  ],
  detect_dga_domains: [
    { num: 1, title: "Read dns.log", detail: "all queries, regardless of rcode" },
    { num: 2, title: "Bucket by 5-min window", detail: "DGA families fire bursts" },
    { num: 3, title: "Group by src", detail: "single host iterating its day's domains" },
    { num: 4, title: "Per-domain entropy", detail: "Shannon entropy of second-level label" },
    { num: 5, title: "Threshold", detail: ">=30 distinct domains, avg entropy >=3.3, >=50% NXDOMAIN" },
  ],
};

interface Props {
  detectorFunction: string;
}

export default function PipelineDiagram({ detectorFunction }: Props) {
  const steps = PIPELINES[detectorFunction];
  if (!steps) return null;
  return (
    <div className="pipeline" aria-label={`${detectorFunction} pipeline`}>
      {steps.map((s) => (
        <div className="pipeline__step" key={s.num}>
          <div className="pipeline__step-num">Step {s.num}</div>
          <div className="pipeline__step-title">{s.title}</div>
          <div className="pipeline__step-detail">{s.detail}</div>
        </div>
      ))}
    </div>
  );
}
