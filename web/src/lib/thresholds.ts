/* Threshold knobs exposed by each detector. The web playground renders a
   slider per knob; the Pyodide call passes them as kwargs.

   Source of truth: the keyword args of detlab.detector.<fn>. Keep this file
   in sync when detector signatures change — there's no automation. */

export interface ThresholdKnob {
  /** Python kwarg name. */
  key: string;
  /** Display label. */
  label: string;
  /** One-line explanation that shows under the slider. */
  hint: string;
  /** Default value (matches the Python default). */
  default: number;
  /** Slider min and max. */
  min: number;
  max: number;
  /** Granularity. */
  step: number;
  /** Optional formatter for the displayed value. */
  format?: (v: number) => string;
}

export const DETECTOR_THRESHOLDS: Record<string, ThresholdKnob[]> = {
  detect_dns_tunnel: [
    { key: "min_query_count", label: "min queries / window", hint: "Lower → catches slower beacons, more FPs", default: 50, min: 5, max: 200, step: 1 },
    { key: "min_avg_sub_len", label: "min avg subdomain length", hint: "Lower → catches short labels, more FPs", default: 20, min: 5, max: 60, step: 1 },
    { key: "min_avg_entropy", label: "min avg entropy (bits/char)", hint: "Lower → catches non-random encoding, more FPs", default: 3.5, min: 1.0, max: 5.0, step: 0.1, format: (v) => v.toFixed(1) },
    { key: "min_unique_queries", label: "min unique queries", hint: "Lower → catches repetitive payloads, more FPs", default: 30, min: 5, max: 200, step: 1 },
  ],
  detect_beaconing: [
    { key: "min_connections", label: "min connections", hint: "Lower → catches shorter sessions, more FPs", default: 30, min: 5, max: 200, step: 1 },
    { key: "max_avg_interval", label: "max avg interval (s)", hint: "Higher → catches very slow beacons", default: 600, min: 30, max: 3600, step: 30 },
    { key: "max_coefficient_of_variation", label: "max CoV (stddev/mean)", hint: "Higher → catches jittered beacons, more FPs", default: 0.1, min: 0.0, max: 1.0, step: 0.01, format: (v) => v.toFixed(2) },
    { key: "min_duration_seconds", label: "min duration (s)", hint: "Higher → fewer FPs, slower to alert", default: 600, min: 60, max: 7200, step: 60 },
  ],
  detect_port_scan: [
    { key: "min_distinct_ports", label: "min distinct dest ports", hint: "Lower → catches stealthy scans, more FPs", default: 100, min: 10, max: 500, step: 5 },
    { key: "min_incomplete_fraction", label: "min incomplete fraction", hint: "Lower → catches connect-scans (full handshake), more FPs", default: 0.7, min: 0.0, max: 1.0, step: 0.05, format: (v) => v.toFixed(2) },
    { key: "window_seconds", label: "window (s)", hint: "Larger → catches slow scans, slower to alert", default: 60, min: 10, max: 600, step: 10 },
  ],
  detect_protocol_tunnel: [
    { key: "min_duration_seconds", label: "min duration (s)", hint: "Lower → catches shorter tunnels, more FPs", default: 600, min: 60, max: 7200, step: 60 },
    { key: "min_total_bytes", label: "min total bytes", hint: "Lower → catches low-throughput interactive tunnels, more FPs", default: 10_000_000, min: 100_000, max: 100_000_000, step: 100_000, format: (v) => `${(v / 1_000_000).toFixed(1)} MB` },
  ],
  detect_tor_relay_use: [
    { key: "min_distinct_relays", label: "min distinct relays", hint: "Lower → catches casual Tor users, more FPs", default: 3, min: 1, max: 20, step: 1 },
    { key: "window_seconds", label: "window (s)", hint: "Larger → catches very slow clients", default: 3600, min: 60, max: 14400, step: 60 },
  ],
  detect_dns_exfil: [
    { key: "min_query_count", label: "min queries / window", hint: "Lower → catches slower exfil, more FPs", default: 30, min: 5, max: 500, step: 1 },
    { key: "min_total_subdomain_bytes", label: "min total subdomain bytes", hint: "Lower → catches slower exfil, more FPs", default: 30_000, min: 1_000, max: 500_000, step: 1_000, format: (v) => `${(v / 1_000).toFixed(0)} KB` },
    { key: "min_avg_sub_len", label: "min avg label length", hint: "Lower → catches shorter-label tools, more FPs", default: 50, min: 10, max: 63, step: 1 },
  ],
  detect_ssh_brute_force: [
    { key: "min_attempts", label: "min attempts", hint: "Lower → catches stealthy slow brute force, more FPs", default: 20, min: 5, max: 200, step: 1 },
    { key: "max_avg_duration_seconds", label: "max avg duration (s)", hint: "Higher → catches 'patient' tools, more FPs", default: 5, min: 0.5, max: 60, step: 0.5, format: (v) => `${v.toFixed(1)} s` },
  ],
  detect_dga_domains: [
    { key: "min_distinct_domains", label: "min distinct base domains", hint: "Lower → catches small DGA bursts, more FPs", default: 30, min: 5, max: 500, step: 1 },
    { key: "min_avg_entropy", label: "min avg entropy (bits/char)", hint: "Lower → catches less-random DGAs, more FPs", default: 3.3, min: 1.0, max: 5.0, step: 0.1, format: (v) => v.toFixed(1) },
    { key: "min_nxdomain_fraction", label: "min NXDOMAIN fraction", hint: "Lower → catches DGAs whose operator registers many, more FPs", default: 0.5, min: 0.0, max: 1.0, step: 0.05, format: (v) => v.toFixed(2) },
  ],
};

