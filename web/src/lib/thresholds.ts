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
  detect_rmm_tool_use: [
    { key: "min_distinct_rmm_domains", label: "min distinct RMM domains", hint: "1 = any RMM domain fires it; raise for noisier environments", default: 1, min: 1, max: 10, step: 1 },
    { key: "window_seconds", label: "window (s)", hint: "Larger window groups bursty resolutions together", default: 300, min: 60, max: 3600, step: 60 },
  ],
  detect_volumetric_flood: [
    { key: "min_connections", label: "min conns / second", hint: "Lower → catches smaller floods, more FPs", default: 100, min: 10, max: 1000, step: 10 },
    { key: "window_seconds", label: "window (s)", hint: "Smaller = tighter pps definition", default: 1, min: 1, max: 60, step: 1 },
  ],
  detect_suricata_exploits: [
    { key: "min_alerts", label: "min Suricata alerts", hint: "1 = any single alert fires; raise to require sustained activity", default: 1, min: 1, max: 50, step: 1 },
    { key: "window_seconds", label: "window (s)", hint: "Larger groups multi-stage attacks together", default: 300, min: 60, max: 3600, step: 60 },
  ],
  detect_c2_exfil: [
    { key: "min_exfil_total_bytes", label: "min total uplink bytes", hint: "Lower → catches drip-style exfil, more FPs", default: 100_000, min: 10_000, max: 10_000_000, step: 10_000, format: (v) => `${(v / 1_000).toFixed(0)} KB` },
    { key: "min_exfil_orig_bytes_per_record", label: "min per-record uplink", hint: "Lower → catches smaller chunks, more FPs", default: 10_000, min: 1_000, max: 1_000_000, step: 1_000, format: (v) => `${(v / 1_000).toFixed(0)} KB` },
    { key: "min_beacon_connections", label: "min beacon conns", hint: "Beacon prerequisite — looser than the standalone rule", default: 30, min: 5, max: 200, step: 1 },
  ],
  detect_cloud_exfil: [
    { key: "min_total_orig_bytes", label: "min total uplink bytes", hint: "Lower → catches smaller staging, more FPs", default: 50_000_000, min: 1_000_000, max: 500_000_000, step: 1_000_000, format: (v) => `${(v / 1_000_000).toFixed(0)} MB` },
    { key: "min_orig_bytes_per_record", label: "min per-record uplink", hint: "Lower → catches smaller per-flow chunks, more FPs", default: 1_000_000, min: 100_000, max: 10_000_000, step: 100_000, format: (v) => `${(v / 1_000_000).toFixed(1)} MB` },
    { key: "window_seconds", label: "window (s)", hint: "Larger window catches drip-style exfil", default: 3600, min: 600, max: 14400, step: 600 },
  ],
  detect_rdp_lateral: [
    { key: "min_distinct_destinations", label: "min distinct internal RDP dests", hint: "Lower → catches narrower pivots, more FPs", default: 3, min: 1, max: 20, step: 1 },
    { key: "window_seconds", label: "window (s)", hint: "Larger window catches slower pivoting", default: 3600, min: 300, max: 14400, step: 300 },
  ],
  detect_web_wordlist: [
    { key: "min_distinct_404_paths", label: "min distinct 404 URI paths", hint: "Lower → catches narrower scans, more FPs", default: 50, min: 10, max: 500, step: 5 },
    { key: "window_seconds", label: "window (s)", hint: "Larger window catches slower scans", default: 60, min: 30, max: 600, step: 30 },
  ],
  detect_internal_proxy: [
    { key: "min_distinct_destinations", label: "min distinct internal pivots", hint: "Lower → catches narrower pivots, more FPs", default: 3, min: 1, max: 20, step: 1 },
    { key: "window_seconds", label: "window (s)", hint: "Larger window catches slower pivoting", default: 3600, min: 300, max: 14400, step: 300 },
  ],
  detect_smb_lateral: [
    { key: "min_distinct_destinations", label: "min distinct internal SMB dests", hint: "Lower → catches narrower pivots, more FPs", default: 3, min: 1, max: 20, step: 1 },
    { key: "window_seconds", label: "window (s)", hint: "Larger window catches slower pivoting", default: 3600, min: 300, max: 14400, step: 300 },
  ],
  detect_lateral_tool_transfer: [
    { key: "min_orig_bytes", label: "min per-record uplink (bytes)", hint: "Lower → catches smaller transfers, more FPs", default: 5_000_000, min: 100_000, max: 100_000_000, step: 100_000, format: (v) => `${(v / 1_000_000).toFixed(1)} MB` },
  ],
  detect_external_remote_services: [
    { key: "min_distinct_destinations", label: "min distinct internal dests", hint: "1 = any external→internal RDP/VPN fires; raise to require pivoting", default: 1, min: 1, max: 20, step: 1 },
    { key: "window_seconds", label: "window (s)", hint: "Larger window groups burst attempts", default: 3600, min: 300, max: 14400, step: 300 },
  ],
  detect_newly_registered_domain: [
    { key: "min_distinct_nrd", label: "min distinct NRD resolutions", hint: "1 = any single NRD lookup fires; raise for high-volume environments", default: 1, min: 1, max: 10, step: 1 },
    { key: "window_seconds", label: "window (s)", hint: "Default 24h matches the typical NRD-feed refresh cadence", default: 86400, min: 3600, max: 604800, step: 3600 },
  ],
  detect_info_repo_bulk_read: [
    { key: "min_distinct_paths", label: "min distinct URI paths", hint: "Lower → catches narrower scrapes, more FPs", default: 100, min: 20, max: 1000, step: 10 },
    { key: "window_seconds", label: "window (s)", hint: "Larger window catches slower scrapes", default: 3600, min: 300, max: 14400, step: 300 },
  ],
  detect_vuln_scan: [
    { key: "min_distinct_signatures", label: "min distinct scanner sigs", hint: "Lower → catches narrower scans, more FPs", default: 5, min: 1, max: 50, step: 1 },
    { key: "window_seconds", label: "window (s)", hint: "Larger window groups multi-stage scans", default: 3600, min: 300, max: 14400, step: 300 },
  ],
  detect_html_smuggling: [
    { key: "window_seconds", label: "window (s)", hint: "Aggregation window for the per-(src, dest) grouping", default: 3600, min: 300, max: 14400, step: 300 },
  ],
  detect_rpc_coercion: [
    { key: "min_distinct_operations", label: "min distinct coercion ops", hint: "1 = any single coercion-shape RPC fires; raise to require multiple ops", default: 1, min: 1, max: 10, step: 1 },
    { key: "window_seconds", label: "window (s)", hint: "Smaller window = tighter (fewer FPs)", default: 600, min: 60, max: 3600, step: 60 },
  ],
};

