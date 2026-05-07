"""Per-case rich metadata — single source of truth for the build scripts.

`scripts/build_app.py` and `scripts/build_web_data.py` both import this
module so the data flows into:

  * the Splunk app's `detlab_cases.csv` lookup (risk_score, risk_object,
    pyramid_tier columns)
  * the per-case `risk` modifier inside `savedsearches.conf`
  * the web portfolio's case JSON (everything else: triage, threat groups,
    data sources, pyramid_tier)

Layered metadata (kept in code instead of CSV / YAML):
  - **risk_score, risk_object** — Splunk ES Risk-Based Alerting framework.
    risk_score follows the standard SOC 0-100 scale where 100 is critical.
    risk_object_type is one of "system" (host/IP), "user", or "other".
  - **pyramid_tier** — David Bianco's Pyramid of Pain (1=hash, 2=ip,
    3=domain, 4=network/host artifact, 5=tool, 6=TTP). Higher = harder
    for an adversary to evade.
  - **data_sources** — primary telemetry sources the rule consumes
    (zeek_dns, zeek_conn, zeek_http, zeek_ssl, zeek_smb, zeek_dce_rpc,
    suricata_alert, threat_intel).
  - **threat_groups** — adversary groups known to use this technique in
    the wild. Sourced from MITRE ATT&CK group pages + DFIR Report
    intrusion writeups.
  - **triage** — what an analyst does when this fires:
      * steps: ordered triage actions
      * false_positives: common benign causes worth checking
      * containment: response actions if confirmed malicious
"""

from __future__ import annotations

CASE_METADATA: dict[str, dict] = {
    # ============================================================
    # Reconnaissance / Discovery
    # ============================================================
    "t1046_network_service_discovery": {
        "risk_score": 50,
        "risk_object_type": "system",
        "pyramid_tier": 5,
        "data_sources": ["zeek_conn"],
        "threat_groups": ["FIN7", "APT29", "Conti", "BlackCat"],
        "triage": {
            "steps": [
                "Verify the source IP is internal — external scans are noise unless from a high-value subnet.",
                "Check if the source is an authorised vuln scanner (Nessus, Qualys, internal pentest box).",
                "Pivot to dns.log + http.log on the same src to look for follow-on enumeration.",
                "Check authentication logs on the most-touched destinations for failed logins.",
            ],
            "false_positives": [
                "Authorised vulnerability scanners (compare src against your scanner allowlist).",
                "Network monitoring tools (Nagios, SolarWinds) doing periodic port checks.",
                "Vendor uptime probes hitting public-facing ports.",
            ],
            "containment": [
                "Block the src at the perimeter / segment firewall if external.",
                "Quarantine the host via EDR if internal and unsanctioned.",
                "Open a SOC ticket; pivot to credential-access / lateral-movement detections on same src.",
            ],
        },
    },
    "t1595_002_vuln_scanning": {
        "risk_score": 40,
        "risk_object_type": "system",
        "pyramid_tier": 5,
        "data_sources": ["suricata_alert"],
        "threat_groups": ["APT41", "FIN11", "Sandworm"],
        "triage": {
            "steps": [
                "Inspect the Suricata signature IDs to identify the scanner family (Acunetix, Nikto, sqlmap, etc.).",
                "Confirm the source is external — if internal, escalate immediately.",
                "Check whether any signatures resulted in 200/302 responses (successful scan vs blocked).",
                "Pivot to web logs and look for follow-on exploitation attempts.",
            ],
            "false_positives": [
                "Internal authorised vulnerability scanners.",
                "Bug-bounty researchers (compare src against bug-bounty platform IP lists).",
                "Search-engine crawlers triggering broad signatures (Googlebot, BingBot).",
            ],
            "containment": [
                "Block the src at the WAF / perimeter.",
                "Increase WAF sensitivity for the targeted application.",
                "Notify the application owner; request a vuln scan of the targeted endpoint.",
            ],
        },
    },
    "t1595_003_web_wordlist": {
        "risk_score": 35,
        "risk_object_type": "system",
        "pyramid_tier": 5,
        "data_sources": ["zeek_http"],
        "threat_groups": ["LAPSUS$", "FIN7", "APT41"],
        "triage": {
            "steps": [
                "Sample the 404 paths — wordlist scanners hit predictable directories (/admin, /wp-login, /.env).",
                "Check if any 200/301/302 responses appeared in the same window — those are the hits the attacker found.",
                "Identify the User-Agent: dirbuster, gobuster, ffuf, feroxbuster have telltale defaults.",
                "Pivot to detect_suricata_exploits to see if a follow-on exploit fired.",
            ],
            "false_positives": [
                "Search-engine crawlers exploring deprecated paths.",
                "Broken application links generating 404 sprays from internal users.",
                "Security-tool scheduled scans against your own webapp.",
            ],
            "containment": [
                "Block the src IP at the WAF.",
                "Add rate-limiting on 404 responses.",
                "Audit the targeted webapp's exposed paths against a recent inventory.",
            ],
        },
    },
    "t1583_001_nrd_resolution": {
        "risk_score": 30,
        "risk_object_type": "system",
        "pyramid_tier": 3,
        "data_sources": ["zeek_dns", "threat_intel"],
        "threat_groups": ["APT29", "Cobalt Strike operators", "BlackCat"],
        "triage": {
            "steps": [
                "Cross-check the resolved domain against threat intel (VirusTotal, urlscan).",
                "Look at the WHOIS registration date — minutes-old domains are higher confidence.",
                "Check process telemetry on the resolving host (which process opened the socket).",
                "Check for follow-on beaconing or exfil patterns from the same src.",
            ],
            "false_positives": [
                "CDN edge nodes and ad-tech domains rotated frequently.",
                "Marketing-campaign domains registered the same day.",
                "Shortener services (bit.ly, t.co) and link unfurlers.",
            ],
            "containment": [
                "Sinkhole the domain at internal DNS.",
                "Add the domain to the blocklist on egress proxy / firewall.",
                "Quarantine the resolving host pending forensic review.",
            ],
        },
    },
    # ============================================================
    # Initial access
    # ============================================================
    "t1190_suricata_exploit": {
        "risk_score": 80,
        "risk_object_type": "system",
        "pyramid_tier": 4,
        "data_sources": ["suricata_alert"],
        "threat_groups": ["APT41", "Sandworm", "Volt Typhoon", "Lazarus"],
        "triage": {
            "steps": [
                "Inspect the Suricata signature payload for CVE references — confirm exploit vs scanner heuristic.",
                "Check the response side: did the exploited service return 200 or an error code?",
                "Pivot to host EDR for post-exploit child-process activity.",
                "Snapshot the targeted asset for forensic preservation.",
            ],
            "false_positives": [
                "Internal authorised pentest exercises.",
                "Vulnerability scanners that send proof-of-concept payloads.",
                "Outdated Suricata rule with high FP rate (review SID over last 30 days).",
            ],
            "containment": [
                "Isolate the targeted host from production network.",
                "Patch or virtual-patch the targeted service.",
                "Open IR ticket with Sev1 if exploit succeeded.",
            ],
        },
    },
    # ============================================================
    # Execution
    # ============================================================
    "t1027_006_html_smuggling": {
        "risk_score": 70,
        "risk_object_type": "user",
        "pyramid_tier": 5,
        "data_sources": ["zeek_http", "suricata_alert"],
        "threat_groups": ["NOBELIUM/APT29", "Qakbot operators", "BumbleBee"],
        "triage": {
            "steps": [
                "Identify the user that downloaded the smuggled blob (resolve src → user via DHCP/AD).",
                "Pull the HTTP response body if available — check for base64-decoded EXE/ZIP signatures.",
                "Check EDR for any subsequent process execution from the user's Downloads directory.",
                "Search proxy logs for the staging domain across the org.",
            ],
            "false_positives": [
                "Legitimate vendor portals that ship installers via JS-based download (rare but exists).",
                "QR-code generators or graphic-export tools using base64 inline data.",
                "Internal tools shipping signed payloads via XHR.",
            ],
            "containment": [
                "Block the staging domain at egress proxy.",
                "Reset the user's credentials (HTML smuggling often follows credential phish).",
                "Trigger EDR scan of the user's endpoint.",
            ],
        },
    },
    # ============================================================
    # Persistence
    # ============================================================
    "t1133_external_remote": {
        "risk_score": 75,
        "risk_object_type": "user",
        "pyramid_tier": 5,
        "data_sources": ["zeek_conn"],
        "threat_groups": ["BlackCat", "Conti", "LockBit", "FIN7"],
        "triage": {
            "steps": [
                "Identify the authenticating account on the external-remote service (VPN, RDP, Citrix).",
                "Check for impossible-travel relative to recent geolocation history.",
                "Review whether MFA was used; if not, escalate.",
                "Pivot to detect_rdp_lateral / detect_smb_lateral on internal systems the account touched.",
            ],
            "false_positives": [
                "Legitimate remote employees newly travelling to a different country.",
                "Vendor accounts with documented external access.",
                "Penetration test engagement using authorised credentials.",
            ],
            "containment": [
                "Force MFA re-prompt or session revocation for the account.",
                "Disable the account if compromise confirmed.",
                "Audit recent activity for the account across all production systems.",
            ],
        },
    },
    # ============================================================
    # Privilege escalation
    # ============================================================
    "t1068_rpc_coercion": {
        "risk_score": 90,
        "risk_object_type": "system",
        "pyramid_tier": 6,
        "data_sources": ["zeek_dce_rpc"],
        "threat_groups": ["Conti", "LockBit", "BlackCat", "FIN7"],
        "triage": {
            "steps": [
                "Confirm the destination is a Domain Controller — coercion against DCs is the high-impact case.",
                "Check whether the relayed authentication succeeded (EventID 4624 / 4769 on DCs).",
                "Search for ntlmrelayx tooling indicators on the source host.",
                "Audit any AD CS certificate templates the relay might have abused.",
            ],
            "false_positives": [
                "Legitimate distributed file system replication (DFS-R) jobs.",
                "Vendor tools that legitimately invoke EFSRPC operations (rare).",
            ],
            "containment": [
                "Block SMB/RPC from the source host immediately.",
                "Disable Web Enrollment on AD CS if exploited path was AD CS relay.",
                "Reset the targeted machine account credentials.",
                "Open a Sev1 IR ticket — privilege escalation in AD is critical.",
            ],
        },
    },
    # ============================================================
    # Credential access
    # ============================================================
    "t1110_001_ssh_brute_force": {
        "risk_score": 50,
        "risk_object_type": "system",
        "pyramid_tier": 4,
        "data_sources": ["zeek_conn"],
        "threat_groups": ["Mirai operators", "Outlaw", "TeamTNT"],
        "triage": {
            "steps": [
                "Check whether any attempts succeeded (auth.log / SSH server logs).",
                "If success, pivot to detect_lateral_tool_transfer + detect_smb_lateral on the target.",
                "Identify whether the targeted account exists; non-existent accounts = noise scan.",
                "Geo-locate the source IP — distinguish opportunistic from targeted.",
            ],
            "false_positives": [
                "Misconfigured automation re-trying with stale credentials.",
                "User locking themselves out and retrying repeatedly.",
                "Internet-exposed jump host attracting opportunistic scanners.",
            ],
            "containment": [
                "Add the source IP to the SSH-deny list / fail2ban.",
                "Move the SSH service off port 22 if internet-exposed.",
                "Enforce key-only authentication; disable password auth.",
            ],
        },
    },
    # ============================================================
    # Discovery / Lateral movement
    # ============================================================
    "t1021_001_rdp_lateral": {
        "risk_score": 75,
        "risk_object_type": "user",
        "pyramid_tier": 5,
        "data_sources": ["zeek_conn"],
        "threat_groups": ["Conti", "BlackCat", "FIN7", "Wizard Spider"],
        "triage": {
            "steps": [
                "Identify the source account driving the RDP fan-out.",
                "Compare destination hosts touched against the user's normal access pattern.",
                "Check Windows EventID 4624 LogonType=10 on each destination.",
                "Pivot to detect_lateral_tool_transfer on the same src/dest pairs.",
            ],
            "false_positives": [
                "IT helpdesk staff doing batch troubleshooting (resolve via known-IT-account list).",
                "Patch-deployment tooling using RDP for verification.",
                "RMM tools chained through internal RDP for support.",
            ],
            "containment": [
                "Disable the user account; force credential reset.",
                "Snapshot all touched destinations for forensic preservation.",
                "Hunt for persistence on each destination (scheduled tasks, services).",
            ],
        },
    },
    "t1021_002_smb_lateral": {
        "risk_score": 80,
        "risk_object_type": "user",
        "pyramid_tier": 5,
        "data_sources": ["zeek_conn", "zeek_smb"],
        "threat_groups": ["Conti", "Ryuk", "BlackCat", "Lazarus"],
        "triage": {
            "steps": [
                "Identify whether ADMIN$ or C$ shares were touched (psexec/wmiexec signature).",
                "Check Windows Service Control Manager events on destinations (EventID 7045 — service install).",
                "Pivot to lateral_tool_transfer to find the dropped binary.",
                "Identify the source account driving the fan-out.",
            ],
            "false_positives": [
                "Group Policy refresh workflows (MS GP processes).",
                "Vulnerability scanners using SMB credentialed scans.",
                "Backup software touching admin shares for VSS jobs.",
            ],
            "containment": [
                "Disable the source user/service account immediately.",
                "Block SMB between the source and reachable hosts at the segment firewall.",
                "Run EDR scan on every touched destination.",
            ],
        },
    },
    "t1570_lateral_tool_transfer": {
        "risk_score": 75,
        "risk_object_type": "system",
        "pyramid_tier": 5,
        "data_sources": ["zeek_conn"],
        "threat_groups": ["Conti", "LockBit", "BlackCat"],
        "triage": {
            "steps": [
                "Identify the file size / hash if Zeek captured the file extraction.",
                "Check whether the source has shipped tools to multiple destinations (chain analysis).",
                "Pivot to the destination's EDR for execution telemetry.",
                "Search for the file hash against known offensive tool repositories (Mythic, Cobalt Strike).",
            ],
            "false_positives": [
                "Software-deployment tools (SCCM, BigFix) pushing legitimate packages.",
                "Backup software replicating large files between hosts.",
                "Image-deployment workflows during VM/container provisioning.",
            ],
            "containment": [
                "Quarantine both source and destination hosts.",
                "Hash-block the dropped binary in EDR.",
                "Open IR ticket; lateral tool transfer often immediately precedes ransomware.",
            ],
        },
    },
    # ============================================================
    # Defense evasion
    # ============================================================
    "t1090_001_internal_proxy": {
        "risk_score": 65,
        "risk_object_type": "system",
        "pyramid_tier": 5,
        "data_sources": ["zeek_conn"],
        "threat_groups": ["APT29", "Cobalt Strike operators", "Volt Typhoon"],
        "triage": {
            "steps": [
                "Identify the source host running the proxy and the destinations it's pivoting to.",
                "Pull EDR for the proxy process on the source (chisel, ngrok, frp, ssh -D).",
                "Check whether destination accesses look like reconnaissance vs targeted services.",
                "Pivot to detect_protocol_tunnel on the same src.",
            ],
            "false_positives": [
                "Legitimate developer tunneling for local-dev access.",
                "Vendor support sessions using ngrok with documented approval.",
                "DevOps tools using SSH local-port-forwards.",
            ],
            "containment": [
                "Kill the proxy process via EDR.",
                "Block the upstream proxy destination at egress.",
                "Audit egress firewall rules to prevent unauthorised tunneling.",
            ],
        },
    },
    # ============================================================
    # Collection
    # ============================================================
    "t1213_002_info_repo_bulk": {
        "risk_score": 60,
        "risk_object_type": "user",
        "pyramid_tier": 5,
        "data_sources": ["zeek_http"],
        "threat_groups": ["LAPSUS$", "APT29", "Insider threats"],
        "triage": {
            "steps": [
                "Identify the user account driving the bulk read.",
                "Compare the page-access pattern against normal user behaviour.",
                "Check whether the user has attempted similar bulk reads on other repos (SharePoint, Confluence, GitHub).",
                "Snapshot DLP events for the same user.",
            ],
            "false_positives": [
                "Internal search-indexer bots (Confluence has its own; SharePoint Search).",
                "Audit / compliance tools doing periodic full-content review.",
                "Migration tools during repo consolidation projects.",
            ],
            "containment": [
                "Suspend the user's session token.",
                "Audit all data the user accessed in the previous 7 days.",
                "Notify Legal/Compliance if sensitive content was accessed.",
            ],
        },
    },
    # ============================================================
    # Command and control
    # ============================================================
    "t1071_001_http_beacon_sliver": {
        "risk_score": 80,
        "risk_object_type": "system",
        "pyramid_tier": 6,
        "data_sources": ["zeek_conn", "zeek_http"],
        "threat_groups": ["FIN7", "APT29", "BlackCat", "Wizard Spider"],
        "triage": {
            "steps": [
                "Identify the upstream C2 IP/domain and check threat intel.",
                "Pull EDR for the beaconing process on the source host.",
                "Compute the beacon interval and jitter — confirm the periodicity reported by the rule.",
                "Check whether other hosts beacon to the same upstream (campaign breadth).",
            ],
            "false_positives": [
                "Telemetry agents (DataDog, Splunk UF) with regular check-ins.",
                "Software-update clients polling for new versions.",
                "Heartbeat/health-check daemons inside SaaS connectors.",
            ],
            "containment": [
                "Block the C2 IP/domain at egress.",
                "Quarantine the source host via EDR.",
                "Hash-block the beaconing binary across the org.",
            ],
        },
    },
    "t1071_004_dns_c2_dnscat2": {
        "risk_score": 80,
        "risk_object_type": "system",
        "pyramid_tier": 6,
        "data_sources": ["zeek_dns"],
        "threat_groups": ["APT34", "MuddyWater", "Cobalt Strike operators"],
        "triage": {
            "steps": [
                "Identify the base domain hosting the tunnel; check WHOIS + threat intel.",
                "Pull EDR on the source for DNS-tunneling tools (dnscat2, iodine, dns2tcp).",
                "Sample the queried subdomains — confirm they look base32/base64-encoded.",
                "Check for follow-on data movement on the same src.",
            ],
            "false_positives": [
                "DNSSEC validators that emit large TXT queries during validation.",
                "Anti-spam DNSBLs that produce high-volume DNS lookups.",
                "Some CDN health-check probes use long subdomain labels.",
            ],
            "containment": [
                "Sinkhole the C2 base domain at internal DNS.",
                "Block the recursive resolver from forwarding to that NS.",
                "Quarantine the source host.",
            ],
        },
    },
    "t1568_002_dga_c2": {
        "risk_score": 70,
        "risk_object_type": "system",
        "pyramid_tier": 6,
        "data_sources": ["zeek_dns"],
        "threat_groups": ["TrickBot operators", "Qakbot", "Emotet"],
        "triage": {
            "steps": [
                "Sample the queried domains — confirm randomness (3-5 chars, no English vocab).",
                "Check NXDOMAIN ratio reported by the alert.",
                "Pull EDR for the resolving process on the source.",
                "Check threat intel for known DGA seed lists matching the family.",
            ],
            "false_positives": [
                "CDN edge-node DNS rotations (Akamai, Fastly).",
                "Some anti-fraud tooling that resolves randomized canary domains.",
                "Browser DNS prefetch on user-typed misspellings.",
            ],
            "containment": [
                "Sinkhole the resolving DNS suffix if a pattern is identifiable.",
                "Quarantine the source host pending malware analysis.",
                "Hash-block the resolving binary.",
            ],
        },
    },
    "t1572_protocol_tunneling_chisel": {
        "risk_score": 75,
        "risk_object_type": "system",
        "pyramid_tier": 5,
        "data_sources": ["zeek_conn"],
        "threat_groups": ["Volt Typhoon", "APT41", "Cobalt Strike operators"],
        "triage": {
            "steps": [
                "Identify the upstream destination IP — confirm whether it's a known cloud-VPS provider.",
                "Pull EDR on the source host for chisel/frp/ngrok process indicators.",
                "Measure the byte-volume profile — bursty interactive vs steady-state SSH-style.",
                "Check egress firewall logs for related connections (multi-port tunneling).",
            ],
            "false_positives": [
                "Legitimate developers using SSH tunneling for local-dev port forwarding.",
                "VPN clients using HTTPS encapsulation for restrictive networks.",
                "WebSocket-based collab tools (Slack, Notion realtime channels).",
            ],
            "containment": [
                "Kill the tunneling process via EDR.",
                "Block the upstream destination IP/range at egress.",
                "Audit egress proxy bypass list — chisel needs unrestricted HTTPS.",
            ],
        },
    },
    "t1090_003_tor_relay_use": {
        "risk_score": 70,
        "risk_object_type": "system",
        "pyramid_tier": 3,
        "data_sources": ["zeek_conn", "threat_intel"],
        "threat_groups": ["LockBit", "Hive", "Vice Society"],
        "triage": {
            "steps": [
                "Identify the source host and the user logged in at the connection time.",
                "Pull EDR for Tor browser / orbot process indicators.",
                "Check whether the user has historically used Tor (legitimate research / privacy).",
                "Pivot to detect_c2_exfil + detect_dns_tunnel for additional indicators.",
            ],
            "false_positives": [
                "Security researchers performing OSINT through Tor.",
                "Journalists / privacy-conscious users (acceptable in some orgs).",
                "Tor-based research tools (e.g., academic darkweb monitoring).",
            ],
            "containment": [
                "Block the Tor relay-list IPs at egress (refresh daily).",
                "Talk to the user before disabling — Tor isn't always malicious.",
                "Quarantine the source if combined with other detections.",
            ],
        },
    },
    "t1219_rmm_tool_use": {
        "risk_score": 65,
        "risk_object_type": "system",
        "pyramid_tier": 4,
        "data_sources": ["zeek_dns", "threat_intel"],
        "threat_groups": ["BlackCat", "Akira", "Conti", "FIN7"],
        "triage": {
            "steps": [
                "Identify the RMM domain (AnyDesk, ScreenConnect, Atera, TeamViewer, etc.).",
                "Cross-check against your sanctioned-RMM list.",
                "Pull EDR on the source for the RMM client binary.",
                "Identify the user logged in at the connection time.",
            ],
            "false_positives": [
                "IT department legitimately deploying or testing a sanctioned RMM.",
                "Vendor support sessions using RMM with prior approval.",
                "Acquired companies still using legacy RMM tools.",
            ],
            "containment": [
                "Block the RMM domain at egress.",
                "Uninstall the RMM client via EDR.",
                "Notify the user and verify whether the install was authorised.",
            ],
        },
    },
    # ============================================================
    # Exfiltration
    # ============================================================
    "t1041_exfil_over_c2": {
        "risk_score": 95,
        "risk_object_type": "system",
        "pyramid_tier": 6,
        "data_sources": ["zeek_conn", "zeek_http"],
        "threat_groups": ["BlackCat", "Conti", "LockBit", "FIN7"],
        "triage": {
            "steps": [
                "Sum the exfiltrated byte volume — quantify data loss for IR.",
                "Identify the C2 destination; check threat intel for staging server attribution.",
                "Pull DLP / EDR for the source host's recently accessed files.",
                "Open Sev1 IR; this is data theft in progress.",
            ],
            "false_positives": [
                "Backup software exfiltrating to a misconfigured offsite endpoint.",
                "Legitimate cloud-sync clients with permissions misconfigured.",
            ],
            "containment": [
                "Sever egress from the source host immediately.",
                "Snapshot the source for forensic preservation.",
                "Notify Legal/Privacy team — likely breach notification trigger.",
            ],
        },
    },
    "t1048_003_dns_exfil": {
        "risk_score": 75,
        "risk_object_type": "system",
        "pyramid_tier": 5,
        "data_sources": ["zeek_dns"],
        "threat_groups": ["APT41", "OilRig/APT34", "FIN7"],
        "triage": {
            "steps": [
                "Quantify the cumulative data volume (subdomain bytes × queries).",
                "Identify the receiving authoritative nameserver.",
                "Pull EDR for the resolving process on the source.",
                "Compare with detect_dns_tunnel — DNS exfil and DNS C2 often coexist.",
            ],
            "false_positives": [
                "Some marketing analytics SDKs encode large data in DNS labels.",
                "DNS-based ad-tech beacons.",
                "Anti-bot solutions with long DNS-encoded fingerprints.",
            ],
            "containment": [
                "Sinkhole the receiving NS at internal DNS.",
                "Quarantine the source host.",
                "Trigger DLP scan over recently accessed sensitive content.",
            ],
        },
    },
    "t1567_002_cloud_exfil": {
        "risk_score": 90,
        "risk_object_type": "system",
        "pyramid_tier": 4,
        "data_sources": ["zeek_conn", "threat_intel"],
        "threat_groups": ["BlackCat", "Akira", "FIN7", "LAPSUS$"],
        "triage": {
            "steps": [
                "Identify the cloud-storage destination (S3, R2, MEGA, Dropbox).",
                "Sum the uplink byte volume — this is the data-loss estimate.",
                "Check whether the source host has DLP-classified data on disk.",
                "Identify the user logged in at the connection time.",
            ],
            "false_positives": [
                "Approved cloud-backup tools with documented destinations.",
                "Marketing teams uploading large media to sanctioned cloud apps.",
                "Developer workflows pushing artifacts to S3 / GCS for legitimate releases.",
            ],
            "containment": [
                "Block the cloud-storage destination at egress.",
                "Sever egress from the source host.",
                "Open IR ticket; preserve forensic image.",
                "Notify Legal — breach-notification timeline starts here.",
            ],
        },
    },
    # ============================================================
    # Impact
    # ============================================================
    "t1499_001_volumetric_flood": {
        "risk_score": 85,
        "risk_object_type": "system",
        "pyramid_tier": 2,
        "data_sources": ["zeek_conn"],
        "threat_groups": ["Mirai operators", "Anonymous-affiliated", "KillNet"],
        "triage": {
            "steps": [
                "Identify whether the flood is inbound (DDoS against us) or outbound (we are the source).",
                "If outbound, locate the source host — likely a botnet member.",
                "Engage the upstream provider / DDoS-mitigation vendor.",
                "Check whether the targeted service is degraded (latency / error-rate dashboards).",
            ],
            "false_positives": [
                "Load-test tooling running against the wrong target.",
                "CDN cache-invalidation events triggering high pps internally.",
            ],
            "containment": [
                "Engage upstream DDoS scrubbing.",
                "Rate-limit the source IP at the edge.",
                "If outbound, isolate the source host (likely compromised).",
            ],
        },
    },
}


# Stable list of all pyramid tiers with their David-Bianco labels.
# Used by the web Pyramid of Pain page and the data-quality validator.
PYRAMID_TIERS: dict[int, dict[str, str]] = {
    1: {
        "label": "Hash values",
        "color": "#4caf50",
        "description": "Trivial to evade — adversary recompiles or repacks.",
    },
    2: {
        "label": "IP addresses",
        "color": "#7cb342",
        "description": "Cheap to rotate — adversary spins up a new VPS.",
    },
    3: {
        "label": "Domain names",
        "color": "#f8be34",
        "description": "Annoying to change — needs new registration / DNS.",
    },
    4: {
        "label": "Network/host artifacts",
        "color": "#fb8c00",
        "description": "Requires tooling change — User-Agents, registry keys, named pipes.",
    },
    5: {
        "label": "Tools",
        "color": "#e64a19",
        "description": "Forces toolchain rewrite — Cobalt Strike → Sliver → custom.",
    },
    6: {
        "label": "Tactics, Techniques, Procedures",
        "color": "#dc4e41",
        "description": "Hardest to evade — demands a fundamentally different operating model.",
    },
}


# Stable list of all data sources used by the cases. Used by the web
# Data Sources page to organize the visualization.
DATA_SOURCES: dict[str, dict[str, str]] = {
    "zeek_dns": {
        "label": "Zeek dns.log",
        "category": "DNS",
        "description": "Every DNS query/response observed on the wire.",
    },
    "zeek_conn": {
        "label": "Zeek conn.log",
        "category": "Flow",
        "description": "Every TCP/UDP connection summary (5-tuple + bytes + duration).",
    },
    "zeek_http": {
        "label": "Zeek http.log",
        "category": "Application",
        "description": "Every HTTP request/response with method, URI, status, UA.",
    },
    "zeek_ssl": {
        "label": "Zeek ssl.log",
        "category": "Application",
        "description": "Every TLS handshake with JA3, SNI, cert details.",
    },
    "zeek_smb": {
        "label": "Zeek smb_*.log",
        "category": "Application",
        "description": "SMB file access, named-pipe operations, share access.",
    },
    "zeek_dce_rpc": {
        "label": "Zeek dce_rpc.log",
        "category": "Application",
        "description": "DCE/RPC operations including the high-value EFSRPC / DFS coercion ops.",
    },
    "suricata_alert": {
        "label": "Suricata eve.json",
        "category": "IDS",
        "description": "Signature-based alerts from Emerging Threats, ETPRO, ETOpen.",
    },
    "threat_intel": {
        "label": "Threat-intel lookup",
        "category": "Enrichment",
        "description": "Static / refreshable lookups (RMM domains, NRD feed, Tor relays, cloud-storage IPs).",
    },
}


# Splunk CIM data model registry. Drives the /cim compliance page —
# every case maps to one or more of these models, and the required-field
# matrix tells the viewer which ES data-model accelerations a given
# detection participates in.
#
# Required-field lists are abbreviated to the ES-relevant set; the full
# CIM specs at https://docs.splunk.com/Documentation/CIM include more.
CIM_DATA_MODELS: dict[str, dict] = {
    "Network_Traffic": {
        "label": "Network Traffic",
        "description": "Connection-level flow data — TCP/UDP 5-tuples, byte counts, durations.",
        "color": "#5cc8ff",
        "required_fields": ["src", "src_port", "dest", "dest_port", "transport", "bytes", "action"],
    },
    "Network_Resolution": {
        "label": "Network Resolution (DNS)",
        "description": "DNS queries and responses — query, query_type, reply_code, answers.",
        "color": "#7cd6ff",
        "required_fields": ["src", "dest", "query", "query_type", "reply_code", "message_type"],
    },
    "Web": {
        "label": "Web",
        "description": "HTTP / HTTPS request-response pairs.",
        "color": "#f8be34",
        "required_fields": ["src", "dest", "uri_path", "uri_query", "http_method", "status", "http_user_agent"],
    },
    "Authentication": {
        "label": "Authentication",
        "description": "Successful and failed login events across SSH / RDP / SMB.",
        "color": "#fb8c00",
        "required_fields": ["src", "dest", "user", "action", "app", "authentication_method"],
    },
    "Intrusion_Detection": {
        "label": "Intrusion Detection",
        "description": "Signature-based IDS alerts (Suricata, Snort).",
        "color": "#dc4e41",
        "required_fields": ["src", "dest", "category", "signature", "signature_id", "severity", "vendor_action"],
    },
}


# Per-case CIM data model alignment. Drives the /cim compliance page.
# Source of truth: each case's macros.conf composition + savedsearches
# alert action. Most detections map to 1 model; Web detections that also
# emit conn-level facts get both Network_Traffic and Web.
CIM_CASE_MAPPING: dict[str, list[str]] = {
    "t1021_001_rdp_lateral":         ["Network_Traffic"],
    "t1021_002_smb_lateral":         ["Network_Traffic", "Authentication"],
    "t1027_006_html_smuggling":      ["Web", "Intrusion_Detection"],
    "t1041_exfil_over_c2":           ["Network_Traffic"],
    "t1046_network_service_discovery": ["Network_Traffic"],
    "t1048_003_dns_exfil":           ["Network_Resolution"],
    "t1068_rpc_coercion":            ["Network_Traffic", "Authentication"],
    "t1071_001_http_beacon_sliver":  ["Network_Traffic", "Web"],
    "t1071_004_dns_c2_dnscat2":      ["Network_Resolution"],
    "t1090_001_internal_proxy":      ["Network_Traffic"],
    "t1090_003_tor_relay_use":       ["Network_Traffic"],
    "t1110_001_ssh_brute_force":     ["Network_Traffic", "Authentication"],
    "t1133_external_remote":         ["Network_Traffic", "Authentication"],
    "t1190_suricata_exploit":        ["Intrusion_Detection"],
    "t1213_002_info_repo_bulk":      ["Web"],
    "t1219_rmm_tool_use":            ["Network_Resolution"],
    "t1499_001_volumetric_flood":    ["Network_Traffic"],
    "t1567_002_cloud_exfil":         ["Network_Traffic"],
    "t1568_002_dga_c2":              ["Network_Resolution"],
    "t1570_lateral_tool_transfer":   ["Network_Traffic"],
    "t1572_protocol_tunneling_chisel": ["Network_Traffic"],
    "t1583_001_nrd_resolution":      ["Network_Resolution"],
    "t1595_002_vuln_scanning":       ["Intrusion_Detection"],
    "t1595_003_web_wordlist":        ["Web"],
}


# Lookup-table catalogue. Each entry describes one CSV under
# app/lookups/ — what it contains, how it should be refreshed, and which
# detections rely on it. The /lookups page fans this out into a UI that
# also pulls live row counts from the actual files at build time.
LOOKUPS: dict[str, dict] = {
    "rmm_domains.csv": {
        "label": "RMM domains",
        "description": "Sanctioned and unsanctioned remote-management tool DNS suffixes (AnyDesk, ScreenConnect, TeamViewer, Atera, etc.). Used by detect_rmm_tool_use to spot remote-control tool installs.",
        "refresh_cadence": "monthly — track new RMM SaaS launches",
        "used_by": ["t1219_rmm_tool_use"],
    },
    "tor_relays.csv": {
        "label": "Tor relays",
        "description": "Public-relay IPs published by the Tor directory authorities. Used by detect_tor_relay_use to spot connections to multi-hop anonymization.",
        "refresh_cadence": "daily — directory consensus rotates",
        "used_by": ["t1090_003_tor_relay_use"],
    },
    "cloud_storage_ips.csv": {
        "label": "Cloud-storage IP ranges",
        "description": "IP ranges of major object-storage and file-transfer providers (AWS S3, Cloudflare R2, MEGA, Dropbox, GCS, Azure Blob). Used by detect_cloud_exfil to spot bulk uplinks.",
        "refresh_cadence": "weekly — providers publish ranges",
        "used_by": ["t1567_002_cloud_exfil"],
    },
    "detlab_cases.csv": {
        "label": "Cases (auto-generated)",
        "description": "Generated by scripts/build_app.py from each case's macros.conf eval block + scripts/case_metadata.py. Powers all dashboards, the RBA risk_score join, and the SOC pivot workflow_actions.",
        "refresh_cadence": "build-time — never edit by hand",
        "used_by": ["all dashboards", "all workflow_actions"],
    },
}
