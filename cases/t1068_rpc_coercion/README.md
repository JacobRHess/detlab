# T1068 — RPC coercion (PetitPotam, DFSCoerce)

**Tactic:** Privilege Escalation
**Technique:** [T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
**Tools simulated:** PetitPotam, DFSCoerce, Coercer, ntlmrelayx

## What the attacker does

Forces a Windows host (often a domain controller) to authenticate to an attacker-controlled relay via specific RPC calls (EfsRpcOpenFileRaw, NetrDfsAddStdRoot). The relay then signs into another service as the coerced machine account, often the domain controller — instant domain takeover.

## What the defender sees in Zeek / Suricata

Zeek dce_rpc.log records whose `operation` field is in the coercion set {EfsRpcOpenFileRaw, EfsRpcDecryptFileSrv, NetrDfsAddStdRoot, NetrDfsRemoveStdRoot}. Per (10-min window, src, dest), even one match from a non-DC source is high-confidence.

## Detection logic

| Field | Threshold |
|---|---|
| `RPC operation` | in coercion set |
    | `source` | non-DC (allowlist DC IPs) |
    | `distinct ops per (src, dest, window)` | ≥ 1 |

The Python detector
(`src/detlab/detector.py:detect_rpc_coercion`) is the testable spec; the SPL macro
in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `rpc_coercion` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES integration
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_dce_rpc.log`](tests/positive_dce_rpc.log) — synthetic positive fixture
- [`tests/negative_dce_rpc.log`](tests/negative_dce_rpc.log) — synthetic negative fixture
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Domain controllers replicating to each other — allowlist DC↔DC pairs
- Backup software using EFSRPC for shadow-copy enumeration
- Internal pen-test / red-team engagements

## Tuning knobs

| Knob | Effect |
|---|---|
| `coercion_ops` | Add new operations as coercion research evolves |
    | `window_seconds` | Smaller → tighter (fewer FPs), larger → catches drip-style |
