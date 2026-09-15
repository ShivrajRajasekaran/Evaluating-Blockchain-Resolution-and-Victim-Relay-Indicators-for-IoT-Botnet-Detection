<!-- GENERATED FILE — do not edit by hand.
     Source of truth: src/schema/columns.py
     Regenerate:      python -m src.reports.generate_docs -->

# Feature catalogue & IoT-23 availability

> Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT Botnet Detection.

## Feature catalogue

16 features across 4 groups. Unit of analysis: one device over one 300-second window. Ranges are enforced by the validator; a value outside them is a schema error, not a clamp.

| Feature | Group | Role | IoT-23 | Lab-only | Binary | Range |
| --- | --- | --- | --- | --- | --- | --- |
| `ens_query_rate` | resolution | NOVEL — on trial | unavailable (NaN) | — | — | [0, ∞] |
| `rpc_endpoint_ratio` | resolution | NOVEL — on trial | proxy (flagged) | — | — | [0, 1] |
| `resolution_entropy` | resolution | NOVEL — on trial | unavailable (NaN) | — | — | [0, 8] |
| `serverlist_pull` | resolution | NOVEL — on trial | unavailable (NaN) | — | yes | [0, 1] |
| `bidir_flow_duration` | relay | NOVEL — on trial | computable | — | — | [0, ∞] |
| `flow_fanout` | relay | NOVEL — on trial | computable | — | — | [0, ∞] |
| `upnp_addportmapping` | relay | NOVEL — on trial | unavailable (NaN) | — | yes | [0, 1] |
| `updownlink_ratio` | relay | NOVEL — on trial | computable | — | — | [0, 5] |
| `login_burst_count` | infection | base — comparison | proxy (flagged) | — | — | [0, ∞] |
| `scan_rate` | infection | base — comparison | computable | — | — | [0, ∞] |
| `distinct_dst_ports` | infection | base — comparison | computable | — | — | [0, ∞] |
| `failed_conn_ratio` | infection | base — comparison | computable | — | — | [0, 1] |
| `beacon_interval` | payload | base — comparison | computable | — | — | [0, ∞] |
| `beacon_jitter` | payload | base — comparison | computable | — | — | [0, ∞] |
| `rc4_string_score` | payload | base — comparison | unavailable (NaN) | yes | — | [0, 1] |
| `mean_pkt_size` | payload | base — comparison | computable | — | — | [40, 1500] |

## IoT-23 feature availability (Track A)

IoT-23's lightweight distribution ships Zeek `conn.log.labeled` only — no `dns.log`, `http.log`, `ssl.log`, and no payload. The counts below are read from `src/schema/columns.py`, not asserted in prose.

| Group | Computable | Proxy | Unavailable | Unavailable features |
| --- | --- | --- | --- | --- |
| resolution | 0 | 1 | 3 | `ens_query_rate`, `resolution_entropy`, `serverlist_pull` |
| relay | 3 | 0 | 1 | `upnp_addportmapping` |
| infection | 3 | 1 | 0 | — |
| payload | 3 | 0 | 1 | `rc4_string_score` |

**5 of 16 features are unavailable and 2 are proxies on IoT-23.** Both resolution and relay — the groups whose independent value this project measures — are among them. This is why the thesis is tested only on Track B (mock), and why Track A measures false alarms on real benign traffic rather than the thesis itself.

---

*Regenerated from the schema by `python -m src.reports.generate_docs`. Edit `src/schema/columns.py`, not this file.*
