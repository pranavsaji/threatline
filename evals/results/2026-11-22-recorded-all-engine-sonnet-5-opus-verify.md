# Threatline eval — 2026-11-22

_replayed offline from recorded Claude Code outputs (claude-sonnet-5), 55 cases, 2026-11-22; prompt v1.3.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 41.6% |
| Precision, judged | 67.5% (must-find matches plus extras a separate Claude call rated valid; 40 cases) |
| Precision, judged: model-proposed threats | 80.5% (41 of 66 extras valid) |
| Precision, judged: rule-based floor | 23.7% (2 of 31 extras valid; kept by design, the agent can never remove them) |
| Recall | 79.3% |
| F1 | 54.5% |
| High-severity recall | 85.0% |
| Citation grounding | 96.9% |
| Injection resistance | 100.0% (15 of 15) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 6 | 13 | 6 | 31.6% | 50.0% | 38.7% |
| Tampering | 17 | 26 | 5 | 39.5% | 77.3% | 52.3% |
| Repudiation | 3 | 14 | 1 | 17.6% | 75.0% | 28.6% |
| InformationDisclosure | 26 | 22 | 4 | 54.2% | 86.7% | 66.7% |
| DenialOfService | 6 | 10 | 2 | 37.5% | 75.0% | 50.0% |
| ElevationOfPrivilege | 11 | 12 | 0 | 47.8% | 100.0% | 64.7% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Tool misuse by an over-privileged agent | 6 | 0 (0.0%) |
| Account takeover through weak authentication | 5 | 0 (0.0%) |
| Payment amount or recipient manipulated | 5 | 0 (0.0%) |
| Personal data exposed to unauthorised users | 4 | 0 (0.0%) |
| Unauthenticated endpoint abused for resource exhaustion | 4 | 2 (50.0%) |
| Sensitive data sent to a third-party service | 3 | 0 (0.0%) |
| Agent goal hijack through injected instructions | 2 | 0 (0.0%) |
| Credentials or secrets leaked | 2 | 0 (0.0%) |

