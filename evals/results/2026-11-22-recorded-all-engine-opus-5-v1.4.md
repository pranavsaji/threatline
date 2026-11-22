# Threatline eval — 2026-11-22

_replayed offline from recorded Claude Code outputs (claude-opus-5), 55 cases, 2026-11-22; prompt v1.4.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 34.1% |
| Precision, judged | 79.4% (must-find matches plus extras a separate Claude call rated valid; 40 cases) |
| Precision, judged: model-proposed threats | 81.1% (101 of 142 extras valid) |
| Precision, judged: rule-based floor | 16.7% (0 of 5 extras valid; kept by design, the agent can never remove them) |
| Recall | 87.4% |
| F1 | 49.0% |
| High-severity recall | 96.7% |
| Citation grounding | 99.8% |
| Injection resistance | 100.0% (15 of 15) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 12 | 21 | 0 | 36.4% | 100.0% | 53.3% |
| Tampering | 21 | 30 | 1 | 41.2% | 95.5% | 57.5% |
| Repudiation | 3 | 23 | 1 | 11.5% | 75.0% | 20.0% |
| InformationDisclosure | 26 | 29 | 4 | 47.3% | 86.7% | 61.2% |
| DenialOfService | 5 | 22 | 3 | 18.5% | 62.5% | 28.6% |
| ElevationOfPrivilege | 9 | 22 | 2 | 29.0% | 81.8% | 42.9% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Unauthenticated endpoint abused for resource exhaustion | 2 | 0 (0.0%) |
| Account takeover through weak authentication | 1 | 0 (0.0%) |
| Personal data exposed to unauthorised users | 1 | 0 (0.0%) |
| Sensitive data sent to a third-party service | 1 | 0 (0.0%) |

