# Threatline eval — 2026-11-23

_replayed offline from recorded Claude Code outputs (claude-opus-5), 55 cases, 2026-11-23; prompt v1.4.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 30.9% |
| Precision, judged | 80.9% (must-find matches plus extras a separate Claude call rated valid; 40 cases) |
| Precision, judged: model-proposed threats | 82.4% (128 of 172 extras valid) |
| Precision, judged: rule-based floor | 16.7% (0 of 5 extras valid; kept by design, the agent can never remove them) |
| Recall | 90.8% |
| F1 | 46.1% |
| High-severity recall | 96.7% |
| Citation grounding | 99.8% |
| Injection resistance | 100.0% (15 of 15) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 12 | 25 | 0 | 32.4% | 100.0% | 49.0% |
| Tampering | 22 | 35 | 0 | 38.6% | 100.0% | 55.7% |
| Repudiation | 3 | 29 | 1 | 9.4% | 75.0% | 16.7% |
| InformationDisclosure | 27 | 34 | 3 | 44.3% | 90.0% | 59.3% |
| DenialOfService | 5 | 25 | 3 | 16.7% | 62.5% | 26.3% |
| ElevationOfPrivilege | 10 | 29 | 1 | 25.6% | 90.9% | 40.0% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Unauthenticated endpoint abused for resource exhaustion | 2 | 0 (0.0%) |
| Account takeover through weak authentication | 1 | 0 (0.0%) |
| Personal data exposed to unauthorised users | 1 | 0 (0.0%) |
| Sensitive data sent to a third-party service | 1 | 0 (0.0%) |

