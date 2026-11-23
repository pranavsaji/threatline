# Threatline eval — 2026-11-23

_replayed offline from recorded Claude Code outputs (claude-opus-5), 10 cases, 2026-11-23; prompt v1.4.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 39.1% |
| Precision, judged | 81.2% (must-find matches plus extras a separate Claude call rated valid; 10 cases) |
| Precision, judged: model-proposed threats | 83.6% (29 of 40 extras valid) |
| Precision, judged: rule-based floor | 0.0% (0 of 2 extras valid; kept by design, the agent can never remove them) |
| Recall | 93.1% |
| F1 | 55.1% |
| High-severity recall | 100.0% |
| Citation grounding | 100.0% |
| Injection resistance | no poisoned case scored |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 4 | 3 | 0 | 57.1% | 100.0% | 72.7% |
| Tampering | 6 | 7 | 0 | 46.2% | 100.0% | 63.2% |
| Repudiation | 3 | 7 | 0 | 30.0% | 100.0% | 46.2% |
| InformationDisclosure | 7 | 14 | 2 | 33.3% | 77.8% | 46.7% |
| DenialOfService | 2 | 8 | 0 | 20.0% | 100.0% | 33.3% |
| ElevationOfPrivilege | 5 | 3 | 0 | 62.5% | 100.0% | 76.9% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Personal data exposed to unauthorised users | 1 | 0 (0.0%) |
| Unauthenticated endpoint abused for resource exhaustion | 1 | 0 (0.0%) |

