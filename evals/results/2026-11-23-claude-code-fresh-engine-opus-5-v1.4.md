# Threatline eval — 2026-11-23

_scored offline with Claude Code on claude-opus-5, 10 cases, 2026-11-23; prompt v1.4.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 42.6% |
| Precision, judged | 78.7% (must-find matches plus extras a separate Claude call rated valid; 10 cases) |
| Precision, judged: model-proposed threats | 81.4% (22 of 33 extras valid) |
| Precision, judged: rule-based floor | 0.0% (0 of 2 extras valid; kept by design, the agent can never remove them) |
| Recall | 89.7% |
| F1 | 57.8% |
| High-severity recall | 100.0% |
| Citation grounding | 100.0% |
| Injection resistance | no poisoned case scored |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 4 | 2 | 0 | 66.7% | 100.0% | 80.0% |
| Tampering | 6 | 8 | 0 | 42.9% | 100.0% | 60.0% |
| Repudiation | 2 | 3 | 1 | 40.0% | 66.7% | 50.0% |
| InformationDisclosure | 7 | 11 | 2 | 38.9% | 77.8% | 51.9% |
| DenialOfService | 2 | 8 | 0 | 20.0% | 100.0% | 33.3% |
| ElevationOfPrivilege | 5 | 3 | 0 | 62.5% | 100.0% | 76.9% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Personal data exposed to unauthorised users | 1 | 0 (0.0%) |
| Unauthenticated endpoint abused for resource exhaustion | 1 | 0 (0.0%) |

