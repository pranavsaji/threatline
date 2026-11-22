# Threatline eval — 2026-11-22

_replayed offline from recorded Claude Code outputs (claude-opus-5), 55 cases, 2026-11-22; prompt v1.4.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 32.4% |
| Precision, judged | 72.4% (must-find matches plus extras a separate Claude call rated valid; 34 cases; incomplete: 6 not judged, see failures) |
| Precision, judged: model-proposed threats | 73.4% (78 of 129 extras valid) |
| Precision, judged: rule-based floor | 25.0% (1 of 4 extras valid; kept by design, the agent can never remove them) |
| Recall | 83.9% |
| F1 | 46.8% |
| High-severity recall | 93.3% |
| Citation grounding | 97.4% |
| Injection resistance | 100.0% (15 of 15) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 11 | 21 | 1 | 34.4% | 91.7% | 50.0% |
| Tampering | 18 | 22 | 4 | 45.0% | 81.8% | 58.1% |
| Repudiation | 2 | 27 | 2 | 6.9% | 50.0% | 12.1% |
| InformationDisclosure | 26 | 32 | 4 | 44.8% | 86.7% | 59.1% |
| DenialOfService | 6 | 17 | 2 | 26.1% | 75.0% | 38.7% |
| ElevationOfPrivilege | 10 | 33 | 1 | 23.3% | 90.9% | 37.0% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Personal data exposed to unauthorised users | 2 | 1 (50.0%) |
| Payment amount or recipient manipulated | 1 | 0 (0.0%) |
| Unauthenticated endpoint abused for resource exhaustion | 1 | 0 (0.0%) |

Failures: judge web-07: schema (judge must give one verdict per id (x1, x2)), judge api-02: schema (judge must give one verdict per id (x1, x2, x3)), judge mobile-04: schema (judge must give one verdict per id (x1, x2)), judge mobile-05: schema (judge must give one verdict per id (x1, x2, x3)), judge data-02: schema (judge must give one verdict per id (x1, x2, x3, x4, x5)), judge data-07: schema (judge must give one verdict per id (x1, x2, x3, x4))
