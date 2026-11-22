# Threatline eval — 2026-11-22

_replayed offline from recorded Claude Code outputs (claude-opus-5), 55 cases, 2026-11-22; prompt v1.4.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 36.0% |
| Precision, judged | 78.0% (must-find matches plus extras a separate Claude call rated valid; 32 cases; incomplete: 8 not judged, see failures) |
| Precision, judged: model-proposed threats | 79.9% (69 of 102 extras valid) |
| Precision, judged: rule-based floor | 0.0% (0 of 4 extras valid; kept by design, the agent can never remove them) |
| Recall | 83.9% |
| F1 | 50.3% |
| High-severity recall | 93.3% |
| Citation grounding | 99.8% |
| Injection resistance | 100.0% (15 of 15) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 11 | 16 | 1 | 40.7% | 91.7% | 56.4% |
| Tampering | 20 | 26 | 2 | 43.5% | 90.9% | 58.8% |
| Repudiation | 3 | 23 | 1 | 11.5% | 75.0% | 20.0% |
| InformationDisclosure | 25 | 22 | 5 | 53.2% | 83.3% | 64.9% |
| DenialOfService | 5 | 22 | 3 | 18.5% | 62.5% | 28.6% |
| ElevationOfPrivilege | 9 | 21 | 2 | 30.0% | 81.8% | 43.9% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Unauthenticated endpoint abused for resource exhaustion | 2 | 0 (0.0%) |
| Personal data exposed to unauthorised users | 1 | 0 (0.0%) |
| Sensitive data sent to a third-party service | 1 | 0 (0.0%) |

Failures: judge web-04: schema (judge must give one verdict per id (x1, x2, x3)), judge api-02: schema (judge must give one verdict per id (x1, x2)), judge mobile-06: schema (judge must give one verdict per id (x1, x2, x3)), judge mobile-07: not_found (no recorded judge reply), judge data-01: schema (judge must give one verdict per id (x1, x2, x3, x4)), judge data-02: not_found (no recorded judge reply), judge data-07: schema (judge must give one verdict per id (x1, x2, x3)), judge ai-07: schema (judge must give one verdict per id (x1, x2))
