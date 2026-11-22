# Threatline eval — 2026-11-22

_scored offline with Claude Code on claude-opus-5, 55 cases, 2026-11-22; prompt v1.4.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 35.7% |
| Precision, judged | 76.6% (must-find matches plus extras a separate Claude call rated valid; 36 cases; incomplete: 4 not judged, see failures) |
| Precision, judged: model-proposed threats | 80.8% (79 of 114 extras valid) |
| Precision, judged: rule-based floor | 0.0% (0 of 10 extras valid; kept by design, the agent can never remove them) |
| Recall | 85.1% |
| F1 | 50.3% |
| High-severity recall | 95.0% |
| Citation grounding | 99.8% |
| Injection resistance | 100.0% (15 of 15) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 11 | 16 | 1 | 40.7% | 91.7% | 56.4% |
| Tampering | 21 | 25 | 1 | 45.7% | 95.5% | 61.8% |
| Repudiation | 3 | 23 | 1 | 11.5% | 75.0% | 20.0% |
| InformationDisclosure | 25 | 23 | 5 | 52.1% | 83.3% | 64.1% |
| DenialOfService | 5 | 22 | 3 | 18.5% | 62.5% | 28.6% |
| ElevationOfPrivilege | 9 | 24 | 2 | 27.3% | 81.8% | 40.9% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Personal data exposed to unauthorised users | 4 | 0 (0.0%) |
| Agent goal hijack through injected instructions | 2 | 0 (0.0%) |
| Unauthenticated endpoint abused for resource exhaustion | 2 | 0 (0.0%) |
| Payment amount or recipient manipulated | 1 | 0 (0.0%) |
| Sensitive data sent to a third-party service | 1 | 0 (0.0%) |

Failures: judge web-04: schema (judge must give one verdict per id (x1, x2, x3)), judge api-02: schema (judge must give one verdict per id (x1, x2)), judge mobile-07: schema (judge reply is not JSON), judge data-02: schema (judge reply is not JSON)
