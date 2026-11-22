# Threatline eval — 2026-11-22

_scored offline with Claude Code on claude-opus-5, 30 cases, 2026-11-22; prompt v1.4.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 37.4% |
| Precision, judged | 74.4% (must-find matches plus extras a separate Claude call rated valid; 22 cases; incomplete: 2 not judged, see failures) |
| Precision, judged: model-proposed threats | 78.9% (46 of 70 extras valid) |
| Precision, judged: rule-based floor | 0.0% (0 of 7 extras valid; kept by design, the agent can never remove them) |
| Recall | 90.7% |
| F1 | 53.0% |
| High-severity recall | 97.3% |
| Citation grounding | 99.7% |
| Injection resistance | 100.0% (6 of 6) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 8 | 11 | 0 | 42.1% | 100.0% | 59.3% |
| Tampering | 13 | 15 | 0 | 46.4% | 100.0% | 63.4% |
| Repudiation | 2 | 15 | 1 | 11.8% | 66.7% | 20.0% |
| InformationDisclosure | 16 | 14 | 2 | 53.3% | 88.9% | 66.7% |
| DenialOfService | 5 | 13 | 1 | 27.8% | 83.3% | 41.7% |
| ElevationOfPrivilege | 5 | 14 | 1 | 26.3% | 83.3% | 40.0% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Personal data exposed to unauthorised users | 2 | 0 (0.0%) |
| Unauthenticated endpoint abused for resource exhaustion | 2 | 0 (0.0%) |
| Agent goal hijack through injected instructions | 1 | 0 (0.0%) |
| Payment amount or recipient manipulated | 1 | 0 (0.0%) |
| Sensitive data sent to a third-party service | 1 | 0 (0.0%) |

Failures: judge api-01: schema (judge reply is not JSON), judge data-02: schema (judge reply is not JSON)
