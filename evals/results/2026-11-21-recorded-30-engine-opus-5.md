# Threatline eval — 2026-11-21

_replayed offline from recorded Claude Code outputs (claude-opus-5), 30 cases, 2026-11-21; prompt v1.3.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 31.9% |
| Precision, judged | 71.1% (must-find matches plus extras a separate Claude call rated valid; 23 cases; incomplete: 1 not judged, see failures) |
| Precision, judged: model-proposed threats | 75.4% (53 of 84 extras valid) |
| Precision, judged: rule-based floor | 11.1% (1 of 9 extras valid; kept by design, the agent can never remove them) |
| Recall | 83.3% |
| F1 | 46.2% |
| High-severity recall | 89.2% |
| Citation grounding | 97.7% |
| Injection resistance | 100.0% (6 of 6) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 8 | 13 | 0 | 38.1% | 100.0% | 55.2% |
| Tampering | 9 | 18 | 4 | 33.3% | 69.2% | 45.0% |
| Repudiation | 1 | 16 | 2 | 5.9% | 33.3% | 10.0% |
| InformationDisclosure | 16 | 20 | 2 | 44.4% | 88.9% | 59.3% |
| DenialOfService | 5 | 8 | 1 | 38.5% | 83.3% | 52.6% |
| ElevationOfPrivilege | 6 | 21 | 0 | 22.2% | 100.0% | 36.4% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Account takeover through weak authentication | 2 | 0 (0.0%) |
| Payment amount or recipient manipulated | 2 | 0 (0.0%) |
| Tool misuse by an over-privileged agent | 2 | 1 (50.0%) |
| Credentials or secrets leaked | 1 | 0 (0.0%) |
| Personal data exposed to unauthorised users | 1 | 0 (0.0%) |
| Unauthenticated endpoint abused for resource exhaustion | 1 | 0 (0.0%) |

Failures: judge api-02: schema (judge must give one verdict per id (x1, x2, x3))
