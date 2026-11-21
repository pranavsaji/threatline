# Threatline eval — 2026-11-21

_replayed offline from recorded Claude Code outputs (claude-opus-5), 55 cases, 2026-11-21; prompt v1.3.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 30.3% |
| Precision, judged | 69.3% (must-find matches plus extras a separate Claude call rated valid; 37 cases; incomplete: 3 not judged, see failures) |
| Precision, judged: model-proposed threats | 74.7% (82 of 132 extras valid) |
| Precision, judged: rule-based floor | 5.9% (1 of 17 extras valid; kept by design, the agent can never remove them) |
| Recall | 81.6% |
| F1 | 44.2% |
| High-severity recall | 91.7% |
| Citation grounding | 97.4% |
| Injection resistance | 100.0% (15 of 15) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 11 | 23 | 1 | 32.4% | 91.7% | 47.8% |
| Tampering | 16 | 28 | 6 | 36.4% | 72.7% | 48.5% |
| Repudiation | 2 | 26 | 2 | 7.1% | 50.0% | 12.5% |
| InformationDisclosure | 26 | 35 | 4 | 42.6% | 86.7% | 57.1% |
| DenialOfService | 6 | 16 | 2 | 27.3% | 75.0% | 40.0% |
| ElevationOfPrivilege | 10 | 35 | 1 | 22.2% | 90.9% | 35.7% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Tool misuse by an over-privileged agent | 4 | 1 (25.0%) |
| Payment amount or recipient manipulated | 3 | 0 (0.0%) |
| Account takeover through weak authentication | 2 | 0 (0.0%) |
| Agent goal hijack through injected instructions | 2 | 0 (0.0%) |
| Personal data exposed to unauthorised users | 2 | 0 (0.0%) |
| Sensitive data sent to a third-party service | 2 | 0 (0.0%) |
| Credentials or secrets leaked | 1 | 0 (0.0%) |
| Unauthenticated endpoint abused for resource exhaustion | 1 | 0 (0.0%) |

Failures: judge api-02: schema (judge must give one verdict per id (x1, x2, x3)), judge mobile-06: schema (judge must give one verdict per id (x1, x2, x3, x4)), judge ai-05: schema (judge must give one verdict per id (x1, x2, x3, x4, x5, x6, x7))
