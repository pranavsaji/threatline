# Threatline eval — 2026-11-22

_scored offline with Claude Code on claude-sonnet-5, 55 cases, 2026-11-22; prompt v1.3.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 41.7% |
| Precision, judged | 67.9% (must-find matches plus extras a separate Claude call rated valid; 40 cases) |
| Precision, judged: model-proposed threats | 82.9% (40 of 60 extras valid) |
| Precision, judged: rule-based floor | 23.1% (1 of 31 extras valid; kept by design, the agent can never remove them) |
| Recall | 74.7% |
| F1 | 53.5% |
| High-severity recall | 83.3% |
| Citation grounding | 96.9% |
| Injection resistance | 93.3% (14 of 15) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 6 | 12 | 6 | 33.3% | 50.0% | 40.0% |
| Tampering | 16 | 25 | 6 | 39.0% | 72.7% | 50.8% |
| Repudiation | 2 | 10 | 2 | 16.7% | 50.0% | 25.0% |
| InformationDisclosure | 25 | 21 | 5 | 54.3% | 83.3% | 65.8% |
| DenialOfService | 6 | 10 | 2 | 37.5% | 75.0% | 50.0% |
| ElevationOfPrivilege | 10 | 13 | 1 | 43.5% | 90.9% | 58.8% |

Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
| Payment amount or recipient manipulated | 6 | 0 (0.0%) |
| Tool misuse by an over-privileged agent | 6 | 0 (0.0%) |
| Account takeover through weak authentication | 5 | 0 (0.0%) |
| Unauthenticated endpoint abused for resource exhaustion | 4 | 1 (25.0%) |
| Personal data exposed to unauthorised users | 3 | 0 (0.0%) |
| Sensitive data sent to a third-party service | 3 | 0 (0.0%) |
| Agent goal hijack through injected instructions | 2 | 0 (0.0%) |
| Credentials or secrets leaked | 2 | 0 (0.0%) |

