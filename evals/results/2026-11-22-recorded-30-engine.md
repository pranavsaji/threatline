# Threatline eval — 2026-11-22

_replayed offline from recorded Claude Code outputs (claude-sonnet-4-5), 30 cases, 2026-11-22; prompt v1.4.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 32.9% |
| Recall | 88.5% |
| F1 | 47.9% |
| High-severity recall | 94.3% |
| Citation grounding | 99.7% |
| Injection resistance | 100.0% (6 of 6) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 7 | 10 | 1 | 41.2% | 87.5% | 56.0% |
| Tampering | 11 | 12 | 2 | 47.8% | 84.6% | 61.1% |
| Repudiation | 3 | 9 | 0 | 25.0% | 100.0% | 40.0% |
| InformationDisclosure | 15 | 26 | 2 | 36.6% | 88.2% | 51.7% |
| DenialOfService | 5 | 16 | 1 | 23.8% | 83.3% | 37.0% |
| ElevationOfPrivilege | 5 | 21 | 0 | 19.2% | 100.0% | 32.3% |

Failures: ai-04: timeout (claude -p timed out after 240000 ms)
