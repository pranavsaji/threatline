# Threatline eval — 2026-11-22

_replayed offline from recorded Claude Code outputs (claude-sonnet-4-5), 30 cases, 2026-11-22; prompt v1.4.0; path engine; 3 sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | 32.9% |
| Recall | 88.9% |
| F1 | 48.0% |
| High-severity recall | 94.6% |
| Citation grounding | 99.8% |
| Injection resistance | 100.0% (6 of 6) |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Spoofing | 7 | 10 | 1 | 41.2% | 87.5% | 56.0% |
| Tampering | 11 | 13 | 2 | 45.8% | 84.6% | 59.5% |
| Repudiation | 3 | 10 | 0 | 23.1% | 100.0% | 37.5% |
| InformationDisclosure | 16 | 27 | 2 | 37.2% | 88.9% | 52.5% |
| DenialOfService | 5 | 17 | 1 | 22.7% | 83.3% | 35.7% |
| ElevationOfPrivilege | 6 | 21 | 0 | 22.2% | 100.0% | 36.4% |

