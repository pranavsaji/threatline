# Threatline recall, judged — opus-5, holdout (2026-11-22)

_Each must-find threat graded by a separate claude-sonnet-4-5 call (match-v1) against the threats the review showed;
replayed from `evals/results/opus-5/`. 16 of 16 clean cases graded._

| Metric | Judged | Keyword matcher |
| --- | --- | --- |
| Recall | 87.9% (29 of 33) | 81.8% (27 of 33) |
| High-severity recall | 95.7% (22 of 23) | |
| Severity vs expected (found threats) | 19 higher, 10 same, 0 lower | |

Not found:

| Case | Expected severity | Expected threat | Judge's reason |
| --- | --- | --- | --- |
| ai-08 | High | New tools run with the agent’s full privileges | No threat specifically addresses tools running with full agent privileges as architectural weakness |
| data-07 | Low | Log injection through logged request bodies | No reported threat describes log injection or tampering through logged request bodies |
| mobile-06 | Medium | Personal order details shown on the lock screen | No threat addresses bystander lock screen visibility; T4 covers wrong-recipient delivery, different attack. |
| mobile-08 | Low | Automated sign-ups | No threat describes service disruption from automated sign-ups; T1 covers automation for fraud, not DoS. |
