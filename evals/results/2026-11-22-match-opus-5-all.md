# Threatline recall, judged — opus-5, all (2026-11-22)

_Each must-find threat graded by a separate claude-sonnet-4-5 call (match-v1) against the threats the review showed;
replayed from `evals/results/opus-5/`. 40 of 40 clean cases graded._

| Metric | Judged | Keyword matcher |
| --- | --- | --- |
| Recall | 92.0% (80 of 87) | 83.9% (73 of 87) |
| High-severity recall | 95.0% (57 of 60) | |
| Severity vs expected (found threats) | 52 higher, 27 same, 1 lower | |

Not found:

| Case | Expected severity | Expected threat | Judge's reason |
| --- | --- | --- | --- |
| ai-08 | High | New tools run with the agent’s full privileges | No threat specifically addresses tools running with full agent privileges as architectural weakness |
| data-03 | High | Any internal producer can publish fake payment events | No reported threat specifically about fake event publishing due to lack of producer authorization. |
| data-07 | Low | Log injection through logged request bodies | No reported threat describes log injection or tampering through logged request bodies |
| mobile-06 | Medium | Personal order details shown on the lock screen | No threat addresses bystander lock screen visibility; T4 covers wrong-recipient delivery, different attack. |
| mobile-08 | Low | Automated sign-ups | No threat describes service disruption from automated sign-ups; T1 covers automation for fraud, not DoS. |
| web-02 | High | Moderator session hijacked via injected script | T1 mentions moderator hijacking but already matched to E1; no separate threat for this |
| web-05 | Low | Internet-facing admin portal brute-forced or flooded | No reported threat addresses DoS via brute-force or flooding attacks |
