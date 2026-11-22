# Threatline recall, judged — sonnet-5, all (2026-11-22)

_Each must-find threat graded by a separate claude-sonnet-4-5 call (match-v1) against the threats the review showed;
replayed from `evals/results/sonnet-5/`. 38 of 40 clean cases graded._

| Metric | Judged | Keyword matcher |
| --- | --- | --- |
| Recall | 78.0% (64 of 82) | 75.6% (62 of 82) |
| High-severity recall | 84.2% (48 of 57) | |
| Severity vs expected (found threats) | 20 higher, 41 same, 3 lower | |

Not found:

| Case | Expected severity | Expected threat | Judge's reason |
| --- | --- | --- | --- |
| ai-03 | High | Agent pushes malicious code | No threat focuses on agent pushing malicious code; T3 mentions push but as consequence of scope |
| ai-05 | Medium | Generated queries read data beyond the analyst’s scope | No reported threat addresses reading data beyond analyst's authorized scope; T2 is DoS-focused. |
| api-01 | High | Stolen non-expiring API key reused | While T2 mentions non-expiring keys, it's matched to E1; no other threat focuses on key reuse. |
| api-06 | High | Shared signing secret lets any service mint tokens for others | No threat describes services minting tokens for each other |
| data-01 | Low | No record of who queried personal data | No reported threat discusses audit logging of personal data queries. |
| data-04 | Medium | Backups modified or deleted | No reported threat describes tampering with or deleting backups; T2 is about unauthorized read access |
| data-07 | Low | Log injection through logged request bodies | No reported threat describes log injection attacks via request body content |
| mobile-01 | High | Biometric check bypassed because it only gates the UI | T2 is generic weak authentication, doesn't specifically identify UI-only biometric bypass vulnerability |
| mobile-04 | High | Premium unlocked without a real purchase by faking the client flag | Different weaknesses: T1 targets receipt validation, E1 targets trusted client flag |
| mobile-08 | Low | Automated sign-ups | No reported threat addresses DoS/availability impact from automated sign-ups; T2 covers fraud not DoS |
| web-01 | High | Account takeover via reusable or guessable reset token | No threat addresses weak token generation; T3/T4 describe timing/exposure, not reusability or guessability. |
| web-02 | High | Moderator session hijacked via injected script | T1 mentions moderator session theft but as consequence, not separate EoP threat |
| web-02 | Low | No audit trail for comment deletion | No reported threat addresses audit logging or repudiation of deletion actions |
| web-03 | Medium | Long-lived session cookie stolen and reused | No threat focuses on session cookie theft/reuse as the primary vulnerability. |
| web-04 | Low | Billing data cached by shared proxies | Neither reported threat addresses shared proxy caching; T2 focuses on data aggregation, not infrastructure caching. |
| web-05 | Low | Internet-facing admin portal brute-forced or flooded | Neither threat addresses brute-force or flooding DoS attacks on the portal. |
| web-06 | High | Misconfigured storage bucket exposes all files | No reported threat addresses bucket access control misconfiguration; T2 covers predictable identifiers instead |
| web-08 | High | Over-broad impersonation lets support staff act as any customer | No threat addresses over-broad authorization scope of impersonation feature |

Not graded: api-02: schema; mobile-02: schema
