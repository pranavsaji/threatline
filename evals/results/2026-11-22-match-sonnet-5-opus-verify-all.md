# Threatline recall, judged — sonnet-5-opus-verify, all (2026-11-22)

_Each must-find threat graded by a separate claude-sonnet-4-5 call (match-v1) against the threats the review showed;
replayed from `evals/results/sonnet-5-opus-verify/`. 40 of 40 clean cases graded._

| Metric | Judged | Keyword matcher |
| --- | --- | --- |
| Recall | 79.3% (69 of 87) | 78.2% (68 of 87) |
| High-severity recall | 85.0% (51 of 60) | |
| Severity vs expected (found threats) | 24 higher, 42 same, 3 lower | |

Not found:

| Case | Expected severity | Expected threat | Judge's reason |
| --- | --- | --- | --- |
| ai-03 | High | Agent pushes malicious code | No threat focuses on agent pushing malicious code; T3 mentions it but emphasizes token scope. |
| ai-05 | Medium | Generated queries read data beyond the analyst’s scope | No reported threat addresses data access beyond analyst authorization scope |
| api-01 | High | Stolen non-expiring API key reused | T2 mentions non-expiring keys but focuses on leakage; no threat primarily addresses reuse |
| data-07 | Low | Log injection through logged request bodies | No reported threat describes log injection or tampering via request bodies |
| mobile-01 | High | Biometric check bypassed because it only gates the UI | No reported threat describes bypassing UI-only biometric check to access stored token. |
| mobile-02 | Medium | Another app hijacks the custom URL scheme | No threat covers malicious app registering same URL scheme |
| mobile-04 | High | Premium unlocked without a real purchase by faking the client flag | T1 describes receipt replay attack; E1 targets client flag tampering—different attack vectors |
| mobile-05 | High | Driver location and phone exposed to anyone with a delivery id | No threat directly describes the missing authorization check enabling unauthorized delivery-ID-based access. |
| mobile-08 | Low | Automated sign-ups | No reported threat addresses DoS from automated sign-ups |
| web-02 | High | Moderator session hijacked via injected script | T1 mentions moderator session theft but already matched E1; no separate moderator-focused threat |
| web-02 | Low | No audit trail for comment deletion | No threat mentions missing audit trails for comment deletions |
| web-03 | Medium | Long-lived session cookie stolen and reused | No threat focuses on session cookie lifetime vulnerability |
| web-04 | Low | Billing data cached by shared proxies | T2 focuses on PDF content leakage via sharing, not HTTP caching by proxies |
| web-05 | Critical | Forged or replayed SAML assertion | T2 mentions replay/forgery only in passing; focuses on internet exposure, not SAML validation weakness. |
| web-05 | Low | Internet-facing admin portal brute-forced or flooded | Neither threat describes brute-force or flooding denial-of-service attacks on the portal. |
| web-06 | High | Misconfigured storage bucket exposes all files | No threat describes bucket-level ACL or policy misconfiguration |
| web-07 | Medium | Discount code brute force or reuse | No threat describes brute-forcing codes or reusing codes multiple times |
| web-08 | High | Over-broad impersonation lets support staff act as any customer | No reported threat addresses over-broad impersonation access scope or authorization controls |
