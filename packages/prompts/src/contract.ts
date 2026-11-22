export const OUTPUT_CONTRACT = `Return exactly one JSON object and nothing else:
{
  "schema": "threatline.threatmodel.v1",
  "issueKey": "<the work item key you were given>",
  "sketch": {
    "components": ["<= 30 short names"], "dataStores": [], "externalServices": [], "trustBoundaries": [],
    "dataClasses": ["pii" | "credentials" | "payment" | "health" | "secrets"],
    "exposure": "internal" | "partner" | "public",
    "llmFeatures": true | false
  },
  "threats": [
    {
      "stride": "Spoofing" | "Tampering" | "Repudiation" | "InformationDisclosure" | "DenialOfService" | "ElevationOfPrivilege",
      "title": "<= 120 chars, plain words",
      "scenario": "<= 600 chars: who attacks, how, and what they get",
      "component": "<= 80 chars",
      "likelihood": 1-5,
      "impact": 1-5,
      "rating": { "attacker": "anyone" | "user" | "insider", "effort": "low" | "medium" | "high", "reach": "one" | "many" | "all", "harm": "takeover" | "money" | "sensitive_data" | "integrity" | "personal_data" | "availability" | "minor" },
      "evidence": [ { "quote": "<= 200 chars copied VERBATIM from the context you were given>" } ],
      "asvs": ["V8.2.1"],
      "cwe": ["CWE-639"],
      "plainLanguage": "<= 200 chars a non-security person understands",
      "requirement": { "title": "...", "given": "...", "when": "...", "then": "..." }
    }
  ]
}
No other keys. At most 25 threats. Every threat needs at least one verbatim quote; threats without one are discarded.`;
