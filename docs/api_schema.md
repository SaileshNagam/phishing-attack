# PhishShield — API Response JSON Schema

> **Version:** 2.0 | **Endpoint:** `POST /predict`

Both the Chrome Extension and Web Dashboard consume the **same unified response**. This document is the single source of truth.

---

## `POST /predict` Response Schema

```json
{
  "scan_id":      "3f7a1b2c-…",          // UUID — unique per scan
  "timestamp":    "2026-03-16T00:05:00Z",// ISO-8601 UTC

  "prediction":   "PHISHING",            // "PHISHING" | "LEGITIMATE"
  "confidence":   0.92,                  // float 0.0 – 1.0
  "safety_score": 8,                     // int 0 (dangerous) – 100 (safe)
                                         // inverse of confidence for phishing
  "risk_level":   "CRITICAL",            // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"

  "reasoning": [                         // exactly 3 human-readable bullets
    "Sender domain registered 12 days ago.",
    "SPF check FAILED — unauthorized sending server.",
    "Email contains a bit.ly shortened URL."
  ],

  "xai_features": [                      // top 6 feature importances (bar chart)
    { "feature": "Suspicious URLs",         "weight": 0.82, "direction": "phishing"   },
    { "feature": "New / Unknown Domain",    "weight": 0.74, "direction": "phishing"   },
    { "feature": "Urgent Language Tone",    "weight": 0.65, "direction": "phishing"   },
    { "feature": "SPF / DKIM Failure",      "weight": 0.58, "direction": "phishing"   },
    { "feature": "Sensitive Keyword Count", "weight": 0.44, "direction": "phishing"   },
    { "feature": "HTML Link Obfuscation",   "weight": 0.21, "direction": "legitimate" }
  ],

  "forensics": {
    "spf_status":             "FAIL",    // "PASS" | "FAIL" | "NONE"
    "dkim_status":            "NONE",    // "PASS" | "FAIL" | "NONE"
    "dmarc_status":           "FAIL",    // "PASS" | "FAIL" | "NONE"
    "domain_age_days":        12,        // int | null — from WHOIS heuristic
    "sender_domain":          "secure-bank.xyz",
    "display_name_mismatch":  true,      // bool — display name ≠ from domain
    "url_analysis": [                    // per-URL breakdown
      {
        "url":          "https://bit.ly/verify-bank",
        "domain":       "bit.ly",
        "risk":         "HIGH",          // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        "reason":       "Shortened URL hides true destination",
        "is_shortened": true
      }
    ]
  },

  "email_meta": {
    "subject":         "Urgent: Verify Your Banking Account",
    "sender":          "noreply@secure-bank.xyz",
    "url_count":       2,
    "has_attachments": false
  },

  "pred_proba": {
    "PHISHING":    0.92,
    "LEGITIMATE":  0.08
  }
}
```

---

## `GET /history` Response Schema

```json
{
  "total":   42,
  "records": [
    { /* same structure as /predict response */ }
  ]
}
```

> Records are returned **newest-first**. Max 500 records in memory. Use `?limit=N&offset=M` for pagination.

---

## Risk Level Mapping

| `risk_level` | `safety_score` range | Banner Color | Use case |
|---|---|---|---|
| `CRITICAL`  | 0–20   | 🔴 Red    | Active phishing, high confidence |
| `HIGH`      | 21–40  | 🔴 Red    | Strong phishing indicators        |
| `MEDIUM`    | 41–65  | 🟡 Yellow | Some suspicious signals           |
| `LOW`       | 66–100 | 🟢 Green  | Legitimate email                  |

---

## XAI Feature Direction

| `direction`   | Chart color | Meaning |
|---|---|---|
| `"phishing"`   | 🔴 Red   | Feature increases phishing probability |
| `"legitimate"` | 🟢 Green | Feature decreases phishing probability |
