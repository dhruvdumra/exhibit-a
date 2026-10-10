# ExhibitA benchmark — juice-shop

Target: **juice-shop** — 26 alerts from Semgrep `p/javascript p/typescript p/owasp-top-ten p/security-audit` over its server-side source.  Engine: `ollama:gemma4:e4b`.

## What a plain scanner leaves you with

- **26** raw Semgrep alerts (scan: 101s) — a wall of alerts to read.

## What ExhibitA adds

- **11** of the 26 alerts fall into classes ExhibitA can **prove** exploitable in a sandbox when the app is run: sql_injection ×6, path_traversal ×4, xss ×1.
- **26** triaged in this run (sample of 30; triage: 0s) — each gets a plain-English explanation and a suggested fix.
- **0** (0%) AI-flagged *likely false positive*, **26** left to review.  On a deliberately vulnerable app this is expected: Gemma confirmed the alerts rather than dismissing real issues. (It filters genuine noise — see the MD5-as-cache-key case in the demo app.)

> Honesty: false-positive labels are Gemma's assessment, not hand-verified. The sandbox proof is not run here (Juice Shop isn't launched); this measures triage and shows how much of the wall is provable.

## Most common alert types

- `express-sequelize-injection` × 6
- `express-check-directory-listing` × 5
- `express-res-sendfile` × 4
- `aws-subnet-has-public-ip-address` × 3
- `insecure-load-balancer-tls-version` × 3
- `hardcoded-jwt-secret` × 1
- `unknown-value-in-redirect` × 1
- `express-open-redirect` × 1
- `code-string-concat` × 1
- `unknown-value-with-script-tag` × 1