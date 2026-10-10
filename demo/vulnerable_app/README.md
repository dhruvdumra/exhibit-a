# ⚠️ Intentionally vulnerable demo app — DO NOT DEPLOY

This small Flask app contains **planted security bugs** used to demonstrate ExhibitA.
It must only ever run inside ExhibitA's isolated sandbox. Do not expose it to a network.

Planted issues:

| Where | Bug | Proof |
|---|---|---|
| `GET /api/notes?owner=` | SQL injection | ✅ red→green in sandbox |
| `GET /api/hello?name=` | command injection | ✅ red→green in sandbox |
| `GET /api/read?file=` | path traversal / file disclosure | ✅ red→green in sandbox |
| `GET /api/greet?name=` | server-side template injection | ✅ red→green in sandbox |
| `GET /api/search?q=` | reflected XSS | ✅ red→green in sandbox |
| `POST /api/xml` | XML external entity (XXE) | ✅ red→green in sandbox |
| `app.run(debug=True)` | Werkzeug debugger (RCE) | flagged + explained |
| `GET /api/avatar` | MD5 as a cache key | flagged (likely false positive) |
| `config.py` | hardcoded credentials | flagged + explained |
| `Dockerfile` | `latest` tag, runs as root, secret in `ENV` | flagged + explained |
| `k8s/deployment.yaml` | privileged, hostNetwork, no limits | flagged + explained |
| `.github/workflows/deploy.yml` | `write-all` permissions, unpinned actions | flagged + explained |

`content/public.txt` is a safe file the path-traversal endpoint is meant to serve;
`secret_internal.txt` is the planted file it must never reach.
