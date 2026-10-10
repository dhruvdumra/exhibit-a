# `.exhibita.yml` reference

Place `.exhibita.yml` in the folder you scan. Every key is optional; without the
file, ExhibitA uses safe defaults (all scanners, gate on proven criticals, English).

```yaml
scanners: [semgrep, gitleaks, hadolint, checkov]   # subset to run
ignore: ["tests/*", "vendor/*"]                      # glob paths to drop findings from
gate_severity: critical                              # min severity a proven finding must hit to fail the gate
lang: en                                             # explanation language (code fixes stay English)
fix_check: true                                      # apply each fix to a copy and re-scan to confirm

verify:
  routes:                                            # declare entry points for non-Flask apps
    - match: sql_injection                           # a vuln class or a scanner rule id
      path: /api/users
      param: id
    - match: xxe
      path: /api/import                              # body-based endpoints need no param
```

## Route `match` values

Vulnerability classes: `sql_injection`, `command_injection`, `path_traversal`,
`ssti`, `xss`, `xxe`. Or a specific scanner rule id (e.g. `exhibita-sql-injection`).

Flask apps are located automatically from `@app.route` and `request.args`, so they
usually need no route declarations. Declare routes for FastAPI, Django, Express, and
other frameworks whose entry points ExhibitA cannot read statically.
