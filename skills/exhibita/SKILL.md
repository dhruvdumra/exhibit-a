---
name: exhibita
description: Prove and fix security vulnerabilities in code before committing or opening a pull request. Use when about to commit code, open a PR, or when the user asks to security-review, scan, audit, or harden an app or service. Runs Semgrep/Gitleaks/Hadolint/Checkov, triages findings with the open Gemma 4 model, proves critical bugs (SQL injection, command injection, path traversal, SSTI, reflected XSS, XXE) in an isolated sandbox, and offers verified one-click fixes. Especially useful so an AI agent can check its own changes before proposing them.
license: MIT
compatibility: Requires Python 3.11+, Docker, and either a local Ollama model (offline) or a GEMINI_API_KEY (cloud).
metadata:
  version: "0.1"
  project: ExhibitA
---

# ExhibitA — prove the fix, not just the finding

ExhibitA is a security reviewer that **proves** a vulnerability is real before asking
anyone to fix it: it writes an exploit, runs it against the app in a locked-down
sandbox, applies the AI's fix, and confirms the exploit no longer works and the app
still behaves. Use it to review code you (or another agent) just wrote, **before**
committing or opening a pull request — so proposed changes arrive already checked,
not as unverified noise.

## When to use this skill

- You are about to commit code or open a PR that touches request handling, database
  queries, file access, templating, shell commands, XML parsing, or deployment config.
- The user asks to "security review", "scan", "audit", "harden", or "check for
  vulnerabilities".
- You want evidence a fix actually works, not just a plausible-looking diff.

## Setup (once)

```bash
pip install exhibita                 # or: pip install -e . from the repo
docker build -t exhibita-sandbox:latest sandbox/   # for self-contained apps
```

Choose a backend:
- **Offline:** install Ollama and `ollama pull gemma4:e4b`, then `MODEL_BACKEND=ollama`.
- **Cloud:** set `GEMINI_API_KEY`, then `MODEL_BACKEND=gemini`.

## How to run

Scan and triage (fast, read-only):

```bash
exhibita scan path/to/code
```

Scan, triage, and **prove** critical findings in the sandbox (the full workflow):

```bash
exhibita verify path/to/code
```

The target runs through its own `Dockerfile` when present (any framework); otherwise
ExhibitA runs a self-contained Python app in the sandbox image. For other frameworks,
declare routes in `.exhibita.yml` (see `references/config.md`).

Write machine-readable outputs (used in CI):

```bash
exhibita scan path/to/code --verify --sarif out.sarif --markdown out.md --comments out.json
```

## Reading the result

Each finding carries an honest **evidence** label:

- **proven + fix verified** — the sandbox confirmed the bug, the fix blocked it, and
  a normal request still works. Safe to apply the suggested fix.
- **proven exploitable** — the bug is confirmed real; the suggested fix did not fully
  verify, so review it by hand.
- **explained** — found and explained, but not sandbox-proven (apply judgement).

The **build gate** fails only when a critical finding was *proven* exploitable — "no
proof, no block". Exit code 1 means a proven critical issue is present.

## Agent workflow: check your own work before a PR

1. Make the code change.
2. Run `exhibita verify <changed dir>`.
3. If the gate fails, apply the **proven + fix verified** suggestions and re-run.
4. Only then open the PR, and note in the description that ExhibitA verified it.

Do not propose a fix labelled only "explained" as if it were proven. Say what was
verified and what was not.

## Notes

- ExhibitA runs the target and the scanners in Docker with no network, dropped
  capabilities, and resource limits. It only ever runs the code you point it at.
- See `references/config.md` for the `.exhibita.yml` policy file (scanners, ignore
  paths, gate threshold, language, and route declarations for non-Flask apps).
