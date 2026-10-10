# Security Policy

## Reporting a vulnerability in ExhibitA

If you find a security issue in ExhibitA itself (not in a project it scans), please
report it privately rather than opening a public issue:

- Use GitHub's **Private vulnerability reporting** (Security → Report a vulnerability), or
- email the maintainer listed on the repository.

Please include steps to reproduce and the affected version. We aim to acknowledge
reports within a few days.

## Scope

In scope: the ExhibitA CLI, engine, backends, sandbox/runtime, GitHub Action, MCP
server, and the Agent Skill.

Out of scope: **`demo/vulnerable_app/`** is intentionally vulnerable and exists only
as a test target. Its flaws are deliberate — do not report them, and never deploy it.

## How ExhibitA runs untrusted code

ExhibitA runs scanners and the target application in Docker with no network, dropped
capabilities (`--cap-drop ALL`), `no-new-privileges`, a read-only root where possible,
and memory/pid limits. It only ever runs the code you point it at. Even so, treat the
machine running ExhibitA as one that executes the target's code, and prefer a
disposable CI runner or VM when scanning code you do not trust.

## Secrets

ExhibitA never sends source to a third party when run with the offline (`ollama`)
backend. With the `gemini` backend, code snippets are sent to the Gemini API for
triage — do not use that backend on code you may not share externally. Secret-scanner
matches are redacted before they reach any model or report.

## Supported versions

This is a hackathon-stage project (0.x). Only the latest `main` is supported.
