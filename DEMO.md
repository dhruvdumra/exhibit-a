# Demo runbook

## Before you present
- Docker Desktop running; model pulled (`ollama pull gemma4:e4b`); sandbox image built
  (`docker build -t exhibita-sandbox:latest sandbox/`).
- Warm the model once so there's no cold-load pause on stage:
  `ollama run gemma4:e4b "ok"` then exit.
- For the cloud/Action parts, `GEMINI_API_KEY` set (env locally; repo secret in CI).

## 1. The offline proof (headline — do this in airplane mode)
```bash
exhibita verify demo/vulnerable_app --backend ollama
```
Shows: scanners → Gemma triage → each critical **Exploited → Patched → Blocked →
Still works**, 5 classes proven, and **BUILD GATE: FAILED** (exit 1). Nothing leaves
the laptop. Say: *"Offline isn't the fallback — it's the fast path."*

## 2. Multimodal threat model (Gemma vision)
```bash
exhibita threat-model path/to/whiteboard.jpg --backend ollama
```
Point the camera at a real architecture sketch; Gemma returns specific threats with
suggested checks. (Images also work on `--backend gemini` if you prefer.)

## 3. The demo PR (one-click fixes + gate in GitHub)
The Action only posts inline fixes on lines that are **in the PR diff**, so the demo
PR must touch a flagged line.

1. Branch: `git checkout -b demo/sql-injection`
2. Edit the flagged SQL line in `demo/vulnerable_app/app.py` (keep the bug — just make
   the line change so it lands in the diff), e.g. add a trailing comment:
   ```python
   query = "SELECT owner, body FROM notes WHERE owner = '%s'" % owner  # demo
   ```
3. `git commit -am "demo: tweak notes query"` and push the branch.
4. Open a PR **from the branch, not a fork** (forks don't get the secret).
5. The Action comments inline with a one-click **Commit suggestion**, uploads SARIF to
   the Security tab, and the check **fails** because the SQLi is proven. The merge
   button stays blocked until the fix is committed.

> On a PR the Action scopes triage and proof to the files you changed (it diffs
> against the PR base), so a normal PR is fast and only the touched vulnerability is
> re-proven. A full-repo pass is what you'd run on a schedule or on merge to main.

> Run the PR once before judging so the comment is already there even if the API is
> busy; re-run live only if it's responsive.

## Talking points (honest)
- **vs scanners:** they give a wall of alerts; we prove which are real and hand a
  tested one-click fix.
- **vs AI pentesters (Strix/Shannon):** they prove the app is hackable (pentester);
  we prove the *fix* works, in the PR, on a 4-bit open model offline (reviewer).
- **CodeMender (DeepMind, the Gemma track sponsor):** closest idea — prove-then-patch —
  but research-only and cloud. We bring that loop to everyone with Gemma.
- **Honesty:** we prove bugs on self-contained web apps it can run; generalizing the
  proof to any framework/runtime is the roadmap. Say what's proven vs explained.
- **Benchmark:** see `BENCHMARK.md` — on Juice Shop, 11 of 26 server-side alerts are in
  classes ExhibitA can prove.
