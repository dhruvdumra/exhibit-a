"""Black-box oracle driver: decide, by observation, whether a bug is present.

Runs on the host and drives a target app over HTTP (the app is started by the
runtime adapter). These are the same techniques a DAST scanner uses, so they need
nothing planted in the target:

  signature : a crafted input makes a known system string appear (e.g. /etc/passwd)
  reflect   : input is returned unescaped
  expr      : a server-side expression is evaluated
  diff      : a boolean-true vs boolean-false input produce different responses
  time      : an input that sleeps delays the response

An oracle reports only what it observed; the orchestrator interprets the verdict.
"""

from __future__ import annotations

import re
import time
import urllib.error
import urllib.parse
import urllib.request


def send_request(base: str, plan: dict, value: str) -> tuple[int, str, float]:
    """Send one request carrying `value`; return (status, body, elapsed_seconds)."""
    path = plan["path"]
    send_as = plan.get("send_as", "query")
    url = base + path
    data = None
    headers = {}
    if send_as == "raw_body":
        data = value.encode()
        headers["Content-Type"] = plan.get("content_type", "application/xml")
    elif send_as == "form":
        data = urllib.parse.urlencode({plan.get("param", "q"): value}).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif send_as == "path":
        url = base + path.replace("{value}", urllib.parse.quote(value, safe=""))
    else:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode({plan.get("param", "q"): value})
    req = urllib.request.Request(url, data=data, method=plan.get("method", "GET"), headers=headers)
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), time.time() - start
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), time.time() - start
    except Exception as e:  # noqa: BLE001 - network/launch errors are a non-result, not a crash
        return 0, f"__request_error__: {e}", time.time() - start


def run_oracles(base: str, plan: dict, benign_value: str) -> tuple[bool, str, str]:
    """Return (confirmed, which_oracle, evidence) — the first oracle that fires."""
    for chk in plan.get("checks", []):
        kind = chk["type"]
        if kind == "signature":
            _, body, _ = send_request(base, plan, chk["payload"])
            if re.search(chk["regex"], body):
                return True, "signature", f"response matched /{chk['regex']}/"
        elif kind == "expr":
            _, body, _ = send_request(base, plan, chk["payload"])
            if chk["expected"] in body:
                return True, "expr", f"server evaluated the expression to {chk['expected']}"
        elif kind == "reflect":
            _, body, _ = send_request(base, plan, chk["payload"])
            if chk["needle"] in body:
                return True, "reflect", "input reflected without escaping"
        elif kind == "diff":
            confirmed, evidence = _diff_oracle(base, plan, chk)
            if confirmed:
                return True, "diff", evidence
        elif kind == "time":
            confirmed, evidence = _time_oracle(base, plan, chk, benign_value)
            if confirmed:
                return True, "time", evidence
    return False, "", "no oracle fired"


def _diff_oracle(base: str, plan: dict, chk: dict) -> tuple[bool, str]:
    """Boolean-based: a true vs false condition changes the response.

    The payload strings are removed from each body before comparing, so an endpoint
    that merely echoes its input is not mistaken for an injectable one.
    """
    true_payload, false_payload = chk["true_payload"], chk["false_payload"]
    _, body_t, _ = send_request(base, plan, true_payload)
    _, body_f, _ = send_request(base, plan, false_payload)
    norm_t = body_t.replace(true_payload, "")
    norm_f = body_f.replace(false_payload, "")
    if norm_t != norm_f and abs(len(norm_t) - len(norm_f)) > 8:
        return True, "true/false conditions produced different responses"
    return False, ""


def _time_oracle(base: str, plan: dict, chk: dict, benign_value: str) -> tuple[bool, str]:
    """Time-based: an input that sleeps delays the response well past the baseline."""
    delay = chk.get("delay_s", 5)
    _, _, baseline = send_request(base, plan, benign_value)
    _, _, slow = send_request(base, plan, chk["payload"])
    if slow >= delay * 0.6 and (slow - baseline) >= delay * 0.5:
        return True, f"payload delayed the response by {slow - baseline:.1f}s"
    return False, ""
