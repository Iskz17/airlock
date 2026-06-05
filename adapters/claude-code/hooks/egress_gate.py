#!/usr/bin/env python3
"""Claude Code egress adapter (Stage 4 — exfiltration guard).

PreToolUse on WebFetch/Bash: inspect the outbound URL/command for secrets or
data-exfiltration structure; if found, return permissionDecision 'ask' (or
'deny' when AIRLOCK_EGRESS_BLOCK=1) so a hijacked send pauses for the user.

Stop: scan the final assistant message for secrets/PII and Markdown exfil sinks
and warn via systemMessage (Claude Code can't rewrite the reply — advisory only).

Always exits 0 (fail-open).
"""
import json
import os
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve()
for _cand in (_HERE.parents[1], _HERE.parents[3]):
    sys.path.insert(0, str(_cand))


def _emit(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def _truthy(name):
    return os.environ.get(name, "0").strip().lower() not in ("0", "false", "no", "off", "")


def main():
    raw = sys.stdin.read()
    try:
        hook = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        _emit({})
        return 0

    try:
        from guard_core.config import Config
        from guard_core.egress import assess_outbound
        from guard_core.trace import latest_assistant_text
    except Exception:
        _emit({})
        return 0

    if not Config.load().enabled:
        _emit({})
        return 0

    event = hook.get("hook_event_name", "")

    # --- Stop: advisory scan of the outgoing reply ---------------------------
    if event == "Stop":
        text = latest_assistant_text(hook.get("transcript_path", ""))
        if not text.strip():
            _emit({})
            return 0
        ev = assess_outbound(text=text)
        if ev.decision == "allow":
            _emit({})
            return 0
        labels = ", ".join(sorted({f.label for f in ev.findings}))
        _emit({"systemMessage":
               "airlock egress: the reply may contain data leaving the agent (%s). "
               "Review before sharing." % labels})
        return 0

    # --- PreToolUse: gate outbound tools -------------------------------------
    tool = hook.get("tool_name", "")
    ti = hook.get("tool_input", {}) or {}
    if tool == "WebFetch":
        ev = assess_outbound(url=ti.get("url", ""))
    elif tool == "Bash":
        ev = assess_outbound(command=ti.get("command", ""))
    else:
        ev = assess_outbound(text=json.dumps(ti))

    try:
        ask_threshold = int(os.environ.get("AIRLOCK_EGRESS_ASK_THRESHOLD", "2"))
    except ValueError:
        ask_threshold = 2

    if ev.severity >= ask_threshold:
        decision = "deny" if _truthy("AIRLOCK_EGRESS_BLOCK") else "ask"
        detail = "; ".join("%s (%s)" % (f.label, f.snippet) for f in ev.findings[:4])
        _emit({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason":
                "airlock egress guard: possible data exfiltration — %s" % detail,
        }})
        return 0

    _emit({})
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:  # absolute fail-open
        sys.stdout.write("{}")
        raise SystemExit(0)
