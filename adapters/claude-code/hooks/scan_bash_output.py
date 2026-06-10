#!/usr/bin/env python3
"""Claude Code PostToolUse adapter for Bash — ingress-scan shell-fetched content.

Content pulled with `curl`/`wget`/etc. through the Bash tool bypasses the
WebFetch PostToolUse scan (a documented ingress gap). This hook closes it: when
the Bash command is a network fetch (guard_core.bash_ingress.is_fetch_command),
it runs the shared guard core over the command's stdout/stderr and, on
detection, re-anchors the agent exactly like the WebFetch scan.

Non-fetch Bash (cat/grep/git/…) is skipped entirely — its output is never
scanned, so there is no false-positive surface and no hot-path cost. Always
exits 0 (a security hook must never break the host session on its own error).
"""
import json
import pathlib
import sys

# Make guard_core importable whether vendored in the plugin root (parents[1], a
# symlink) or used from the repo layout (parents[3]).
_HERE = pathlib.Path(__file__).resolve()
for _cand in (_HERE.parents[1], _HERE.parents[3]):
    sys.path.insert(0, str(_cand))

_MAX_CHARS = 20000  # cap the work per command


def _emit(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def main():
    raw = sys.stdin.read()
    try:
        hook = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        _emit({})
        return 0

    try:
        from guard_core.bash_ingress import is_fetch_command
        from guard_core.config import Config
        from guard_core.trace import extract_bash_output, latest_user_intent
        from guard_core.verdict import assess, reanchor_message
    except Exception as e:  # core import failed -> fail open
        _emit({"systemMessage": "airlock disabled (core import failed: %s)" % e})
        return 0

    cfg = Config.load()
    if not cfg.enabled or not cfg.scan_bash_output:
        _emit({})
        return 0

    command = (hook.get("tool_input") or {}).get("command", "")
    if not is_fetch_command(command):
        # Not a remote fetch — its stdout is not untrusted ingress. Skip.
        _emit({})
        return 0

    text = extract_bash_output(hook.get("tool_response"))
    if not text.strip():
        _emit({})
        return 0
    text = text[:_MAX_CHARS]

    intent = latest_user_intent(hook.get("transcript_path", ""))
    verdict = assess(text, intent=intent, config=cfg)

    if verdict.decision == "allow":
        _emit({})
        return 0

    reanchor = reanchor_message(verdict, intent)
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": reanchor,
        }
    }
    if verdict.decision == "block":
        # PostToolUse reads the blocking decision at the TOP level (decision/reason),
        # not inside hookSpecificOutput — keep both: top-level block feeds `reason`
        # back to the model, additionalContext re-anchors regardless.
        out["decision"] = "block"
        out["reason"] = reanchor
        out["systemMessage"] = "airlock: blocked likely prompt injection in fetched (curl/wget) content."
    _emit(out)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 — absolute fail-open
        sys.stdout.write(json.dumps({"systemMessage": "airlock error: %s" % e}))
        raise SystemExit(0)
