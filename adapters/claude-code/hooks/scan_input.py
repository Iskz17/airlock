#!/usr/bin/env python3
"""Claude Code PostToolUse adapter for WebFetch / WebSearch.

Reads the hook JSON on stdin, runs the shared guard core over the fetched
content, and on detection returns a high-priority system reminder that
quarantines the content and re-anchors the agent to the user's task.

Claude Code hooks cannot rewrite tool output, so this re-anchors (and, for
high-confidence hits, signals a block) rather than byte-stripping. Always
exits 0 — a security hook must never break the host session on its own error.
"""
import json
import pathlib
import sys

# Make guard_core importable whether it's vendored in the plugin root
# (parents[1], e.g. a symlink) or used from the repo layout (parents[3]).
_HERE = pathlib.Path(__file__).resolve()
for _cand in (_HERE.parents[1], _HERE.parents[3]):
    sys.path.insert(0, str(_cand))

_MAX_CHARS = 20000  # cap the work per fetch


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
        from guard_core.config import Config
        from guard_core.trace import extract_text, latest_user_intent
        from guard_core.verdict import assess, reanchor_message
    except Exception as e:  # core import failed -> fail open
        _emit({"systemMessage": "airlock disabled (core import failed: %s)" % e})
        return 0

    cfg = Config.load()
    if not cfg.enabled:
        _emit({})
        return 0

    text = extract_text(hook.get("tool_response"))
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
        out["systemMessage"] = "airlock: blocked likely prompt injection in fetched content."
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
