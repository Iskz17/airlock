#!/usr/bin/env python3
"""Claude Code PreToolUse adapter for Stage 3 (AlignmentCheck / task-drift).

Before a *sensitive* tool runs (outbound or state-changing), reconstruct the
conversation trace and ask LlamaFirewall's AlignmentCheck whether the agent is
still serving the user's original request — or has been hijacked toward a
goal the user never asked for (the indirect-injection failure mode). On
misalignment, return permissionDecision 'ask' (or 'deny' when
AIRLOCK_ALIGN_BLOCK=1) so the action pauses for the user.

Stage 3 needs an LLM judge (Together online / local Ollama). When no backend is
configured the hook is a SILENT NO-OP, so the default offline install is
unchanged. Always exits 0 (fail-open).
"""
import json
import os
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve()
for _cand in (_HERE.parents[1], _HERE.parents[3]):
    sys.path.insert(0, str(_cand))

# Tools considered sensitive enough to gate by default (outbound / execution).
_DEFAULT_SENSITIVE = "Bash,WebFetch,WebSearch"


def _emit(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def _truthy(name):
    return os.environ.get(name, "0").strip().lower() not in ("0", "false", "no", "off", "")


def _sensitive_tools():
    raw = os.environ.get("AIRLOCK_SENSITIVE_TOOLS", _DEFAULT_SENSITIVE)
    return {t.strip() for t in raw.replace("|", ",").split(",") if t.strip()}


def main():
    raw = sys.stdin.read()
    try:
        hook = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        _emit({})
        return 0

    try:
        from guard_core.config import Config
        from guard_core.scanners import align, align_available
        from guard_core.trace import build_trace
    except Exception:
        _emit({})
        return 0

    if not Config.load().enabled:
        _emit({})
        return 0

    tool = hook.get("tool_name", "")
    if tool and tool not in _sensitive_tools():
        _emit({})
        return 0

    # Self-gate: if Stage 3 can't actually run (no deps/backend), do nothing.
    if not align_available():
        _emit({})
        return 0

    steps = build_trace(hook.get("transcript_path", ""))
    if not steps:
        _emit({})
        return 0

    # Append the pending action so AlignmentCheck judges the about-to-run step.
    ti = hook.get("tool_input", {}) or {}
    try:
        rendered = json.dumps(ti, ensure_ascii=False)
    except (TypeError, ValueError):
        rendered = str(ti)
    if len(rendered) > 300:
        rendered = rendered[:297] + "..."
    steps.append({"role": "assistant",
                  "content": "[about to call %s with %s]" % (tool, rendered)})

    result = align(steps)
    if result is None or result.decision == "allow":
        _emit({})
        return 0

    decision = "deny" if _truthy("AIRLOCK_ALIGN_BLOCK") else "ask"
    reason = result.detail or "the pending action does not appear to serve the user's original request"
    _emit({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason":
            "airlock alignment guard (task drift): %s. Confirm this %s call is what you intended."
            % (reason, tool),
    }})
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:  # absolute fail-open
        sys.stdout.write("{}")
        raise SystemExit(0)
