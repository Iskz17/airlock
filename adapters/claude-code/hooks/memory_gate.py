#!/usr/bin/env python3
"""Claude Code PreToolUse adapter for Stage 5 (persistence / memory-write guard).

Before the agent writes to a long-term memory sink (CLAUDE.md, a memory/ dir, a
RAG/knowledge store, ...), re-run the ingress pipeline on the content being
written. If it carries a prompt-injection payload (e.g. naively cached from a
poisoned page), pause the write so it can't persist and re-attack future
sessions (AgentPoison / Morris-II defense).

Matches Write/Edit/MultiEdit/NotebookEdit; only acts when the target path is a
memory sink (so ordinary file edits are untouched). Returns permissionDecision
'ask' (or 'deny' when AIRLOCK_MEMORY_BLOCK=1). Always exits 0 (fail-open).
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


def _written_content(tool, ti):
    """Extract the text being written across Write/Edit/MultiEdit/NotebookEdit."""
    if tool == "Write":
        return str(ti.get("content", "") or "")
    if tool == "Edit":
        return str(ti.get("new_string", "") or "")
    if tool == "MultiEdit":
        edits = ti.get("edits", []) or []
        return "\n".join(str(e.get("new_string", "") or "") for e in edits if isinstance(e, dict))
    if tool == "NotebookEdit":
        return str(ti.get("new_source", "") or "")
    return ""


def main():
    raw = sys.stdin.read()
    try:
        hook = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        _emit({})
        return 0

    try:
        from guard_core.config import Config
        from guard_core.memory_guard import assess_memory_write, is_memory_target
    except Exception:
        _emit({})
        return 0

    if not Config.load().enabled or not _truthy_default("AIRLOCK_STAGE5", True):
        _emit({})
        return 0

    tool = hook.get("tool_name", "")
    ti = hook.get("tool_input", {}) or {}
    path = ti.get("file_path") or ti.get("notebook_path") or ti.get("path") or ""

    if not is_memory_target(path):
        _emit({})
        return 0

    content = _written_content(tool, ti)
    if not content.strip():
        _emit({})
        return 0

    v = assess_memory_write(content, path=path)
    if v.decision == "allow":
        _emit({})
        return 0

    decision = "deny" if _truthy("AIRLOCK_MEMORY_BLOCK") else "ask"
    detail = "; ".join(v.reasons[:3]) or "prompt-injection signals in content"
    extra = (" Decoded hidden text: %r." % v.smuggled_payload) if v.smuggled_payload else ""
    _emit({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason":
            "airlock memory guard: refusing to persist likely-poisoned content to '%s' — %s.%s "
            "Persisted injection re-attacks every future session." % (path, detail, extra),
    }})
    return 0


def _truthy_default(name, default):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "no", "off", "")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:  # absolute fail-open
        sys.stdout.write("{}")
        raise SystemExit(0)
