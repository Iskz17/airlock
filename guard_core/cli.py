"""Harness-agnostic CLI: read text on stdin, print a verdict as JSON.

Usage:
  echo "<text>" | python -m guard_core.cli
  python -m guard_core.cli --json     # stdin is {"text": "...", "intent": "..."}
  python -m guard_core.cli --egress   # scan stdin as outbound content (Stage 4)
  python -m guard_core.cli --mcp      # vet installed MCP servers (Stage 6); ignores stdin
  python -m guard_core.cli --align    # task-drift judge (Stage 3); stdin = {"steps":[{role,content}]}
  python -m guard_core.cli --image PATH  # OCR an image + ingress scan (Stage 2b)

Adapters (Claude Code hook, openclaw plugin, /scan command) call this or import
guard_core directly; the harness-specific I/O lives in the adapter, not here.
"""
from __future__ import annotations

import json
import sys

from .config import Config
from .verdict import assess, reanchor_message


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    as_json = "--json" in argv

    if "--image" in argv:
        i = argv.index("--image")
        path = argv[i + 1] if i + 1 < len(argv) else ""
        from .multimodal import scan_image
        r = scan_image(path)
        out = {
            "available": r.available,
            "backend": r.backend,
            "decision": r.decision,
            "severity": r.severity,
            "techniques": r.techniques,
            "reasons": r.reasons,
            "smuggled_payload": r.smuggled_payload,
            "extracted_text": r.extracted_text[:2000],
            "error": r.error,
        }
        sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
        return 0 if r.decision == "allow" else 2

    if "--mcp" in argv:
        from .mcp_vetting import vet
        r = vet()
        out = {
            "decision": r.decision,
            "severity": r.severity,
            "scanner": r.scanner,
            "servers_scanned": r.servers_scanned,
            "tools_scanned": r.tools_scanned,
            "findings": [
                {"server": f.server, "tool": f.tool, "kind": f.kind,
                 "label": f.label, "snippet": f.snippet, "weight": f.weight}
                for f in r.findings
            ],
            "notes": r.notes,
        }
        sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
        return 0 if r.decision == "allow" else 2

    if "--align" in argv:
        # Stage 3 task-drift verifier — handy for confirming a local Ollama judge
        # works end-to-end (set AIRLOCK_ALIGN_BACKEND=ollama + AIRLOCK_OLLAMA_MODEL).
        from .scanners import align, align_status
        raw = sys.stdin.read()
        steps = []
        try:
            obj = json.loads(raw) if raw.strip() else {}
            steps = obj.get("steps") or obj.get("trace") or []
        except json.JSONDecodeError:
            steps = []
        status = align_status()
        r = align(steps) if steps else None
        out = {
            "backend": status.get("backend"),
            "available": status.get("alignment"),
            "model": status.get("model"),
            "decision": (r.decision if r else None),
            "score": (r.score if r else None),
            "reason": (r.detail if r else None),
        }
        sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
        return 0 if (r is None or r.decision == "allow") else 2

    raw = sys.stdin.read()

    text, intent = raw, ""
    if as_json:
        try:
            obj = json.loads(raw)
            text = obj.get("text", "")
            intent = obj.get("intent", "")
        except json.JSONDecodeError:
            text = raw

    if "--egress" in argv:
        from .egress import assess_outbound
        ev = assess_outbound(text=text)
        out = {
            "decision": ev.decision,
            "severity": ev.severity,
            "findings": [
                {"kind": f.kind, "label": f.label, "snippet": f.snippet, "weight": f.weight}
                for f in ev.findings
            ],
            "sanitized_text": ev.sanitized_text,
        }
        sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
        return 0 if ev.decision == "allow" else 2

    cfg = Config.load()
    v = assess(text, intent=intent, config=cfg)
    out = {
        "decision": v.decision,
        "severity": v.severity,
        "techniques": v.techniques,
        "reasons": v.reasons,
        "smuggled_payload": v.smuggled_payload,
        "stage2_available": v.stage2_available,
        "clean_text": v.clean_text,
        "reanchor": reanchor_message(v, intent) if v.decision != "allow" else "",
    }
    sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    return 0 if v.decision == "allow" else 2  # nonzero on detection, for shell use


if __name__ == "__main__":
    raise SystemExit(main())
