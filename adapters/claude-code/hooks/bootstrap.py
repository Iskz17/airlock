#!/usr/bin/env python3
"""SessionStart: report airlock readiness.

Stages 0–1 are always available (stdlib only). The heavier stages are opt-in:
set AIRLOCK_AUTO_INSTALL=1 (extras via AIRLOCK_AUTO_INSTALL_EXTRAS, default
`promptguard`) to have airlock install them into its managed venv in the
background on first run — non-blocking and never silent. Otherwise we just stay
in the offline ladder and say so. Always exits 0.
"""
import json
import os
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve()
for _cand in (_HERE.parents[1], _HERE.parents[3]):
    sys.path.insert(0, str(_cand))


def main():
    try:
        from guard_core.scanners import availability
        avail = availability()
    except Exception as e:  # noqa: BLE001
        sys.stdout.write(json.dumps({"systemMessage": "airlock core load issue: %s" % e}))
        return 0

    try:
        from guard_core.scanners import align_status
        align_on = bool(align_status().get("alignment"))
    except Exception:
        align_on = False

    ingress = "Stages 0–2 (invisible-Unicode + heuristics + Prompt Guard 2)" \
        if avail.get("prompt_guard") else \
        "Stage 0 invisible-Unicode + Stage 1 heuristics (offline)"
    action = "Stage 3 task-drift on" if align_on else "Stage 3 task-drift off (no align backend)"
    msg = ("airlock active — ingress: %s; egress exfil guard (Stage 4); MCP vetting (Stage 6); "
           "memory-write guard (Stage 5); %s." % (ingress, action))

    # Opt-in background install of the heavier extras into airlock's managed venv.
    if os.environ.get("AIRLOCK_AUTO_INSTALL", "0").strip().lower() not in ("0", "false", "no", "off", ""):
        try:
            from guard_core.installer import maybe_autostart
            note = maybe_autostart(os.environ.get("AIRLOCK_AUTO_INSTALL_EXTRAS", "all"))
            if note:
                msg += " [auto-install: %s]" % note
        except Exception:
            pass
    elif not avail.get("prompt_guard"):
        msg += " Run /airlock-setup (or set AIRLOCK_AUTO_INSTALL=1) to enable Stage 2."

    sys.stdout.write(json.dumps({"systemMessage": msg}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:  # absolute fail-open
        raise SystemExit(0)
