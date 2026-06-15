"""Thin HTTP sidecar exposing the guard core to non-Python harnesses.

The openclaw adapter is TypeScript; rather than reimplement Stages 0/1/4 in TS,
it calls this stdlib-only sidecar over loopback HTTP. Offline, dependency-free,
single-purpose. Start it with:

    python3 -m guard_core.server            # binds 127.0.0.1:8787
    AIRLOCK_SIDECAR_PORT=9000 python3 -m guard_core.server

Endpoints (all POST JSON unless noted):
    GET  /health        -> {"ok": true, "stages": {...}}
    POST /ingress       {text, intent?}            -> ingress verdict (+ clean_text, reanchor)
    POST /egress        {text?, url?, command?}    -> egress verdict (+ sanitized_text)
    POST /align         {steps:[{role,content}]}   -> {available, decision?, score?, detail?}
    POST /mcp           {tools?, config_paths?}    -> mcp vet result

Every handler fails *closed-to-allow*: on internal error it returns HTTP 500 and
the caller treats an unreachable/erroring sidecar as "allow" (fail-open) — a
guard must never break the host agent.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from guard_core.config import Config
from guard_core.egress import assess_outbound
from guard_core.verdict import assess, reanchor_message


def _ingress(payload):
    text = payload.get("text", "") or ""
    intent = payload.get("intent", "") or ""
    v = assess(text, intent=intent, config=Config.load())
    return {
        "decision": v.decision,
        "severity": v.severity,
        "techniques": v.techniques,
        "reasons": v.reasons,
        "smuggled_payload": v.smuggled_payload,
        "stage2_available": v.stage2_available,
        "clean_text": v.clean_text,
        "reanchor": reanchor_message(v, intent) if v.decision != "allow" else "",
    }


def _egress(payload):
    ev = assess_outbound(
        text=payload.get("text"),
        url=payload.get("url"),
        command=payload.get("command"),
    )
    return {
        "decision": ev.decision,
        "severity": ev.severity,
        "sanitized_text": ev.sanitized_text,
        "findings": [
            {"kind": f.kind, "label": f.label, "snippet": f.snippet, "weight": f.weight}
            for f in ev.findings
        ],
    }


def _align(payload):
    from guard_core.scanners import align, align_available
    if not align_available():
        return {"available": False, "decision": "allow"}
    r = align(payload.get("steps", []) or [])
    if r is None:
        return {"available": False, "decision": "allow"}
    return {"available": True, "decision": r.decision, "score": r.score, "detail": r.detail}


def _mcp(payload):
    from guard_core.mcp_vetting import vet
    r = vet(tools=payload.get("tools"), config_paths=payload.get("config_paths"))
    return {
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


_ROUTES = {"/ingress": _ingress, "/egress": _egress, "/align": _align, "/mcp": _mcp}


def _health():
    from guard_core.scanners import availability, align_status
    cfg = Config.load()
    return {"ok": True, "stages": {
        "ingress": {"stage0": cfg.stage0, "stage1": cfg.stage1, "stage2": cfg.stage2},
        "prompt_guard": availability(),
        "alignment": align_status(),
        "enabled": cfg.enabled,
    }}


_MAX_BODY = 8 * 1024 * 1024  # 8 MB cap on request bodies (loopback, but bound it)


class _Handler(BaseHTTPRequestHandler):
    server_version = "airlock-sidecar/1.0"
    timeout = 15  # per-request socket timeout so a stalled client can't pin a thread

    def log_message(self, *a):  # keep the sidecar quiet
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/") in ("/health", ""):
            try:
                self._send(200, _health())
            except Exception as e:  # noqa: BLE001
                self._send(500, {"error": str(e)})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        route = _ROUTES.get(self.path.rstrip("/"))
        if route is None:
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length > _MAX_BODY:
                self._send(413, {"error": "request too large"})
                return
            raw = self.rfile.read(length) if length else b""
            payload = json.loads(raw or b"{}")
            if not isinstance(payload, dict):
                payload = {}
            self._send(200, route(payload))
        except Exception as e:  # noqa: BLE001 — surface as 500; caller fails open
            self._send(500, {"error": str(e)})


def serve(host=None, port=None):
    host = host or os.environ.get("AIRLOCK_SIDECAR_HOST", "127.0.0.1")
    if port is None:
        try:
            port = int(os.environ.get("AIRLOCK_SIDECAR_PORT", "8787"))
        except ValueError:
            port = 8787
    httpd = ThreadingHTTPServer((host, port), _Handler)
    return httpd


def _maybe_prewarm():
    """Warm the Stage 2 model in a background daemon thread at sidecar boot so the
    first real /ingress doesn't cold-load it on the request path and fail open
    (the openclaw client cap is shorter than a cold model load). Off the request
    path, never blocks serving, and a no-op when Stage 2 is off/uninstalled.
    Opt out with AIRLOCK_PREWARM=0."""
    if os.environ.get("AIRLOCK_PREWARM", "1").strip().lower() in ("0", "off", "false", "no"):
        return

    def _warm():
        import sys
        try:
            from guard_core.scanners import prewarm
            info = prewarm()
            if info.get("prewarmed"):
                sys.stderr.write("[airlock] stage2 prewarmed (%s)\n"
                                 % (info.get("model") or info.get("backend") or "open"))
        except Exception:
            pass  # warming is best-effort; the hot path still works cold (fails open)

    threading.Thread(target=_warm, daemon=True).start()


def main():
    httpd = serve()
    host, port = httpd.server_address
    import sys
    sys.stderr.write("[airlock] sidecar listening on http://%s:%s\n" % (host, port))
    _maybe_prewarm()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
