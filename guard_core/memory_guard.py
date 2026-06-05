"""Stage 5 — persistence / memory-write guard.

Indirect-injection payloads that survive a single turn are dangerous; ones that
get written into long-term memory / a RAG store are *persistent* — they re-attack
every future session and can self-replicate (AgentPoison; Morris-II). The defense
is symmetric with ingress: before content is committed to memory, re-run the
ingress pipeline (Stages 0–2) on it and refuse to persist a poisoned write.

This module decides (a) whether a write *target* is a memory/RAG sink, and
(b) whether the *content* being written is poisoned. It reuses verdict.assess,
so detection is single-sourced with ingress. Offline; never raises.

Memory persists, so the default posture is stricter than transient ingress: any
detection (flag or block) is surfaced; whether the adapter asks or denies is its
policy (Claude Code gate defaults to 'ask', deny via AIRLOCK_MEMORY_BLOCK=1).
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass

from .config import Config
from .verdict import assess

# Default sinks treated as long-term memory on Claude Code (case-insensitive,
# matched against the full path and the basename). Override/add with
# AIRLOCK_MEMORY_PATHS (os.pathsep- or comma-separated fnmatch globs).
_DEFAULT_MEMORY_GLOBS = [
    "*/CLAUDE.md", "CLAUDE.md", "*/CLAUDE.local.md",
    "*/memory/*", "*/memories/*", "*MEMORY*.md",
    "*/.claude/*memory*", "*/rag/*", "*/knowledge/*",
]


@dataclass
class MemoryVerdict:
    is_memory_target: bool
    decision: str            # allow | flag | block
    techniques: list
    reasons: list
    smuggled_payload: str
    clean_text: str          # poison-stripped content (for harnesses that can rewrite)
    severity: int


def _globs():
    raw = os.environ.get("AIRLOCK_MEMORY_PATHS", "")
    extra = [g.strip() for part in raw.split(os.pathsep) for g in part.split(",") if g.strip()]
    return _DEFAULT_MEMORY_GLOBS + extra


def is_memory_target(path: str) -> bool:
    """True if `path` looks like a long-term memory / RAG sink."""
    if not path:
        return False
    p = path.replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    low_p, low_b = p.lower(), base.lower()
    for g in _globs():
        gl = g.lower()
        if fnmatch.fnmatch(low_p, gl) or fnmatch.fnmatch(low_b, gl):
            return True
    return False


def assess_memory_write(content, path="", config: Config = None, force: bool = False) -> MemoryVerdict:
    """Vet a pending memory write. If `path` is not a memory sink and not `force`,
    returns a benign allow (is_memory_target=False) so non-memory writes are cheap."""
    target = force or is_memory_target(path)
    if not target:
        return MemoryVerdict(False, "allow", [], [], "", content or "", 0)

    v = assess(content or "", config=config)
    return MemoryVerdict(
        is_memory_target=True,
        decision=v.decision,
        techniques=v.techniques,
        reasons=v.reasons,
        smuggled_payload=v.smuggled_payload,
        clean_text=v.clean_text,
        severity=v.severity,
    )
