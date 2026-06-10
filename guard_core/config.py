"""Runtime configuration via environment variables, plus a fail-open helper.

Security tooling must never break the host agent because of its own bug, so the
adapters wrap their work and fall back to "do nothing" on error.
"""
from __future__ import annotations

import functools
import os
import sys
from dataclasses import dataclass

_FALSEY = ("0", "false", "no", "off", "")


def _flag(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() not in _FALSEY


@dataclass
class Config:
    enabled: bool
    stage0: bool
    stage1: bool
    stage2: bool
    strip_zwj: bool
    nfkc: bool
    confusables: bool
    scan_bash_output: bool  # ingress-scan stdout of curl/wget/etc. Bash fetches
    block_threshold: int   # combined severity at/above which we hard-block

    @classmethod
    def load(cls) -> "Config":
        try:
            threshold = int(os.environ.get("AIRLOCK_BLOCK_THRESHOLD", "3"))
        except ValueError:
            threshold = 3
        return cls(
            enabled=not _flag("AIRLOCK_DISABLE", False),
            stage0=_flag("AIRLOCK_STAGE0", True),
            stage1=_flag("AIRLOCK_STAGE1", True),
            stage2=_flag("AIRLOCK_STAGE2", True),
            strip_zwj=_flag("AIRLOCK_STRIP_ZWJ", False),
            nfkc=_flag("AIRLOCK_NFKC", True),
            confusables=_flag("AIRLOCK_CONFUSABLES", False),
            scan_bash_output=_flag("AIRLOCK_SCAN_BASH_OUTPUT", True),
            block_threshold=threshold,
        )


def log(msg: str) -> None:
    sys.stderr.write("[airlock] %s\n" % msg)


def fail_open(default):
    """Decorator: on any exception, log to stderr and return `default`
    (called if it's a callable, e.g. `list`)."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            try:
                return fn(*a, **k)
            except Exception as e:  # noqa: BLE001
                log("%s failed open: %s" % (fn.__name__, e))
                return default() if callable(default) else default
        return wrapper
    return deco
