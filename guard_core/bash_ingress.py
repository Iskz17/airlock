"""Ingress for shell-fetched content (closes the curl/wget Bash bypass).

The Claude Code WebFetch/WebSearch PostToolUse scan never sees content pulled
with `curl`/`wget`/etc. through the **Bash** tool — a documented ingress gap: an
injection in a `curl`'d page reaches the model unguarded. `is_fetch_command`
recognizes those commands so the Bash PostToolUse hook can ingress-scan that
stdout exactly like a WebFetch (Stage 0–2 + re-anchor).

Detection is deliberately HIGH-PRECISION — true only when **both**:
  1. a known network-fetch CLI is invoked as a *command word* (start of the
     line, after a shell separator/pipe/`$(`, allowing `sudo`/`env`/`VAR=val`
     prefixes and an absolute/relative path), and
  2. an explicit `http(s)`/`ftp(s)://` URL is present.

So ordinary Bash (`cat`, `grep`, `git log`, `echo https://x`) never matches and
its (often huge, pattern-laden) stdout is not scanned — no false positives, no
hot-path cost. Known residual gaps (documented, not silently covered): language
one-liners that fetch (`python -c "...urlopen..."`, `node -e "...fetch..."`) and
scheme-less hosts (`curl example.com`) are not matched; defense-in-depth (egress
guard, alignment) still applies to those.
"""
from __future__ import annotations

import re

# Network-fetch CLIs whose stdout/body is remote content the WebFetch ingress
# scan never sees. `git`/`fetch`/`scp` are intentionally excluded (their content
# lands in files/.git, not the model's context, and they over-match).
_FETCH_TOOLS = (
    "curl", "wget2", "wget", "xh", "httpie", "aria2c", "aria2",
    "lynx", "elinks", "links2", "links", "w3m", "lwp-request", "lwp-download",
)

# A command word: line start, or after a shell separator (`; | & \n ( ) { } `,
# `&&`, `||`, backtick, `$(`), allowing sudo/env/VAR=val prefixes and a path.
_SEP = r"(?:\A|[\n;|&`(){}]|\|\||&&|\$\()"
_PREFIX = (
    r"(?:\s*(?:sudo|env|nohup|time|command|builtin|exec|then|do|else)\s+"
    r"|\s*[A-Za-z_]\w*=(?:\"[^\"]*\"|'[^']*'|\S*)\s+)*"
)
_PATH = r"(?:[\w./@~+-]*/)?"  # optional absolute/relative path before the binary
_TOOL_RE = re.compile(
    _SEP + r"\s*" + _PREFIX + _PATH + r"(?:" + "|".join(_FETCH_TOOLS) + r")"
    r"(?=\s|\Z|[;|&'\"])",  # tool followed by whitespace/end/sep — not `-`/letters
    re.IGNORECASE,
)
_URL_RE = re.compile(r"(?:https?|ftps?)://[^\s'\"`<>|)]+", re.IGNORECASE)


def fetch_urls(command: str) -> list:
    """The explicit URLs in a command (for re-anchor messaging). Never raises."""
    if not command:
        return []
    return _URL_RE.findall(command)


def is_fetch_command(command: str) -> bool:
    """True iff `command` fetches remote content over HTTP/FTP via a known CLI,
    so its Bash output should be ingress-scanned. High-precision; never raises."""
    if not command or "://" not in command:
        return False
    if not _URL_RE.search(command):
        return False
    return bool(_TOOL_RE.search(command))
