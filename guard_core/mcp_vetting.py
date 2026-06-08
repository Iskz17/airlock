"""Stage 6 — MCP supply-chain guard (tool-poisoning detection).

An installed MCP server can attack the agent through the *metadata* it serves:
a tool **description** is injected straight into the model's context, so a
malicious server hides instructions there — e.g. a `<IMPORTANT>` block telling
the assistant to read `~/.ssh/id_rsa` and pass it as a parameter, "do not tell
the user", or invisible-Unicode smuggling. This is the MCP analogue of indirect
prompt injection (cf. Invariant Labs' tool-poisoning research).

Two independent layers, both fail-open and Python 3.9-safe:

  * **Offline (default, always on):** every tool description is re-fed through
    Stage 0 (`normalize` — invisible Unicode) + Stage 1 (`heuristics`) plus a set
    of MCP-specific poison signatures. Server *launch commands* from the config
    are also checked for remote-code-execution install vectors. No network, no
    extra deps — this is the part the test-suite verifies.
  * **`mcp-scan` (opt-in, `AIRLOCK_MCP_SCAN=1`):** shell out to Invariant's
    `mcp-scan` (installed, or via `uvx`) for its classifier-backed analysis. It
    connects to the servers and uses a remote API, so it stays off the default
    hot path. Its output schema varies by version, so we parse it defensively
    and — crucially — re-feed any tool descriptions it surfaces back through the
    offline detector, which is schema-independent.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from dataclasses import dataclass, field

from guard_core.heuristics import scan as _heuristic_scan
from guard_core.normalize import normalize

# --- MCP-specific tool-poisoning signatures ----------------------------------
# Complement the generic Stage-1 heuristics with patterns peculiar to a
# *tool description* that is secretly addressing the assistant.
_MCP_PATTERNS = [
    ("hidden_directive_tag", 3,
     r"<\s*/?\s*(important|secret|system|instructions?|ai|assistant|admin)\s*>"),
    ("conceal_from_user", 3,
     r"\b(do\s+not|don'?t|never|without)\b[^.\n]{0,40}\b(tell|inform|mention|reveal|"
     r"show|notify|alert|disclos\w*|let)\b[^.\n]{0,25}\b(the\s+)?(user|human|operator)\b"),
    ("read_sensitive_file", 3,
     r"\b(read|open|cat|load|access|include|attach|pass|send|contents?\s+of)\b"
     r"[^.\n]{0,45}(~/?\.ssh|id_rsa|id_ed25519|\.env\b|\.aws/credentials|\.netrc|"
     r"\.git-credentials|secret|credential|private[\s_-]?key|password)"),
    ("tool_precedence_hijack", 2,
     r"\b(before|prior\s+to|always|first|whenever)\b[^.\n]{0,30}\b(using|calling|"
     r"invoking|use|call|run)\b[^.\n]{0,25}\b(any\s+other|every|all|each|this)\b[^.\n]{0,15}\btool"),
    ("side_channel", 2,
     r"\b(side[\s-]?note|by\s+the\s+way|secretly|silently|covertly|quietly|in\s+the\s+background)\b"),
]
_MCP_COMPILED = [(label, weight, re.compile(p, re.IGNORECASE)) for label, weight, p in _MCP_PATTERNS]

# Server *launch command* signatures: fetch-and-execute-remote-code install vectors.
_REMOTE_EXEC_RX = re.compile(
    r"(?i)(curl|wget|fetch)\b[^|&;]*\|\s*(sudo\s+)?(ba|z|d|fi)?sh\b"      # curl ... | sh
    r"|\beval\b\s*[\"'`$(]"                                                # eval "$(...)"
    r"|base64\s+(-d|--decode)\b[^|]*\|\s*(ba)?sh"                          # base64 -d | sh
    r"|\bpython3?\s+-c\b|\bnode\s+-e\b"                                    # inline interpreter
    r"|/dev/tcp/")                                                         # reverse shell


def _clip(s, n=140):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n - 3] + "..."


def _truthy(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "no", "off", "")


@dataclass
class McpFinding:
    server: str
    tool: str
    kind: str        # hidden_unicode | injection | poison_phrase | install_vector | mcp_scan
    label: str
    snippet: str
    weight: int      # 1 weak, 2 strong, 3 severe


@dataclass
class McpVetResult:
    decision: str               # allow | flag | block
    findings: list = field(default_factory=list)
    servers_scanned: int = 0
    tools_scanned: int = 0
    scanner: str = "offline"    # offline | mcp-scan+offline
    notes: list = field(default_factory=list)

    @property
    def severity(self):
        return max([f.weight for f in self.findings], default=0)


# --- offline detection -------------------------------------------------------

def scan_tool_description(description, name="", server=""):
    """Offline poison check of a single tool description. Returns McpFindings."""
    findings = []
    if not description or not str(description).strip():
        return findings
    text = str(description)

    norm = normalize(text)
    if norm.found:
        # Invisible/control characters have no legitimate place in a tool
        # description served to a model — treat as a strong/severe signal.
        snip = norm.smuggled_payload or ("invisible chars: " + ", ".join(norm.techniques))
        findings.append(McpFinding(
            server, name, "hidden_unicode", ",".join(norm.techniques),
            _clip(snip), 3 if norm.high_confidence else 2))

    # Scan the cleaned text plus any decoded smuggled payload.
    scan_text = norm.clean_text
    if norm.smuggled_payload:
        scan_text = scan_text + "\n" + norm.smuggled_payload

    for hit in _heuristic_scan(scan_text):
        findings.append(McpFinding(server, name, "injection", hit.label, hit.snippet, hit.weight))

    for label, weight, rx in _MCP_COMPILED:
        m = rx.search(scan_text)
        if m:
            findings.append(McpFinding(server, name, "poison_phrase", label, _clip(m.group(0)), weight))
    return findings


def scan_tools(tools, server=""):
    """tools: iterable of dicts with 'name' and 'description' (extra keys ignored)."""
    findings = []
    if not tools:
        return findings
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", "") or "")
        desc = t.get("description") or t.get("desc") or ""
        findings.extend(scan_tool_description(desc, name=name, server=server))
        # Some servers smuggle directives in parameter descriptions too.
        schema = t.get("inputSchema") or t.get("input_schema") or {}
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        if isinstance(props, dict):
            for pname, pdef in props.items():
                if isinstance(pdef, dict) and pdef.get("description"):
                    findings.extend(scan_tool_description(
                        pdef["description"], name="%s.%s" % (name, pname), server=server))
    return findings


def _scan_server_def(name, definition):
    """Flag a server *launch command* that fetches and executes remote code."""
    findings = []
    if not isinstance(definition, dict):
        return findings
    parts = [str(definition.get("command", "") or "")]
    args = definition.get("args") or []
    if isinstance(args, list):
        parts.extend(str(a) for a in args)
    cmdline = " ".join(p for p in parts if p)
    if cmdline and _REMOTE_EXEC_RX.search(cmdline):
        findings.append(McpFinding(
            name, "", "install_vector", "remote_code_exec", _clip(cmdline), 2))
    return findings


# --- config discovery --------------------------------------------------------

def _default_config_paths():
    paths = []
    home = os.path.expanduser("~")
    paths.append(os.path.join(home, ".claude.json"))                 # Claude Code (global + per-project)
    paths.append(os.path.join(os.getcwd(), ".mcp.json"))             # project-scoped
    paths.append(os.path.join(
        home, "Library", "Application Support", "Claude",
        "claude_desktop_config.json"))                               # Claude Desktop (macOS)
    extra = os.environ.get("AIRLOCK_MCP_CONFIGS", "")
    paths.extend(p.strip() for p in extra.split(os.pathsep) if p.strip())
    # de-dupe, keep order, keep only existing
    seen, out = set(), []
    for p in paths:
        if p and p not in seen and os.path.isfile(p):
            seen.add(p)
            out.append(p)
    return out


def read_mcp_servers(config_paths=None):
    """Return {server_name: definition} merged across the given config files.

    Handles the Claude Code shape (top-level `mcpServers` plus per-project
    `projects[<cwd>].mcpServers`) and the plain `{mcpServers: {...}}` shape used
    by `.mcp.json` / Claude Desktop. Best-effort; never raises.
    """
    if config_paths is None:
        config_paths = _default_config_paths()
    servers = {}
    for path in config_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for nm, d in (data.get("mcpServers") or {}).items():
            servers.setdefault(nm, d)
        for _proj, pdata in (data.get("projects") or {}).items():
            if isinstance(pdata, dict):
                for nm, d in (pdata.get("mcpServers") or {}).items():
                    servers.setdefault(nm, d)
    return servers


# --- mcp-scan integration (opt-in) -------------------------------------------

def _mcp_scan_cmd(config_paths):
    """Return the argv to invoke mcp-scan, or None if unavailable."""
    base_args = ["scan", "--json"] + list(config_paths)
    if shutil.which("mcp-scan"):
        return ["mcp-scan"] + base_args
    # airlock's managed venv (populated by `/airlock-setup mcp`).
    try:
        from .installer import venv_dir
        for rel in ("bin/mcp-scan", "Scripts/mcp-scan.exe"):
            cand = os.path.join(venv_dir(), rel)
            if os.path.exists(cand):
                return [cand] + base_args
    except Exception:
        pass
    if shutil.which("uvx"):
        return ["uvx", "mcp-scan@latest"] + base_args
    return None


def _collect_mcp_scan_findings(obj, out):
    """Walk mcp-scan's JSON defensively. Two things, schema-tolerantly:

      1. Any dict that looks like a tool ({name, description}) → re-run our own
         offline detector on it (schema-independent).
      2. Any issue/vulnerability/warning entry → surface its message.
    """
    if isinstance(obj, dict):
        name = obj.get("name") or obj.get("tool") or obj.get("tool_name")
        desc = obj.get("description") or obj.get("desc")
        if name and desc:
            out.extend(scan_tool_description(desc, name=str(name), server=str(obj.get("server", ""))))
        # explicit issue records flagged by mcp-scan itself
        status = str(obj.get("status", "") or obj.get("level", "") or obj.get("severity", "")).lower()
        msg = obj.get("message") or obj.get("issue") or obj.get("title") or obj.get("reason")
        flagged = obj.get("verified") is False or any(
            k in status for k in ("fail", "error", "vuln", "warn", "risk", "poison", "high", "critical"))
        if msg and flagged:
            out.append(McpFinding(
                str(obj.get("server", "")), str(name or ""), "mcp_scan",
                status or "issue", _clip(msg), 3 if any(
                    k in status for k in ("high", "critical", "poison")) else 2))
        for v in obj.values():
            _collect_mcp_scan_findings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_mcp_scan_findings(v, out)


def run_mcp_scan(config_paths, timeout=90):
    """Run mcp-scan if enabled & available. Returns (findings, note).

    findings is None when the scan could not run (note explains why). The exact
    output schema is version-dependent and confirmed defensively — see
    _collect_mcp_scan_findings.
    """
    cmd = _mcp_scan_cmd(config_paths)
    if cmd is None:
        return None, "mcp-scan not installed (pip install mcp-scan, or have uvx on PATH)"
    try:
        proc = subprocess.run(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, text=True)
    except subprocess.TimeoutExpired:
        return None, "mcp-scan timed out after %ss" % timeout
    except Exception as e:  # noqa: BLE001 — never let the scanner break us
        return None, "mcp-scan failed to run: %s" % e

    out = (proc.stdout or "").strip()
    findings = []
    try:
        data = json.loads(out)
    except ValueError:
        # Non-JSON (older version / no --json support). Surface stderr/stdout note.
        note = "mcp-scan produced non-JSON output (schema unconfirmed); relying on offline checks"
        return [], note
    _collect_mcp_scan_findings(data, findings)
    return findings, ""


# --- orchestration -----------------------------------------------------------

def vet(tools=None, config_paths=None, use_mcp_scan=None):
    """Vet MCP supply chain.

    tools          optional pre-fetched [{name, description, ...}] to scan offline
                   (defense-in-depth even when mcp-scan isn't used).
    config_paths   override config discovery (else Claude Code/Desktop defaults).
    use_mcp_scan   force the mcp-scan layer on/off (else AIRLOCK_MCP_SCAN env).
    """
    if config_paths is None:
        config_paths = _default_config_paths()
    if use_mcp_scan is None:
        use_mcp_scan = _truthy("AIRLOCK_MCP_SCAN", False)

    findings = []
    notes = []
    scanner = "offline"

    # 1. offline: any pre-fetched tool descriptions
    tools_scanned = 0
    if tools:
        findings.extend(scan_tools(tools))
        tools_scanned = len(tools)

    # 2. offline: server launch-command vectors from config
    servers = read_mcp_servers(config_paths)
    for nm, d in servers.items():
        findings.extend(_scan_server_def(nm, d))

    # 3. opt-in: mcp-scan (classifier-backed, connects to servers)
    if use_mcp_scan:
        ms_findings, note = run_mcp_scan(config_paths)
        if note:
            notes.append(note)
        if ms_findings is not None:
            findings.extend(ms_findings)
            scanner = "mcp-scan+offline"

    severity = max([f.weight for f in findings], default=0)
    try:
        block_threshold = int(os.environ.get("AIRLOCK_BLOCK_THRESHOLD", "3"))
    except ValueError:
        block_threshold = 3
    if severity >= block_threshold:
        decision = "block"
    elif severity > 0:
        decision = "flag"
    else:
        decision = "allow"

    return McpVetResult(
        decision=decision, findings=findings, servers_scanned=len(servers),
        tools_scanned=tools_scanned, scanner=scanner, notes=notes)
