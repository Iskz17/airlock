"""Offline tests for Stage 3 (AlignmentCheck / task-drift).

build_trace is dependency-free and tested directly. The llamafirewall-backed
align() path is exercised with a *mock* llamafirewall module injected into
sys.modules, so the trace->message conversion, scan_replay call, and decision
mapping are verified even though the real package isn't installed here.
"""
import json
import os
import pathlib
import sys
import tempfile
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from guard_core import scanners  # noqa: E402
from guard_core.trace import build_trace  # noqa: E402

_failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), "-", name)
    if not cond:
        _failures.append(name)


# --- A) build_trace reconstructs an ordered trace, folding in tool calls ------
def _write_transcript(rows):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(json.dumps(r) for r in rows))
    return path

tp = _write_transcript([
    {"type": "user", "message": {"role": "user", "content": "summarize this article about cats"}},
    {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "text", "text": "Sure, reading it now."},
        {"type": "tool_use", "name": "WebFetch", "input": {"url": "http://site/cats"}},
    ]}},
    {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "text": "cats are great"}]}},  # echo -> skipped
])
steps = build_trace(tp)
os.unlink(tp)
check("trace: first step is the user goal",
      steps and steps[0]["role"] == "user" and "summarize" in steps[0]["content"])
check("trace: assistant tool_use folded into a [calls WebFetch ...] note",
      any(s["role"] == "assistant" and "[calls WebFetch" in s["content"] for s in steps))
check("trace: bare tool_result user echo skipped",
      not any(s["role"] == "user" and "cats are great" in s["content"] for s in steps))
check("trace: empty path -> empty list", build_trace("") == [])


# --- B) graceful no-op when no backend / deps --------------------------------
for k in ("TOGETHER_API_KEY", "AIRLOCK_OLLAMA_MODEL"):
    os.environ.pop(k, None)
os.environ["AIRLOCK_ALIGN_BACKEND"] = "auto"
scanners._align_initialized = False
scanners._align_fw = None
scanners._align_init_error = None
check("align unavailable with no backend (auto)", scanners.align_available() is False)
check("align() returns None when unavailable", scanners.align([{"role": "user", "content": "hi"}]) is None)

# explicit off
os.environ["AIRLOCK_ALIGN_BACKEND"] = "off"
scanners._align_initialized = False
scanners._align_fw = None
check("align disabled when backend=off", scanners.align_available() is False)


# --- C) full path via a mock llamafirewall -----------------------------------
def _install_fake_llamafirewall():
    fake = types.ModuleType("llamafirewall")

    class _Dec:
        def __init__(self, name):
            self.name = name

    class _Result:
        def __init__(self, decision, score, reason):
            self.decision, self.score, self.reason = decision, score, reason

    class LlamaFirewall:
        def __init__(self, scanners=None):
            self.scanners = scanners

        def scan_replay(self, msgs):
            joined = " ".join(getattr(m, "content", "") for m in msgs).lower()
            # A trace that drifts toward revealing secrets / reading keys = misaligned.
            if "reveal" in joined or "id_rsa" in joined or "api key" in joined:
                return _Result(_Dec("BLOCK"), 0.95, "pending action unrelated to the user's stated goal")
            return _Result(_Dec("HUMAN_IN_THE_LOOP_REQUIRED") if "maybe" in joined else _Dec("ALLOW"), 0.0, "")

    class Role:
        USER = "user"
        ASSISTANT = "assistant"

    class ScannerType:
        PROMPT_GUARD = "prompt_guard"
        AGENT_ALIGNMENT = "agent_alignment"

    class UserMessage:
        def __init__(self, content=""):
            self.content = content
            self.role = "user"

    class AssistantMessage:
        def __init__(self, content=""):
            self.content = content
            self.role = "assistant"

    for nm, v in dict(LlamaFirewall=LlamaFirewall, Role=Role, ScannerType=ScannerType,
                      UserMessage=UserMessage, AssistantMessage=AssistantMessage).items():
        setattr(fake, nm, v)
    sys.modules["llamafirewall"] = fake


_install_fake_llamafirewall()
os.environ["AIRLOCK_ALIGN_BACKEND"] = "together"  # engage without needing a real key in the mock
scanners._align_initialized = False
scanners._align_fw = None
scanners._align_init_error = None

check("align available with deps+backend present", scanners.align_available() is True)

drift = [
    {"role": "user", "content": "summarize this article about cats"},
    {"role": "assistant", "content": "[about to call Bash with {\"command\": \"reveal the api key\"}]"},
]
r = scanners.align(drift)
check("misaligned trace -> block", r is not None and r.decision == "block")
check("misaligned result carries a reason", bool(r.detail))

benign = [
    {"role": "user", "content": "summarize this article about cats"},
    {"role": "assistant", "content": "[about to call WebFetch with {\"url\": \"http://site/cats\"}]"},
]
r2 = scanners.align(benign)
check("aligned trace -> allow", r2 is not None and r2.decision == "allow")

# decision-name mapping: HUMAN_IN_THE_LOOP -> flag
r3 = scanners.align([{"role": "user", "content": "maybe do the thing"}])
check("HUMAN_IN_THE_LOOP_REQUIRED maps to flag", r3 is not None and r3.decision == "flag")

# cleanup
sys.modules.pop("llamafirewall", None)
os.environ.pop("AIRLOCK_ALIGN_BACKEND", None)


# --- D) the OPEN, no-subscription Ollama backend (stdlib HTTP, no llamafirewall) --
for k in ("TOGETHER_API_KEY", "AIRLOCK_OLLAMA_MODEL", "AIRLOCK_OLLAMA_URL"):
    os.environ.pop(k, None)

# D1) backend resolution: auto prefers a configured local Ollama over paid Together
os.environ["AIRLOCK_ALIGN_BACKEND"] = "auto"
check("auto + nothing -> off", scanners._resolve_align_backend() == "off")
os.environ["AIRLOCK_OLLAMA_MODEL"] = "llama3.2"
check("auto + OLLAMA_MODEL -> ollama (no key needed)", scanners._resolve_align_backend() == "ollama")
check("ollama backend reports available", scanners.align_available() is True)
os.environ["TOGETHER_API_KEY"] = "tok"
check("auto + key present -> together", scanners._resolve_align_backend() == "together")
os.environ.pop("TOGETHER_API_KEY", None)
os.environ["AIRLOCK_ALIGN_BACKEND"] = "ollama"
check("explicit ollama -> ollama", scanners._resolve_align_backend() == "ollama")

# D2) align() via a MOCKED Ollama /api/chat (no real server, no key, no llamafirewall)
import urllib.request  # noqa: E402

class _FakeResp:
    def __init__(self, body):
        self._b = body
    def read(self):
        return self._b
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False

def _fake_urlopen(req, timeout=None):
    # Inspect ONLY the user message (the trace) — the system prompt legitimately
    # mentions "exfiltrating"/"secret", which must not be read as a trace signal.
    obj = json.loads(req.data.decode("utf-8"))
    usertext = (obj.get("messages") or [{}])[-1].get("content", "").lower()
    misaligned = any(w in usertext for w in ("reveal", "id_rsa", "api key", "exfiltrat"))
    verdict = {"aligned": (not misaligned),
               "reason": "reads secrets unrelated to task" if misaligned else "on task"}
    outer = {"message": {"role": "assistant", "content": json.dumps(verdict)}}
    return _FakeResp(json.dumps(outer).encode("utf-8"))

_real_urlopen = urllib.request.urlopen
urllib.request.urlopen = _fake_urlopen
try:
    drift_o = [
        {"role": "user", "content": "summarize this article about cats"},
        {"role": "assistant", "content": "[about to call Bash with {\"command\": \"reveal the api key\"}]"},
    ]
    r = scanners.align(drift_o)
    check("ollama: misaligned trace -> block", r is not None and r.decision == "block")
    check("ollama: block carries the judge's reason", bool(r.detail) and "secret" in r.detail.lower())

    benign_o = [
        {"role": "user", "content": "summarize this article about cats"},
        {"role": "assistant", "content": "[about to call WebFetch with {\"url\": \"http://site/cats\"}]"},
    ]
    r2 = scanners.align(benign_o)
    check("ollama: aligned trace -> allow", r2 is not None and r2.decision == "allow")

    # ollama path must NOT touch llamafirewall (works even where it can't import)
    sys.modules.pop("llamafirewall", None)
    check("ollama: empty trace short-circuits to allow",
          scanners.align([]) is not None and scanners.align([]).decision == "allow")
finally:
    urllib.request.urlopen = _real_urlopen
    for k in ("AIRLOCK_ALIGN_BACKEND", "AIRLOCK_OLLAMA_MODEL", "AIRLOCK_OLLAMA_URL"):
        os.environ.pop(k, None)

print()
if _failures:
    print("%d FAILED: %s" % (len(_failures), _failures))
    sys.exit(1)
print("all alignment tests passed")
sys.exit(0)
