"""Stage 2 — Prompt Guard 2 via LlamaFirewall (local open-weight classifier).
Stage 3 — AlignmentCheck (task-drift) via LlamaFirewall `scan_replay`.

Both degrade gracefully: if `llamafirewall` (or its model/backend) is
unavailable, the scan functions return None and the pipeline falls back to the
offline stages. Importing this module never raises on a missing dependency —
the llamafirewall import happens lazily inside the functions.

Stage 2 (Prompt Guard 2) is local once the model is fetched. Stage 3
(AlignmentCheck) needs an LLM judge — Together (TOGETHER_API_KEY) online, or a
local Ollama — and is therefore off the default offline path; it activates only
when a backend is configured (see `align_available`).

VERIFIED against the real `llamafirewall` package (introspection + live
construction): ScannerType.PROMPT_GUARD and .AGENT_ALIGNMENT exist; Role.USER /
.ASSISTANT exist; UserMessage/AssistantMessage take `content: str`;
LlamaFirewall.scan(input) and .scan_replay(trace: List[Message]) match; ScanResult
exposes `.decision` (ScanDecision ALLOW/BLOCK/HUMAN_IN_THE_LOOP_REQUIRED), `.score`
(float) and `.reason` (str). The mappings stay defensive (getattr + candidate
names) to tolerate version drift, but the current names are confirmed correct.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass

_firewall = None
_init_error = None
_initialized = False

# Stage 2 default backend = an UNGATED open classifier (no HF login/license).
_open_clf = None
_open_init_error = None
_open_initialized = False
_OPEN_MODEL_DEFAULT = "protectai/deberta-v3-base-prompt-injection-v2"  # Apache-2.0, not gated

_TIMEOUT = object()  # sentinel: work exceeded its wall-clock budget


def _run_with_timeout(fn, seconds, default):
    """Run fn() in a daemon thread; return its result, or `default` if it exceeds
    `seconds`. A daemon thread won't block process exit, so a slow model load or
    network judge can't pin a hot-path hook past its budget (we just fail open)."""
    box = {}

    def _run():
        try:
            box["r"] = fn()
        except BaseException as e:  # noqa: BLE001 — propagate after join
            box["e"] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        return default
    if "e" in box:
        raise box["e"]
    return box.get("r", default)


def _timeout_secs(name, default):
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


@dataclass
class ScanResult:
    decision: str        # "block" | "flag" | "allow"
    score: float
    detail: str


def _ensure_firewall():
    """Lazily build a LlamaFirewall with only the PROMPT_GUARD scanner.
    Returns the firewall instance or None; records why in _init_error."""
    global _firewall, _init_error, _initialized
    if _initialized:
        return _firewall
    _initialized = True
    try:
        from .installer import add_managed_to_path
        add_managed_to_path()
    except Exception:
        pass
    try:
        from llamafirewall import LlamaFirewall, Role, ScannerType  # type: ignore
    except Exception as e:  # ImportError or transitive failure
        _init_error = "llamafirewall unavailable: %s" % e
        return None
    try:
        _firewall = LlamaFirewall(scanners={Role.USER: [ScannerType.PROMPT_GUARD]})
    except Exception as e:
        _init_error = "LlamaFirewall init failed: %s" % e
        _firewall = None
    return _firewall


def _map_decision(d) -> str:
    name = str(getattr(d, "name", d) or "").upper()
    if "BLOCK" in name:
        return "block"
    if "HUMAN" in name or "FLAG" in name or "REVIEW" in name:
        return "flag"
    return "allow"


def prompt_guard(text: str):
    """Stage 2 — classify `text` for prompt injection. Returns ScanResult or None.

    Default backend is an UNGATED open classifier (no Hugging Face login or license
    needed). Set AIRLOCK_STAGE2_BACKEND=promptguard to use Meta Prompt Guard 2 via
    llamafirewall (gated model), or 'off' to disable. Bounded by a wall-clock budget
    so a first-call model download can't hang the PostToolUse hook (fails open)."""
    backend = os.environ.get("AIRLOCK_STAGE2_BACKEND", "open").strip().lower()
    if backend in ("off", "none", "0"):
        return None
    if backend in ("promptguard", "llamafirewall", "meta"):
        return _prompt_guard_llamafirewall(text)
    return _prompt_guard_open(text)


def _ensure_open_classifier():
    """Lazily build the ungated text-classification pipeline (downloads the model
    on first call). Returns it or None; records why in _open_init_error."""
    global _open_clf, _open_init_error, _open_initialized
    if _open_initialized:
        return _open_clf
    _open_initialized = True
    try:
        from .installer import add_managed_to_path
        add_managed_to_path()
    except Exception:
        pass
    try:
        from transformers import pipeline  # type: ignore
    except Exception as e:
        _open_init_error = "transformers unavailable: %s" % e
        return None
    model = os.environ.get("AIRLOCK_STAGE2_MODEL", _OPEN_MODEL_DEFAULT)
    try:
        _open_clf = pipeline("text-classification", model=model)
    except Exception as e:
        _open_init_error = "open classifier init failed: %s" % e
        _open_clf = None
    return _open_clf


def _prompt_guard_open(text: str):
    """Ungated open prompt-injection classifier (default
    protectai/deberta-v3-base-prompt-injection-v2). No HF token/license required."""
    budget = _timeout_secs("AIRLOCK_STAGE2_TIMEOUT", 8)

    def _work():
        clf = _ensure_open_classifier()
        if clf is None:
            return None
        return clf(text[:10000], truncation=True, max_length=512)

    try:
        out = _run_with_timeout(_work, budget, _TIMEOUT)
    except Exception as e:
        return ScanResult(decision="allow", score=0.0, detail="stage2 open error: %s" % e)
    if out is _TIMEOUT:
        return ScanResult(decision="allow", score=0.0, detail="stage2 open timed out (>%ss)" % budget)
    if out is None:
        return None
    res = out[0] if isinstance(out, list) and out else out
    label = str(res.get("label", "")).upper() if isinstance(res, dict) else ""
    try:
        score = float(res.get("score", 0.0)) if isinstance(res, dict) else 0.0
    except (TypeError, ValueError):
        score = 0.0
    injected = ("INJECT" in label) or (label in ("LABEL_1", "UNSAFE", "JAILBREAK", "TOXIC"))
    # Default 0.98: on a hard-negative eval corpus (tests/eval_stage2.py) the open
    # classifier's scores are bimodal, so 0.98 removes benign-imperative false
    # positives ("ignore the outliers", "you are now connected…") at no recall cost.
    block_score = _timeout_secs("AIRLOCK_STAGE2_BLOCK_SCORE", 0.98)
    if injected and score >= block_score:
        decision = "block"
    elif injected and score >= 0.5:
        decision = "flag"
    else:
        decision = "allow"
    return ScanResult(decision=decision, score=(score if injected else 0.0),
                      detail="open:%s score=%.3f" % (label or "?", score))


def _prompt_guard_llamafirewall(text: str):
    """Meta Prompt Guard 2 via llamafirewall — GATED model (needs an HF token +
    acceptance of the meta-llama license). Opt-in: AIRLOCK_STAGE2_BACKEND=promptguard."""
    budget = _timeout_secs("AIRLOCK_STAGE2_TIMEOUT", 8)

    def _work():
        fw = _ensure_firewall()
        if fw is None:
            return None
        from llamafirewall import UserMessage  # type: ignore
        return fw.scan(UserMessage(content=text))

    try:
        result = _run_with_timeout(_work, budget, _TIMEOUT)
    except Exception as e:
        return ScanResult(decision="allow", score=0.0, detail="prompt_guard error: %s" % e)
    if result is _TIMEOUT:
        return ScanResult(decision="allow", score=0.0, detail="prompt_guard timed out (>%ss)" % budget)
    if result is None:
        return None
    decision = _map_decision(getattr(result, "decision", None))
    score = getattr(result, "score", 0.0)
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0
    detail = str(getattr(result, "reason", "") or "")
    return ScanResult(decision=decision, score=score, detail=detail)


def availability() -> dict:
    """Readiness probe for the SessionStart bootstrap. Cheap — never downloads."""
    backend = os.environ.get("AIRLOCK_STAGE2_BACKEND", "open").strip().lower()
    if backend in ("off", "none", "0"):
        return {"prompt_guard": False, "backend": "off", "model": "", "error": "disabled"}
    if backend in ("promptguard", "llamafirewall", "meta"):
        _ensure_firewall()
        return {"prompt_guard": _firewall is not None, "backend": "promptguard",
                "model": os.environ.get("AIRLOCK_PROMPTGUARD_MODEL", "86M"), "error": _init_error}
    import importlib.util
    try:
        ok = importlib.util.find_spec("transformers") is not None
    except Exception:
        ok = False
    return {"prompt_guard": ok, "backend": "open",
            "model": os.environ.get("AIRLOCK_STAGE2_MODEL", _OPEN_MODEL_DEFAULT),
            "error": None if ok else "transformers not installed (run /airlock-setup)"}


# --- Stage 3: AlignmentCheck (task-drift) ------------------------------------

_align_fw = None
_align_init_error = None
_align_initialized = False

# AlignmentCheck has been exposed under a couple of names across versions.
_ALIGN_SCANNER_NAMES = ("AGENT_ALIGNMENT", "ALIGNMENT_CHECK", "ALIGNMENTCHECK")


def _align_backend() -> str:
    """together | ollama | off | auto. 'auto' picks together iff a key is set."""
    return os.environ.get("AIRLOCK_ALIGN_BACKEND", "auto").strip().lower()


def _ensure_align_firewall():
    """Lazily build a LlamaFirewall with only the AlignmentCheck scanner, on the
    assistant role. Returns the firewall or None; records why in
    _align_init_error. No-op (None) when the backend is disabled or unconfigured."""
    global _align_fw, _align_init_error, _align_initialized
    if _align_initialized:
        return _align_fw
    _align_initialized = True

    backend = _align_backend()
    if backend == "off":
        _align_init_error = "alignment disabled (AIRLOCK_ALIGN_BACKEND=off)"
        return None
    # In 'auto', only engage when a usable backend is actually configured, so the
    # default install stays fully offline and this hook is a silent no-op.
    if backend == "auto" and not (os.environ.get("TOGETHER_API_KEY")
                                  or os.environ.get("AIRLOCK_OLLAMA_MODEL")):
        _align_init_error = "no alignment backend configured (set TOGETHER_API_KEY or AIRLOCK_ALIGN_BACKEND=ollama)"
        return None

    try:
        from .installer import add_managed_to_path
        add_managed_to_path()
    except Exception:
        pass
    try:
        from llamafirewall import LlamaFirewall, Role, ScannerType  # type: ignore
    except Exception as e:
        _align_init_error = "llamafirewall unavailable: %s" % e
        return None

    scanner = None
    for nm in _ALIGN_SCANNER_NAMES:
        scanner = getattr(ScannerType, nm, None)
        if scanner is not None:
            break
    if scanner is None:
        _align_init_error = "no AlignmentCheck ScannerType found in this llamafirewall"
        return None

    role = getattr(Role, "ASSISTANT", None) or getattr(Role, "USER", None)
    try:
        _align_fw = LlamaFirewall(scanners={role: [scanner]})
    except Exception as e:
        _align_init_error = "AlignmentCheck init failed: %s" % e
        _align_fw = None
    return _align_fw


def align_available() -> bool:
    """True iff Stage 3 can actually run (deps + backend present). Cheap-ish:
    builds the firewall once and caches the result."""
    return _ensure_align_firewall() is not None


def align(trace_steps):
    """Run AlignmentCheck over a conversation trace.

    trace_steps: neutral list of {"role": "user"|"assistant", "content": str}
    (built by guard_core.trace.build_trace — dependency-free and testable).

    Returns a ScanResult (decision block|flag|allow) on a detected goal-hijack /
    task drift, or None if Stage 3 is unavailable (no deps/backend) so the caller
    can no-op silently.
    """
    fw = _ensure_align_firewall()
    if fw is None:
        return None
    if not trace_steps:
        return ScanResult(decision="allow", score=0.0, detail="empty trace")
    try:
        from llamafirewall import UserMessage, AssistantMessage  # type: ignore
    except Exception as e:
        return None
    try:
        msgs = []
        for step in trace_steps:
            content = str(step.get("content", "") or "")
            if not content:
                continue
            if step.get("role") == "user":
                msgs.append(UserMessage(content=content))
            else:
                msgs.append(AssistantMessage(content=content))
        if not msgs:
            return ScanResult(decision="allow", score=0.0, detail="empty trace")
        budget = _timeout_secs("AIRLOCK_ALIGN_TIMEOUT", 8)
        result = _run_with_timeout(lambda: fw.scan_replay(msgs), budget, _TIMEOUT)
    except Exception as e:
        # Backend/network error -> fail open (no decision), don't block the host.
        return ScanResult(decision="allow", score=0.0, detail="alignment error: %s" % e)
    if result is _TIMEOUT:
        # LLM judge too slow -> fail open so the PreToolUse hook returns promptly.
        return ScanResult(decision="allow", score=0.0, detail="alignment timed out")

    decision = _map_decision(getattr(result, "decision", None))
    score = getattr(result, "score", 0.0)
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0
    detail = str(getattr(result, "reason", "") or "")
    return ScanResult(decision=decision, score=score, detail=detail)


def align_status() -> dict:
    """Readiness probe for Stage 3 (used by bootstrap / diagnostics)."""
    ok = align_available()
    return {"alignment": ok, "backend": _align_backend(), "error": _align_init_error}
