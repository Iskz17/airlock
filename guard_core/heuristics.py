"""Stage 1 — regex heuristics for overt, assistant-directed prompt injection.

Offline, dependency-free. These catch the blatant cases — text that is plainly
*addressing the AI* rather than being informational content. High-precision
patterns only; subtle/obfuscated injection is left to Stage 2 (Prompt Guard 2).
Weights: 1 = weak signal, 2 = strong, 3 = severe.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS = [
    ("instruction_override", 3,
     r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b"
     r"[^.\n]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|context|directions?)\b"),
    ("system_role_spoof", 3,
     r"(?:^|\n)\s*(?:#{0,3}\s*)?(system|developer|assistant)\s*:\s*\S"),
    ("new_instructions", 2,
     r"\b(new|updated|revised)\s+(instructions?|system\s+prompt|directives?|rules?)\b\s*:?"),
    ("role_hijack", 2,
     r"\byou\s+are\s+now\b|\bact\s+as\b[^.\n]{0,30}\b(dan|jailbreak|unrestricted|developer\s+mode)\b"
     r"|\bdeveloper\s+mode\b|\bignore\s+your\s+(guidelines|guardrails|safety)\b"),
    ("ai_meta_address", 2,
     r"\bif\s+you(?:'re|\s+are)\s+(?:an?\s+)?(ai|a\.i\.|assistant|agent|language\s+model|llm|chatbot|bot)\b"
     r"|\bto\s+the\s+(ai|assistant|agent|model|llm)\s+(reading|processing|that)\b"),
    # Polite "important instructions" / EchoLeak-style indirect injection: data that
    # addresses the assistant about ITS task and slips in a pre/post-task directive.
    # No "ignore previous instructions" verb fires here, so instruction_override
    # misses it; left to Stage 2 alone it's defeated by dilution (injection wrapped
    # in benign prose drops below the block threshold). High-precision: anchored on
    # "the task I gave you" / addressing "you, the <AI>" — phrasing benign tool
    # output essentially never contains. (Surfaced by the AgentDojo eval.)
    ("embedded_task_injection", 2,
     r"\bbefore\s+you\s+(?:can\s+)?(?:solve|answer|complete|finish|continue|proceed|do)\b"
     r"[^.\n]{0,50}\btask\b[^.\n]{0,40}\b(?:do\s+the\s+following|please\s+do|do\s+this|first)\b"
     r"|\bthe\s+task\s+(?:that\s+)?i\s+(?:gave|assigned|asked|set)\s+you\b"
     r"|\bmessage\s+(?:from\s+[^.\n]{0,30}\s+)?to\s+you,?\s+(?:the\s+)?(?:\w+\s+)?"
     r"(?:ai|a\.i\.|assistant|agent|model|language\s+model|llm|chatbot|bot)\b"),
    ("exfiltration", 3,
     r"\b(reveal|expose|print|show|send|email|e-mail|leak|disclose|output|forward|exfiltrate|dump|"
     r"extract|steal|harvest|siphon)\b"
     r"[^.\n]{0,40}\b(system\s+prompt|api[\s_-]?keys?|passwords?|secrets?|tokens?|credentials?|"
     r"account\s+(?:number|details|id)|ssn|social\s+security|private\s+keys?|env(?:ironment)?\s+variables?)\b"),
    # Reading a sensitive credential file (Stage 2 ML classifiers miss this style;
    # mirrors the MCP read_sensitive_file signature). High-precision: gated by the path.
    ("sensitive_file_read", 3,
     r"\b(read|open|cat|load|access|include|attach|send|print|leak|exfiltrate|contents?\s+of)\b"
     # `.env` but NOT the safe-to-share placeholder files (.env.example/.sample/...)
     # — referencing those in dev docs is benign and was over-blocking.
     r"[^.\n]{0,40}(~/?\.ssh|id_rsa|id_ed25519|"
     r"\.env(?!\.(?:example|sample|template|dist|defaults?))\b|"
     r"\.aws/credentials|\.netrc|\.git-credentials|private[\s_-]?key)"),
    # Goal/objective hijack ("your new goal is to …"). Specific forms only (not the
    # broad 'you must now …') to avoid flagging benign imperatives.
    ("goal_hijack", 2,
     r"\byour\s+(new|real|true|actual|primary|secret)\s+"
     r"(goal|objective|task|purpose|mission|directive|instructions?|job)\s+(is|are)\b"
     r"|\bfrom\s+now\s+on\b[^.\n]{0,25}\byour\s+(goal|objective|task|job|purpose)\b"),
    ("task_substitution", 2,
     r"\binstead\s*,?\s+(do|please|you\s+should|ignore|respond|reply)\b"
     r"|\b(also|additionally|furthermore)\b[^.\n]{0,40}\b(append|add|include|write|output|say)\b"
     r"[^.\n]{0,40}\b(at\s+the\s+end|to\s+your\s+(response|answer|reply|output))\b"
     r"|\bappend\s+the\s+following\b"),
    ("tool_coercion", 2,
     r"\b(run|execute|eval(?:uate)?)\b[^.\n]{0,20}\b(this|the\s+following|these)\b"
     r"[^.\n]{0,20}\b(command|commands|code|script|shell)\b"),
    # MCP "line-jumping": untrusted text dictating that EVERY command carry an
    # attacker prefix (e.g. `chmod -R 0666 ~;`). High-precision on the distinctive
    # "all commands must include/be-prefixed-with" idiom — not the (benign-ambiguous)
    # secrecy clause it usually rides with. (Surfaced by the bypass eval.)
    ("command_prefix_injection", 2,
     r"\b(?:all|every|each|any)\s+(?:shell\s+|bash\s+|terminal\s+|cli\s+)?commands?\s+"
     r"(?:must|should|need\s+to|have\s+to|are\s+required\s+to|always)\s+"
     r"(?:include|use|start\s+with|begin\s+with|be\s+prefixed(?:\s+with)?|contain|append|add)\b"),
]

# Morse-encoded payload: Stage 2's ML classifier doesn't decode Morse, so a Morse
# blob otherwise passes. Detected in code (not a pattern) to require a MIX of dots
# and dashes and to stay linear-time — a regex lookahead approach back-tracks
# quadratically on benign dot/dash runs (TOC leaders, `----` rules, diff walls).
# Space OR slash separators (slash is the standard Morse word separator).
_MORSE_RUN = re.compile(r"[.\-]{1,6}(?:[ /]+[.\-]{1,6}){5,}")


def _morse_hit(text: str):
    for m in _MORSE_RUN.finditer(text):
        s = m.group(0)
        if "." in s and "-" in s:  # mixed -> a real Morse blob, not a rule/ellipsis
            return s
    return None

_COMPILED = [(label, weight, re.compile(pat, re.IGNORECASE)) for label, weight, pat in _PATTERNS]


@dataclass
class HeuristicHit:
    label: str
    weight: int
    snippet: str


def scan(text: str) -> list:
    """Return one HeuristicHit per matching pattern (first match each)."""
    hits = []
    for label, weight, rx in _COMPILED:
        m = rx.search(text)
        if m:
            snip = " ".join(m.group(0).split())
            if len(snip) > 120:
                snip = snip[:117] + "..."
            hits.append(HeuristicHit(label=label, weight=weight, snippet=snip))
    morse = _morse_hit(text)
    if morse:
        snip = morse if len(morse) <= 120 else morse[:117] + "..."
        hits.append(HeuristicHit(label="morse_encoded", weight=2, snippet=snip))
    return hits
