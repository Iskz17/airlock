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
]

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
    return hits
