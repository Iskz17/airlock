"""Stage 0 — invisible-Unicode / ASCII-smuggling normalizer.

Deterministic, offline, dependency-free. Detects and neutralizes instructions
hidden in characters that are invisible (or misleading) to a human reviewer but
fully readable by an LLM tokenizer:

  * Unicode Tag block (U+E0000–U+E007F) — "ASCII smuggling": every ASCII char has
    an invisible tag twin (tag codepoint = 0xE0000 + ascii). Decoded back to
    surface the hidden instruction instead of silently dropping it.
  * Supplementary variation-selector smuggling (U+E0100–U+E01EF).
  * Zero-width / invisible formatting (ZWSP, word joiner, BOM, soft hyphen, ...).
  * Bidi override/embedding/isolate controls (Trojan-Source style reordering).

Conservative defaults preserve legitimate uses so we don't corrupt real text:
emoji ZWJ sequences and the ZWNJ used by Persian/Indic are kept (unless
strip_zwj), the emoji presentation selector U+FE0F is kept, and the benign
directionality marks LRM/RLM are kept.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass

# --- codepoint classes -------------------------------------------------------
_TAG_LO, _TAG_HI = 0xE0000, 0xE007F            # Unicode Tag block (ASCII smuggling)
_VS_SUP_LO, _VS_SUP_HI = 0xE0100, 0xE01EF      # supplementary variation selectors

# Always-strip invisibles with no legitimate visible-content use.
_ZERO_WIDTH = frozenset({
    0x200B,  # ZERO WIDTH SPACE
    0x2060,  # WORD JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
    0x00AD,  # SOFT HYPHEN
    0x180E,  # MONGOLIAN VOWEL SEPARATOR
    0x2061, 0x2062, 0x2063, 0x2064,  # invisible math operators
    0xFFF9, 0xFFFA, 0xFFFB,          # interlinear annotation anchors
})

# Bidi embedding/override/isolate controls (Trojan Source). LRM/RLM are kept.
_BIDI_CTRL = frozenset({
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,   # LRE RLE PDF LRO RLO
    0x2066, 0x2067, 0x2068, 0x2069,           # LRI RLI FSI PDI
})

_ZWJ_ZWNJ = frozenset({0x200C, 0x200D})  # legit in emoji + Indic/Persian; kept by default


@dataclass
class NormalizeResult:
    clean_text: str
    smuggled_payload: str       # decoded hidden ASCII (tag block), if any
    techniques: list            # detected technique labels (sorted)
    removed: int                # count of stripped codepoints
    high_confidence: bool       # tag/VS smuggling present => almost certainly malicious

    @property
    def found(self) -> bool:
        return bool(self.techniques)


def normalize(text: str, *, strip_zwj: bool = False, nfkc: bool = True) -> NormalizeResult:
    """Strip/decode dangerous invisible codepoints; return cleaned text + findings."""
    out_chars = []
    smuggled = []
    techniques = set()
    removed = 0

    for ch in text:
        cp = ord(ch)
        if _TAG_LO <= cp <= _TAG_HI:
            techniques.add("unicode_tag_smuggling")
            removed += 1
            decoded = cp - _TAG_LO
            if 0x20 <= decoded <= 0x7E:        # printable ASCII twin
                smuggled.append(chr(decoded))
            continue
        if _VS_SUP_LO <= cp <= _VS_SUP_HI:
            techniques.add("variation_selector_smuggling")
            removed += 1
            continue
        if cp in _ZERO_WIDTH:
            techniques.add("zero_width")
            removed += 1
            continue
        if cp in _BIDI_CTRL:
            techniques.add("bidi_control")
            removed += 1
            continue
        if cp in _ZWJ_ZWNJ and strip_zwj:
            techniques.add("zero_width_joiner")
            removed += 1
            continue
        out_chars.append(ch)

    clean = "".join(out_chars)
    if nfkc:
        clean = unicodedata.normalize("NFKC", clean)

    high = bool({"unicode_tag_smuggling", "variation_selector_smuggling"} & techniques)
    return NormalizeResult(
        clean_text=clean,
        smuggled_payload="".join(smuggled),
        techniques=sorted(techniques),
        removed=removed,
        high_confidence=high,
    )
