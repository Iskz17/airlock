"""Stage 2b — multimodal ingress (image / screenshot text extraction).

Browser- and computer-use agents ingest *images*; an attacker can hide an
injection in a screenshot (rendered text, or low-contrast/near-invisible text a
human skims past). This stage OCRs an ingested image and feeds the extracted
text back through ingress Stages 0–2 (verdict.assess), so an instruction painted
into a picture is caught the same way as one in HTML.

Heavy, optional deps (pytesseract + Pillow, or easyocr). The module imports them
lazily and **degrades gracefully**: with no OCR backend, scan_image returns an
`available=False` result and the caller no-ops. Applicability is flagged per
harness — Claude Code's WebFetch is text-only, so this mainly serves
browser/computer-use agents and is exposed via the CLI / sidecar rather than a
default Claude Code hook.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .config import Config
from .verdict import assess


@dataclass
class ImageVerdict:
    available: bool          # was an OCR backend usable?
    decision: str            # allow | flag | block
    extracted_text: str
    techniques: list
    reasons: list
    smuggled_payload: str
    severity: int
    backend: str
    error: str = ""


def _allow(available=False, backend="", error=""):
    return ImageVerdict(available, "allow", "", [], [], "", 0, backend, error)


def _tesseract_ocr(image_path):
    """Default OCR backend: pytesseract + Pillow. Raises if unavailable."""
    try:
        from .installer import add_managed_to_path
        add_managed_to_path()
    except Exception:
        pass
    import pytesseract  # type: ignore
    from PIL import Image, ImageOps  # type: ignore

    img = Image.open(image_path)
    text = pytesseract.image_to_string(img)
    # Hidden/low-contrast text: also OCR an auto-contrast + inverted pass and
    # merge, so light-on-light or dark-on-dark injections surface.
    try:
        gray = ImageOps.grayscale(img)
        boosted = ImageOps.autocontrast(gray, cutoff=1)
        text += "\n" + pytesseract.image_to_string(boosted)
        text += "\n" + pytesseract.image_to_string(ImageOps.invert(gray))
    except Exception:
        pass
    return text


def ocr_available() -> bool:
    """Cheap probe: are the default OCR deps importable?"""
    try:
        from .installer import add_managed_to_path
        add_managed_to_path()
    except Exception:
        pass
    try:
        import pytesseract  # type: ignore  # noqa: F401
        from PIL import Image  # type: ignore  # noqa: F401
        return True
    except Exception:
        return False


def scan_image(image_path, config: Config = None, ocr=None) -> ImageVerdict:
    """OCR `image_path` and run the extracted text through ingress.

    ocr: optional callable(image_path) -> str, for tests or an alternate backend
    (e.g. easyocr). Defaults to the pytesseract+Pillow pipeline.
    """
    if os.environ.get("AIRLOCK_STAGE2B", "1").strip().lower() in ("0", "false", "no", "off"):
        return _allow(available=False, error="stage 2b disabled")

    backend = "custom" if ocr is not None else "tesseract"
    runner = ocr or _tesseract_ocr
    try:
        text = runner(image_path) or ""
    except Exception as e:  # missing deps / unreadable image -> degrade
        return _allow(available=False, backend=backend, error=str(e))

    if not text.strip():
        return ImageVerdict(True, "allow", "", [], [], "", 0, backend)

    v = assess(text, config=config)
    return ImageVerdict(
        available=True,
        decision=v.decision,
        extracted_text=text,
        techniques=v.techniques,
        reasons=v.reasons,
        smuggled_payload=v.smuggled_payload,
        severity=v.severity,
        backend=backend,
    )
