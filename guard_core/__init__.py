"""airlock guard core — layered, harness-agnostic prompt-injection defense.

Importing this package never requires heavy/optional dependencies; the
Prompt Guard 2 (LlamaFirewall) backend is loaded lazily and degrades to the
offline ladder (Stages 0–1) when unavailable.
"""
from .verdict import assess, Verdict, reanchor_message  # noqa: F401
from .config import Config  # noqa: F401

__all__ = ["assess", "Verdict", "reanchor_message", "Config"]
__version__ = "0.1.0"
