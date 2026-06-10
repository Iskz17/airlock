---
description: Install airlock's optional heavier stages (Prompt Guard 2, OCR, PII, mcp-scan) into its managed venv
argument-hint: "[all|promptguard|pii|ocr|mcp]  (default: all)"
---

Install airlock's optional dependencies into its **managed, isolated venv**
(`~/.cache/airlock/venv` — never your system Python; remove by deleting that
folder). This enables the heavier detection stages that are off by default.

By default this installs **everything** pip-installable (Stage 2 Prompt Guard 2,
Stage 2b OCR, Stage 4 Presidio PII, Stage 6 mcp-scan). Pass a single extra to
narrow it (e.g. `promptguard`). Run this exact command and stream its output
(it may take a few minutes — `all` pulls PyTorch + a model + Presidio/spaCy):

```bash
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}" bash "${CLAUDE_PLUGIN_ROOT}/hooks/airlock-python.sh" -m guard_core.installer --extras "${ARGUMENTS:-all}"
```

Then briefly tell the user:
- which extras are now installed (from the `airlock extras status:` line);
- that Stage 2 (Prompt Guard 2) / Stage 2b (OCR) / Stage 6 (mcp-scan) will be
  active in the **next** session;
- for **OCR**, if `tesseract_binary` is false, they also need the system binary:
  `brew install tesseract` (macOS) or `apt-get install tesseract-ocr` (Debian/Ubuntu);
- that **Stage 3 (task-drift)** is not a pip install — it needs an LLM judge, and
  the **free/local** option is **Ollama** (open models, no API key/subscription):
  install Ollama, `ollama pull qwen2.5:7b`, then set `AIRLOCK_ALIGN_BACKEND=ollama`
  (optionally `AIRLOCK_OLLAMA_MODEL` / `AIRLOCK_OLLAMA_URL`). **Use a 7B+ judge** —
  3B models (e.g. `llama3.2`) false-positive on benign actions in live testing.
  On macOS install via the **cask** (`brew install --cask ollama-app`), not the
  formula (its `llama-server` runner isn't bundled). A paid Together key
  (`AIRLOCK_ALIGN_BACKEND=together` + `TOGETHER_API_KEY`) is the alternative.
  Verify it with: `printf '{"steps":[{"role":"user","content":"summarize cats"},{"role":"assistant","content":"[about to call Bash with reveal the api key]"}]}' | AIRLOCK_ALIGN_BACKEND=ollama PYTHONPATH="${CLAUDE_PLUGIN_ROOT}" python3 -m guard_core.cli --align`

Do not install anything outside this command, and do not touch the user's system
Python environment.
