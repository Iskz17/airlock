---
description: Install airlock's optional heavier stages (Prompt Guard 2, OCR, mcp-scan) into its managed venv
argument-hint: "[promptguard|pii|ocr|mcp|all]  (default: promptguard)"
---

Install airlock's optional dependencies into its **managed, isolated venv**
(`~/.cache/airlock/venv` — never your system Python; remove by deleting that
folder). This enables the heavier detection stages that are off by default.

Run this exact command and stream its output (it may take a few minutes for
Prompt Guard 2, which pulls PyTorch + a model):

```bash
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}" bash "${CLAUDE_PLUGIN_ROOT}/hooks/airlock-python.sh" -m guard_core.installer --extras "${ARGUMENTS:-promptguard}"
```

Then briefly tell the user:
- which extras are now installed (from the `airlock extras status:` line);
- that Stage 2 (Prompt Guard 2) / Stage 2b (OCR) / Stage 6 (mcp-scan) will be
  active in the **next** session;
- for **OCR**, if `tesseract_binary` is false, they also need the system binary:
  `brew install tesseract` (macOS) or `apt-get install tesseract-ocr` (Debian/Ubuntu);
- that **Stage 3 (task-drift)** is not installable — it needs a backend
  (`AIRLOCK_ALIGN_BACKEND=together` + `TOGETHER_API_KEY`, or `ollama`).

Do not install anything outside this command, and do not touch the user's system
Python environment.
