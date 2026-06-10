# airlock

[![CI](https://github.com/Iskz17/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/Iskz17/airlock/actions/workflows/ci.yml)
&nbsp;![license: MIT](https://img.shields.io/badge/license-MIT-blue)
&nbsp;![python: 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)

A layered prompt-injection / agent-security guard with a **shared core** and **thin per-harness adapters** (Claude Code + openclaw), organized around the agent's **trust boundaries** — ingress, action, egress, persistence, and supply chain — with a graceful **offline ladder**. The lesson behind the design (cf. EchoLeak / CVE-2025-32711): a single input classifier gets bypassed, so the defense is layered across boundaries.

## What it catches

**Ingress** (content entering context):
- **Invisible-Unicode / ASCII smuggling** (Stage 0): Unicode Tag block (U+E0000–E007F), zero-width, bidi overrides, supplementary variation selectors. Hidden payloads are **decoded and surfaced**, not silently dropped. Offline, deterministic, high precision.
- **Overt injection** (Stage 1): high-precision regex for assistant-directed instructions ("ignore previous instructions", exfiltration asks, role hijacks, …). Offline.
- **Subtle/obfuscated injection** (Stage 2): an **ungated, openly-licensed** ML classifier (`protectai/deberta-v3-base-prompt-injection-v2`, Apache-2.0) — no account or login. Local model, no per-request network. Meta **Prompt Guard 2** is available as an opt-in backend (`AIRLOCK_STAGE2_BACKEND=promptguard`).
- **Multimodal** (Stage 2b): OCR an ingested image/screenshot → feed extracted text (incl. low-contrast/hidden) back through Stages 0–2. Optional deps (pytesseract/Pillow); mainly for browser/computer-use agents.

**Action** (before the agent acts):
- **Task-drift / AlignmentCheck** (Stage 3): before a sensitive/outbound tool runs, audit whether the agent is still serving the user's original request vs. a hijacked goal (LlamaFirewall `scan_replay`). Needs an LLM judge (Together / Ollama); silent no-op otherwise.

**Egress** (content leaving — the EchoLeak defense):
- **Exfiltration guard** (Stage 4): blocks secrets/PII and Markdown-URL exfil sinks from leaving via outbound tools (`WebFetch`/`Bash`) or the final reply. PreToolUse gate defaults to **ask**; mostly offline, optional Presidio PII.

**Persistence** (writes to long-term memory):
- **Memory-write guard** (Stage 5): re-runs ingress on content being written to a memory/RAG sink (CLAUDE.md, `memory/`, …) so a poisoned write can't persist and re-attack future sessions (AgentPoison / Morris-II).

**Supply chain** (installed MCP servers):
- **MCP vetting** (Stage 6): offline tool-poisoning detection on tool/parameter descriptions (hidden `<IMPORTANT>` directives, invisible-Unicode, "read ~/.ssh / don't tell the user") + remote-code install-vector checks on server launch commands; optional `mcp-scan` enrichment (`AIRLOCK_MCP_SCAN=1`).

## Install (Claude Code)

```bash
# Load for the current session (runs from this repo in place):
claude --plugin-dir /Users/iskandarzulkarnain/airlock/adapters/claude-code
```

### Which stages are on, and how to enable the rest

Install airlock and you're **immediately protected at every boundary, fully offline** — the stdlib stages need nothing. The heavier detectors are opt-in. Here's the whole picture at a glance:

| Stage | Boundary | On by default? | How to enable |
|---|---|---|---|
| **0** invisible-Unicode | ingress | ✅ on | — (stdlib, offline) |
| **1** heuristics | ingress | ✅ on | — (stdlib, offline) |
| **2** ML injection classifier | ingress | ⬜ opt-in | `/airlock-setup` *(or `promptguard`)* — pulls PyTorch + an **ungated, openly-licensed** model. **No account/login/subscription.** |
| **2b** image OCR | ingress | ⬜ opt-in | `/airlock-setup ocr` **+** system `tesseract` (`brew install tesseract`) |
| **3** AlignmentCheck (task drift) | action | ⬜ opt-in | `AIRLOCK_ALIGN_BACKEND=together` + `TOGETHER_API_KEY` (or Ollama) — a service, *not a download* |
| **4** egress exfil (secrets + MD sinks) | egress | ✅ on | — (stdlib, offline) |
| **4** richer PII (Presidio) | egress | ⬜ opt-in | `/airlock-setup pii` **+** `AIRLOCK_EGRESS_PII=1` |
| **5** memory-write guard | persistence | ✅ on | — (stdlib, offline) |
| **6** MCP vetting (offline) | supply chain | ✅ on | — (stdlib, offline) |
| **6** mcp-scan enrichment | supply chain | ⬜ opt-in | `/airlock-setup mcp` **+** `AIRLOCK_MCP_SCAN=1` |

**One command for all the installable stages** — airlock installs them into an **isolated managed venv** (`~/.cache/airlock/venv`; never your system Python — uninstall by deleting that folder):

```bash
/airlock-setup                 # in a Claude Code session — installs EVERYTHING (2, 2b, 4-PII, 6)
/airlock-setup promptguard     # …or narrow to a single extra
airlock-setup --extras all     # CLI equivalent (a pip install of this repo provides it)
```

Or set-and-forget — install in the background on first session (off by default, non-blocking, never silent):

```bash
export AIRLOCK_AUTO_INSTALL=1                       # default extras: all
export AIRLOCK_AUTO_INSTALL_EXTRAS=promptguard,ocr  # optional: narrow the set
```

Prefer your own environment instead of the managed venv? `pip install "airlock-guard-core[all]"` (or `[promptguard]` / `[pii]` / `[ocr]` / `[mcp]`).

> **Stage 2 needs no account or login** — it uses an ungated, Apache-2.0 prompt-injection classifier (`protectai/deberta-v3-base-prompt-injection-v2` by default; override with `AIRLOCK_STAGE2_MODEL`). A couple of *other* stages still need more than a download: **Stage 2b** needs the system `tesseract` binary; **Stage 3** needs an LLM backend (Together key / Ollama).
>
> Prefer Meta's **Prompt Guard 2** instead? Set `AIRLOCK_STAGE2_BACKEND=promptguard` and `/airlock-setup llamafirewall` — note *that* model is gated (needs an `HF_TOKEN` + accepting Meta's license).

## Use

- **Automatic:** every `WebFetch`/`WebSearch` result is scanned; flagged fetches get a quarantine + re-anchor system reminder (high-confidence hits also signal a block).
- **Manual:** `/scan <text-or-url>` runs the same guard on demand.
- **CLI:** `printf '%s' "text" | PYTHONPATH=. python3 -m guard_core.cli`

## Configuration (env vars)

| Var | Default | Effect |
|---|---|---|
| `AIRLOCK_DISABLE` | off | `1` disables the guard |
| `AIRLOCK_STAGE0/1/2` | on | disable an individual stage |
| `AIRLOCK_BLOCK_THRESHOLD` | `3` | severity (1–3) to block vs. only flag |
| `AIRLOCK_STRIP_ZWJ` | off | also strip ZWJ/ZWNJ (off preserves emoji + Persian/Indic) |
| `AIRLOCK_STAGE2_BACKEND` | `open` | `open` (ungated classifier) / `promptguard` (Meta Prompt Guard 2, gated) / `off` |
| `AIRLOCK_STAGE2_MODEL` | `protectai/deberta-v3-base-prompt-injection-v2` | HF repo for the `open` backend |
| `AIRLOCK_STAGE2_BLOCK_SCORE` | `0.98` | open-backend injection score to block vs. flag (tuned for 0 FP — see `tests/eval_stage2.py`) |
| `AIRLOCK_PROMPTGUARD_MODEL` | `86M` | Prompt Guard 2 size (`86M`/`22M`) — only the `promptguard` backend |
| `AIRLOCK_EGRESS_ALLOWLIST` | empty | comma-separated hosts exempt from the data-param heuristic |
| `AIRLOCK_EGRESS_BLOCK` | off | `1` → deny outbound on detection (default: ask) |
| `AIRLOCK_EGRESS_PII` | off | `1` → also run Presidio PII (needs `presidio-analyzer`) |
| `AIRLOCK_ALIGN_BACKEND` | `auto` | `together`/`ollama`/`off`; `auto` engages only if a backend is configured |
| `AIRLOCK_ALIGN_BLOCK` | off | `1` → deny (not ask) on detected task drift |
| `AIRLOCK_SENSITIVE_TOOLS` | `Bash,WebFetch,WebSearch` | tools gated by Stage 3 |
| `AIRLOCK_STAGE3/5/6/2B` | on | disable an individual stage |
| `AIRLOCK_MCP_SCAN` | off | `1` → also run Invariant `mcp-scan` (network) for Stage 6 |
| `AIRLOCK_MEMORY_PATHS` | empty | extra fnmatch globs treated as memory sinks (Stage 5) |
| `AIRLOCK_MEMORY_BLOCK` | off | `1` → deny (not ask) a poisoned memory write |
| `AIRLOCK_AUTO_INSTALL` | off | `1` → background-install heavier extras into the managed venv on first session |
| `AIRLOCK_AUTO_INSTALL_EXTRAS` | `all` | which extras to auto-install (`all`, or narrow: `promptguard,ocr,…`) |
| `AIRLOCK_HOME` | `~/.cache/airlock` | where the managed dependency venv lives |
| `AIRLOCK_SIDECAR_PORT` | `8787` | loopback port for the openclaw sidecar (`python3 -m guard_core.server`) |

## Layout

```
guard_core/        shared, harness-agnostic Python:
                     normalize/heuristics/scanners/verdict  Stages 0–3 (ingress + action)
                     egress.py                              Stage 4 (egress)
                     memory_guard.py                        Stage 5 (persistence)
                     mcp_vetting.py                         Stage 6 (supply chain)
                     multimodal.py                          Stage 2b (image OCR)
                     trace.py / config.py / cli.py          glue
                     server.py                              loopback HTTP sidecar (for openclaw)
adapters/
  claude-code/     .claude-plugin + hooks (ingress scan, egress gate, alignment, memory gate,
                     MCP vet, SessionStart) + airlock skill + /scan
  openclaw/        TS plugin (tool_result_persist true-strip, before_tool_call gate,
                     message_sending rewrite) → calls the core via the sidecar
tests/             offline suites + run_all.py + fixtures/   (101 checks)
docs/SMOKE_TEST.md live in-session verification guide
pyproject.toml     pip-installable core (+ promptguard / pii extras)
```

## Limitations (honest)

- **Claude Code** hooks can't rewrite tool output, so airlock **re-anchors/blocks**, it does not byte-strip. The **openclaw** adapter *can* truly strip (via `tool_result_persist`) and rewrite the reply.
- Ingress covers `WebFetch`/`WebSearch`; content fetched via `Bash` curl/wget bypasses the ingress hook (egress still gates the outbound `Bash`).
- Stage 3 (task drift) and Stage 6's `mcp-scan` enrichment need an LLM/network; they no-op cleanly when absent. Stage 2b needs OCR deps.
- Fails **open**: any internal error → the host session is never blocked.
- A mitigation, not a complete fix. Egress secret detection is precision-tuned but not exhaustive; the gate defaults to **ask** (not deny) so a false positive costs a confirmation, not a hard block.

## Test

```bash
python3 tests/run_all.py       # 101 offline checks (ingress, egress, alignment, MCP, memory,
                               #   multimodal, sidecar), no external deps
```

For a live in-session check (the plugin actually firing on a fetch / egress), follow [docs/SMOKE_TEST.md](docs/SMOKE_TEST.md).
