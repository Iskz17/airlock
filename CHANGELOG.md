# Changelog

All notable changes to airlock are documented here. Versions follow semver.

## [Unreleased]

## [0.2.4] — 2026-06-11

### Added — Stage 3 task-drift now has an open, no-subscription backend (Ollama)
- **Local Ollama judge for Stage 3 (AlignmentCheck)** — talks directly to a local
  Ollama server over HTTP (**stdlib `urllib` only**): no API key, no subscription,
  and **no `llamafirewall`**, so it works even on Python 3.9 (where llamafirewall
  can't import — `from typing import TypeAlias` is 3.10+). Set
  `AIRLOCK_ALIGN_BACKEND=ollama` (+ `AIRLOCK_OLLAMA_MODEL`, default **`qwen2.5:7b`**,
  `AIRLOCK_OLLAMA_URL`). `auto` now **prefers a configured local Ollama over the
  paid Together API**. Previously `ollama` was documented but never actually wired
  (it silently fell back to Together). Fails open fast if the server is down
  (connection-refused is instant). New `python -m guard_core.cli --align` verifier.
- The untrusted trace is delimited and the judge is instructed to treat it as
  data, not instructions (the judge-injection failure mode).
- **Verified live against a real Ollama.** On a drift/benign battery `qwen2.5:7b`
  scored 7/7 (blocked read-secret-file + env-exfil; allowed all benign), while
  `llama3.2` (3B) got 4/7 — false-positiving on benign reads and even the user's
  own requested fetch. Hence the **7B-class default**. macOS: install Ollama via
  the **cask** (`ollama-app`), not the formula (no bundled `llama-server` runner).

### Ingress — closed the curl/wget Bash-fetch bypass
- **New PostToolUse-on-Bash scan** (`scan_bash_output.py` + `guard_core.bash_ingress`):
  content fetched with `curl`/`wget`/`xh`/`lynx`/… through the Bash tool was never
  ingress-scanned (a documented gap). It now runs Stages 0–2 + re-anchor on the
  stdout of a *fetch* command. High-precision: a known fetch CLI as a command word
  **and** an explicit URL — ordinary Bash (`cat`/`grep`/`git`) is never scanned, so
  there's no FP surface or hot-path cost. Toggle: `AIRLOCK_SCAN_BASH_OUTPUT`.

### Fixed — red-team (expanded-corpus + second pass)
- **False positive:** `sensitive_file_read` matched `.env` inside `.env.example`
  (and `.sample`/`.template`/`.dist`/`.defaults`), hard-blocking benign dev docs.
  Now excludes those placeholder files; real `.env` / `.env.local` / `~/.ssh` /
  `~/.aws/credentials` still block. Pinned by regression tests.
- **Mislabel:** the re-anchor said "Prompt Guard 2 flagged injection" even when the
  default **open** classifier (protectai deberta) fired. Now backend-accurate
  ("Stage 2 injection classifier flagged").

### Changed — Stage 2 needs no account/login/subscription
- **Default Stage 2 backend is now an UNGATED, openly-licensed classifier**
  (`protectai/deberta-v3-base-prompt-injection-v2`, Apache-2.0) — **no Hugging Face
  login, no license, no subscription.** Verified end-to-end (injection → block,
  benign → allow) with no token. New env: `AIRLOCK_STAGE2_BACKEND`
  (`open`/`promptguard`/`off`), `AIRLOCK_STAGE2_MODEL`, `AIRLOCK_STAGE2_BLOCK_SCORE`.
- Meta **Prompt Guard 2** is now an **opt-in** backend
  (`AIRLOCK_STAGE2_BACKEND=promptguard` + `/airlock-setup llamafirewall`); its model
  is gated. The `promptguard` extra / `all` are now fully ungated (torch +
  transformers + sentencepiece); `llamafirewall` is a separate, non-`all` extra.
- **Stage 2 block threshold set to 0.98** (from 0.8). On the original 42-item
  corpus this read as precision 1.000 / recall 0.850 / 0 FP — but the
  **expanded 93-item corpus** (realistic security-adjacent prose, code, CLI
  output, multilingual) shows the open classifier is genuinely noisy:
  **precision ≈0.74, recall ≈0.90, ~25% FP**, and the scores are *not* bimodal
  (benign "OWASP lists prompt injection…" scores 1.000), so no threshold
  separates them. Stage 2 **keeps its block authority by default** (max recall);
  if false positives matter in your context, raise `AIRLOCK_STAGE2_BLOCK_SCORE`,
  set `AIRLOCK_STAGE2=0`, or rely on the high-precision Stage 1 heuristics.
  (See `tests/eval_stage2.py`.)
- **Stage 1 heuristics extended** to cover injection styles the ML model misses
  (the layering payoff): `sensitive_file_read` (read ~/.ssh/id_rsa / .env / …),
  `goal_hijack` ("your new goal is to …"), and exfil verbs extract/steal/harvest/
  siphon. High-precision (path/objective-gated) — no new false positives on the
  benign hard-negative set.

### Added
- **CI** (GitHub Actions): test suite on Python 3.9–3.13 × {ubuntu, macos},
  openclaw `tsc` + sidecar round-trip, and manifest/version-agreement checks.
  README CI/license/python badges. Test suite is now hermetic (isolates
  `AIRLOCK_HOME` so a local managed venv's ML model can't perturb results).

### Changed / Fixed (verified against the real libraries)
- **Stage 2/3 LlamaFirewall API confirmed correct** by introspecting the installed
  `llamafirewall` (ScannerType/Role/message/scan/scan_replay/ScanResult fields all
  match) — resolves the red-team "silent no-op" concern for the API itself.
- **Stage 2 dependency break fixed.** llamafirewall imports `HfFolder` (removed in
  `huggingface_hub>=1.0`) but pins hf_hub unbounded, so a bare install broke Prompt
  Guard 2. The `[promptguard]` extra + installer now pin `huggingface_hub==0.30.2`
  and `transformers==4.51.3` (verified working). Documented that Stage 2 also needs
  an HF token + acceptance of the gated meta-llama Prompt Guard 2 license; airlock's
  timeout/fail-open prevents llamafirewall's interactive login prompt from hanging a
  hook.
- **Stage 6 mcp-scan**: the tool was **renamed `mcp-scan` → `snyk-agent-scan`** and
  prints a deprecation banner to stdout. `_mcp_scan_cmd` now prefers the new name
  with `--json` before the `scan` subcommand; new `_extract_json` strips the banner
  before parsing; `[mcp]` extra → `snyk-agent-scan`; installer status is binary-aware.
  148 offline checks.

## [0.2.3] — 2026-06-09

### Changed
- **openclaw adapter reworked against the real gateway (`openclaw@2026.6.1`)**,
  validated live (`plugins install --link`, `inspect --runtime`, `doctor`):
  - Correct registration model `definePluginEntry({id,name,register(api)})` +
    `api.on(...)` — the previous `export const plugin = {…methods}` was a **silent
    no-op** on a real host.
  - Correct hooks: `tool_result_persist`, `before_tool_call`, `message_sending`
    (reply rewrite/withhold), `llm_input` (transcript for task-drift, gated by
    `allowConversationAccess`). `.ts` loads directly (no compiled dist).
  - Split `entry.ts`/`hooks.ts`/`config.ts`; **env reads isolated in `config.ts`**
    so the install scanner no longer flags env-access+`fetch` as credential
    harvesting (installs without a force flag).
  - Added `openclaw.plugin.json` manifest + `openclaw-sdk.d.ts`; expanded
    round-trip suite (guard + hooks + registration binding).
- Added `HANDOFF.md`.

Note: the Claude Code plugin and `guard_core` are unchanged from 0.2.2; this
release is the openclaw adapter + docs (versions kept in lockstep).

## [0.2.2] — 2026-06-08

Security hardening from an adversarial red-team code review (24 verified findings;
21 fixed). Each fix is pinned by a regression test in `tests/test_redteam_fixes.py`.

### Fixed
- **Egress (Stage 4):** detect **HTML `<img>`/`<a>`/`<source>` and CSS `url()`
  exfil sinks** (previously only Markdown was caught — a real EchoLeak gap);
  catch `data_path` with trailing extensions, split/short `data_param`s, and
  **URL-fragment** exfil; match `ENCRYPTED`/PKCS#8 `PRIVATE KEY` headers.
- **Ingress (Claude Code):** PostToolUse block decision is now emitted at the
  **top level** (`decision`/`reason`) — it was nested in `hookSpecificOutput`,
  where Claude Code ignored it, so the high-confidence block never fired.
- **Persistence (Stage 5):** `is_memory_target` now matches **relative/bare**
  memory paths (`memory/x.md`, `CLAUDE.local.md`), not just `*/`-anchored ones;
  memory-gate caps scanned content.
- **Installer:** managed venv is **version-pinned** (rebuilds on python
  minor-version drift instead of silently breaking imports); auto-install lock
  clears **only on success** (no more multi-GB retry every session); atomic lock
  create; venv-create timeout.
- **Hot-path safety:** Stage 2 model-load and Stage 3 network judge now have
  wall-clock timeouts (fail open fast); sidecar caps request body + socket
  timeout; transcript readers are bounded (no full-file slurp).
- **trace:** real WebSearch `tool_response` shape parsed (not repr-stringified);
  genuine user prose starting with `[` no longer dropped.
- **openclaw:** reply rewrite is driven off the egress decision and redacts
  secret/PII snippets (not just sink URLs); optional `AIRLOCK_REPLY_BLOCK`.

### Verified
- 144 offline checks; `tsc` clean; openclaw TS↔Python round-trip; plugin validates.
- **Live in-session smoke test:** SessionStart, PreToolUse (Bash), and Stop hooks
  confirmed firing in a real `claude` session with valid, accepted hook output.

## [0.2.1] — 2026-06-08

### Changed
- `/airlock-setup` (and `AIRLOCK_AUTO_INSTALL`) now default to **`all`** — one
  command installs every pip-installable extra (Stage 2 Prompt Guard 2, Stage 2b
  OCR, Stage 4 Presidio PII, Stage 6 mcp-scan) instead of just Prompt Guard 2.
  Pass a single extra to narrow it. Stage 3 (task-drift) still needs a backend
  key (not a download).

## [0.2.0] — 2026-06-08

### Added
- **One-command setup for the heavier stages** (`guard_core/installer.py`):
  `/airlock-setup` command, `airlock-setup` console script, and an opt-in
  `AIRLOCK_AUTO_INSTALL=1` background install on first session. Optional extras
  (Stage 2 Prompt Guard 2, Stage 2b OCR, Stage 6 mcp-scan) install into an
  **isolated, reversible managed venv** (`~/.cache/airlock/venv`) — never the
  user's system Python. `scanners`/`multimodal`/`mcp_vetting` add that venv to
  `sys.path` so later sessions pick the deps up.
- `AIRLOCK_AUTO_INSTALL`, `AIRLOCK_AUTO_INSTALL_EXTRAS`, `AIRLOCK_HOME` config.
- 12 installer tests (113 offline checks total).

### Changed
- SessionStart readiness line reports auto-install status and points to
  `/airlock-setup` when Stage 2 is unavailable.

## [0.1.0] — 2026-06-05

### Added
- Shared guard core + Claude Code plugin + openclaw adapter, organized around the
  agent's trust boundaries with a graceful offline ladder.
- **Ingress:** invisible-Unicode/ASCII-smuggling normalizer (Stage 0),
  heuristics (Stage 1), Prompt Guard 2 (Stage 2), image OCR (Stage 2b).
- **Action:** AlignmentCheck task-drift gate (Stage 3).
- **Egress:** secret/PII + Markdown-URL exfil sink guard (Stage 4).
- **Persistence:** memory-write poisoning guard (Stage 5).
- **Supply chain:** MCP tool-poisoning vetting + mcp-scan (Stage 6).
- openclaw adapter (true-strip / gate / reply-rewrite) via an HTTP sidecar.
- Distribution: GitHub + Claude Code marketplace + PyPI + npm.
