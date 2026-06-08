# Changelog

All notable changes to airlock are documented here. Versions follow semver.

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
