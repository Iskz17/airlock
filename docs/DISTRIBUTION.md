# Distributing airlock

airlock ships through **three complementary channels** from this one repo. Open
source (GitHub) is the foundation; the others layer on top of it.

| Component | Channel | Install command (end user) |
|---|---|---|
| `adapters/claude-code` (plugin) | **Claude Code marketplace** | `/plugin marketplace add Iskz17/airlock` → `/plugin install airlock@airlock` |
| `guard_core` (Python core + sidecar) | **PyPI** | `pip install airlock-guard-core` |
| `adapters/openclaw` (TS plugin) | **npm** | `npm install airlock-openclaw` |

> Repo owner is set to **Iskz17** throughout (GitHub URLs, marketplace owner,
> package metadata). If you fork or rename, update those refs:
> `grep -rln Iskz17 . --include='*.json' --include='*.toml' --include='*.md'`.

## 0. Open source on GitHub (do this first)

```bash
cd ~/airlock
git init && git add -A && git commit -m "airlock: layered agent-security guard"
gh repo create Iskz17/airlock --public --source=. --remote=origin --push
```

The repo root carries the MIT [LICENSE](../LICENSE), the [README](../README.md),
and `.claude-plugin/marketplace.json` (which makes the repo itself a Claude Code
marketplace).

## 1. Claude Code marketplace

The plugin lives at `adapters/claude-code` and is already validated
(`claude plugin validate adapters/claude-code`). The root
`.claude-plugin/marketplace.json` lists it with a same-repo relative `source`
(`"./adapters/claude-code"`), so **no separate marketplace repo is needed** — the
airlock repo *is* the marketplace.

Users add and install:

```bash
/plugin marketplace add Iskz17/airlock      # add this repo as a marketplace
/plugin install airlock@airlock            # install the plugin from it
```

Release versioning — keep `plugin.json` and the marketplace entry in agreement
and tag releases with the built-in helper:

```bash
claude plugin tag adapters/claude-code     # creates airlock--v0.2.1, validates agreement
```

To also appear in the **official directory** (`claude-plugins-official`), external
plugins are **not** added by pull request — Anthropic reviews submissions through
the [plugin directory submission form](https://clau.de/plugin-directory-submission)
(quality + security review). The entry that represents airlock there is kept in
[docs/marketplace-entry.json](marketplace-entry.json) (`source: git-subdir`
pinned to the release `ref` + `sha`). Bump it on each release.

## 2. PyPI (`airlock-guard-core`)

[pyproject.toml](../pyproject.toml) is ready (stdlib-only core; extras
`promptguard`/`pii`/`ocr`/`mcp`/`all`).

```bash
python3 -m pip install --upgrade build twine
python3 -m build                 # -> dist/airlock_guard_core-0.2.1{.tar.gz,-py3-none-any.whl}
twine upload dist/*              # needs a PyPI token
```

Ships the `airlock-scan` console script and `python3 -m guard_core.server`
(the sidecar the openclaw adapter calls).

## 3. npm (`airlock-openclaw`)

[adapters/openclaw/package.json](../adapters/openclaw/package.json) is ready
(`files`, `publishConfig.access=public`, MIT). It ships TypeScript source run
directly on Node ≥22.6 (type-stripping); it has no runtime deps and reaches the
Python core via the sidecar.

```bash
cd adapters/openclaw
npm install                      # dev only (typescript, @types/node) for typecheck
npm run typecheck && npm test    # test needs a running `python3 -m guard_core.server`
npm publish                      # needs an npm token
```

## Verify before any publish

```bash
python3 tests/run_all.py                       # 101 offline checks
claude plugin validate adapters/claude-code    # plugin manifest
( python3 -m guard_core.server & sleep 1; cd adapters/openclaw && npm test; kill %1 )
```
