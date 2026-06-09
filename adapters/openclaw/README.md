# airlock — openclaw adapter

True-strip ingress, egress sink rewriting, and task-drift gating for
[openclaw](https://docs.openclaw.ai), built on the **same shared Python guard
core** as the Claude Code adapter. Unlike Claude Code (whose PostToolUse hooks
can only *re-anchor*), openclaw's `tool_result_persist` can rewrite the
model-visible tool result, so this adapter does a **true byte-strip** of injected
content, and `message_sending` lets it **rewrite or withhold the outgoing reply**
to neutralize exfiltration sinks.

Hook names, event/return shapes, and the plugin-registration model were verified
against the published **openclaw@2026.6.1** plugin SDK (`openclaw/plugin-sdk`)
and its bundled example plugins.

## Architecture

```
openclaw host ─────────▶ src/index.ts   (definePluginEntry(entryOptions))
                              ▼
                          src/entry.ts    (id/name + register(api) → api.on, fail-open)
                              ▼
                          src/hooks.ts    (event → neutral mapping)
                              │  neutral calls
                              ▼
                          src/guard.ts    (decision logic)
                              │  HTTP (loopback)
                              ▼
                  python3 -m guard_core.server  (the shared core)
```

No detection logic lives in TypeScript — `index.ts` feeds `entryOptions` to the
host's `definePluginEntry`, `entry.ts` holds the hook registrations (split out so
they're testable without the openclaw runtime), `hooks.ts` maps openclaw's
event/ctx shapes onto neutral calls, and `guard.ts` calls the Python sidecar.
This keeps Stages 0/1/2/3/4/6 single-sourced.

## Hooks

| openclaw hook | airlock action |
|---|---|
| `tool_result_persist` | ingress scan → **true-strip** invisible-Unicode + quarantine/re-anchor injected content before the model reads it (rewrites `event.message.content`, returns `{ message }`) |
| `before_tool_call` | egress gate (secret-bearing URL / sensitive-file exfil) → `{ block, blockReason }` / `{ requireApproval: {…} }`; plus task-drift (`align`) when a backend is configured |
| `message_sending` | egress scan of the outgoing reply → **rewrite** (`{ content }`) to remove Markdown/URL exfil sinks & redact secrets, or **withhold** (`{ cancel, cancelReason }`) |
| `llm_input` | observation-only: captures conversation history per run so `before_tool_call` task-drift has a transcript (no-op unless an alignment backend is configured) |

## Run

```bash
# 1. start the core sidecar (stdlib-only, offline)
python3 -m guard_core.server            # 127.0.0.1:8787  (AIRLOCK_SIDECAR_PORT to change)

# 2. point the adapter at it (defaults to 127.0.0.1:8787)
export AIRLOCK_SIDECAR_URL=http://127.0.0.1:8787

# 3. install this package as an openclaw external plugin, then restart the gateway
#    openclaw plugins install --link ./adapters/openclaw
#    openclaw gateway restart        # plugin code changes require a gateway restart
```

The plugin entry (`src/index.ts`) default-exports `definePluginEntry({ id, name,
register(api) })` and attaches its hooks via `api.on(...)` — the registration
model openclaw actually loads (a plain object of hook-named methods is **not**
loaded). Discovery uses the `openclaw` block in `package.json`
(`extensions: ["./src/index.ts"]`) plus the sibling `openclaw.plugin.json`
manifest (`id` + `configSchema`). Requires **Node ≥22.19**.

### Verify the TS ⇄ Python path (no openclaw host needed)

```bash
python3 -m guard_core.server &                       # start sidecar
npm test                                              # node --experimental-strip-types test/roundtrip.ts
npm run typecheck                                     # tsc --noEmit  (needs `npm install` first)
```

`test/roundtrip.ts` drives the guard helpers, the hook handlers in `hooks.ts`
(true-strip, exfil gating, reply rewrite/withhold, image-block + metadata
preservation, the `llm_input` trace path) **and** the `entry.ts` registration
binding (a fake `api` capturing the `api.on(...)` calls — asserting the four hook
names, priorities, handler wiring, and the `AIRLOCK_DISABLE` gate) against the
live core.

## Config

Reads the same `AIRLOCK_*` env as the core (e.g. `AIRLOCK_DISABLE`,
`AIRLOCK_EGRESS_BLOCK`, `AIRLOCK_REPLY_BLOCK`, `AIRLOCK_EGRESS_ALLOWLIST`,
`AIRLOCK_ALIGN_BACKEND`). Adapter-specific: `AIRLOCK_SIDECAR_URL`,
`AIRLOCK_SIDECAR_PORT`, `AIRLOCK_SIDECAR_TIMEOUT_MS` (resolved in `config.ts`),
`AIRLOCK_HOOK_TIMEOUT_MS` (per-hook outer bound, default 6000), `AIRLOCK_ALIGN_BLOCK`,
`AIRLOCK_DEBUG` (surface skipped task-drift, etc.).

## Fail-open

If the sidecar is unreachable, slow, or errors, every helper returns a benign
"allow"/"no change" — the guard never breaks the host agent on its own fault.

## Verified against openclaw@2026.6.1

Against the published plugin SDK (`openclaw/plugin-sdk`) + bundled example plugins,
and **confirmed live** by installing into a real gateway (`openclaw plugins
install --link`, `plugins inspect --runtime`, `plugins doctor`):

- **registration model** — `definePluginEntry({ id, name, register(api) })` +
  `api.on(...)`. Live: `status: loaded`, `shape: hook-only` (a "supported
  compatibility path" per `plugins doctor`).
- **`.ts` loads directly** — the gateway loads `src/index.ts` as-is (Node ≥22.19);
  **no compiled `./dist/index.js` is required**. Source shown as
  `…/src/index.ts`, `Format: openclaw`.
- **import specifier** — `openclaw/plugin-sdk/core` (resolves at runtime from the
  gateway's own `node_modules`).
- **hook names + shapes** — `tool_result_persist` (reads `event.message.content[]`,
  returns `{ message }`), `before_tool_call` (`event.toolName`/`event.params` →
  `{ block, blockReason }` / `{ requireApproval: {…} }`), `message_sending`
  (`event.content` → `{ content }` / `{ cancel, cancelReason }`), `llm_input`
  (observation-only). The old `before_agent_reply` reply-rewrite was wrong (that
  hook is a pre-LLM short-circuit). Live: all four register at `priority: 50`.
- **manifest** — `package.json` `openclaw.extensions` + sibling
  `openclaw.plugin.json` (`id` + `configSchema`); both discovered live.
- **task-drift opt-in** — `llm_input` is gated: a non-bundled plugin must set
  `plugins.entries.airlock.hooks.allowConversationAccess=true` in the gateway
  config, otherwise the gateway blocks that hook (the other three still load).
  With it set, all four hooks register (verified).

### Install note (important)

OpenClaw's install scanner blocks plugins that combine **env access + network
send** ("possible credential harvesting"). airlock's env reads are isolated in
`src/config.ts` (loopback sidecar coordinates only) so the transport module is
clean and the plugin **installs without `--dangerously-force-unsafe-install`**.
Keep env access out of any module that also calls `fetch`. (The npm package name
`airlock-openclaw` differs from the manifest/config id `airlock`; the gateway
uses the manifest id and emits a harmless note.)

### Still host-dependent
- **Reply layer:** whether `message_sending`'s `content` rewrite catches every
  Markdown/image sink, or whether `reply_payload_sending` (post-normalization) is
  also wanted — depends on the channel renderer.
- **End-to-end poisoned turn:** the three surfaces are proven by the offline
  round-trip + live hook registration; driving a full poisoned agent turn through
  the gateway additionally needs a configured model provider.
