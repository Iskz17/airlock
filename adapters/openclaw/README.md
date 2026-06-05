# airlock — openclaw adapter

True-strip ingress, egress sink rewriting, and task-drift gating for
[openclaw](https://docs.openclaw.ai), built on the **same shared Python guard
core** as the Claude Code adapter. Unlike Claude Code (whose PostToolUse hooks
can only *re-anchor*), openclaw's `tool_result_persist` can rewrite the
model-visible tool result, so this adapter does a **true byte-strip** of injected
content, and `before_agent_reply` lets it **rewrite the outgoing reply** to
neutralize exfiltration sinks.

## Architecture

```
openclaw host ──hooks──▶ src/index.ts (thin binding)
                              │  maps ctx → neutral calls
                              ▼
                         src/guard.ts (decision logic)
                              │  HTTP (loopback)
                              ▼
                 python3 -m guard_core.server  (the shared core)
```

No detection logic lives in TypeScript — `index.ts`/`guard.ts` only translate
openclaw's hook I/O and call the Python sidecar. This keeps Stages 0/1/2/3/4/6
single-sourced.

## Hooks

| openclaw hook | airlock action |
|---|---|
| `tool_result_persist` | ingress scan → **true-strip** invisible-Unicode + quarantine/re-anchor injected content before the model reads it |
| `before_tool_call` | egress gate (secret-bearing URL / sensitive-file exfil) → `block`/`requireApproval`; plus task-drift (`align`) when a backend is configured |
| `before_agent_reply` | egress scan of the reply → **rewrite** to remove Markdown/URL exfil sinks, flag secrets |

## Run

```bash
# 1. start the core sidecar (stdlib-only, offline)
python3 -m guard_core.server            # 127.0.0.1:8787  (AIRLOCK_SIDECAR_PORT to change)

# 2. point the adapter at it (defaults to 127.0.0.1:8787)
export AIRLOCK_SIDECAR_URL=http://127.0.0.1:8787

# 3. load this package as an openclaw external plugin (TS source runs directly on Node ≥22.6)
```

### Verify the TS ⇄ Python path (no openclaw host needed)

```bash
python3 -m guard_core.server &                       # start sidecar
npm test                                              # node --experimental-strip-types test/roundtrip.ts
npm run typecheck                                     # tsc --noEmit  (needs `npm install` first)
```

`test/roundtrip.ts` drives the guard helpers **and** the actual hook handlers in
`index.ts` against the live core, asserting true-strip, exfil gating, and reply
rewriting.

## Config

Reads the same `AIRLOCK_*` env as the core (e.g. `AIRLOCK_DISABLE`,
`AIRLOCK_EGRESS_BLOCK`, `AIRLOCK_EGRESS_ALLOWLIST`, `AIRLOCK_ALIGN_BACKEND`).
Adapter-specific: `AIRLOCK_SIDECAR_URL`, `AIRLOCK_SIDECAR_PORT`,
`AIRLOCK_SIDECAR_TIMEOUT_MS`, `AIRLOCK_ALIGN_BLOCK`.

## Fail-open

If the sidecar is unreachable, slow, or errors, every helper returns a benign
"allow"/"no change" — the guard never breaks the host agent on its own fault.

## CONFIRM against a live openclaw build

Only `src/index.ts` needs adjustment if the hook API differs. To confirm:
- exact hook names (`tool_result_persist`, `before_tool_call`, `before_agent_reply`)
  and how external plugins register them;
- `ctx` field names for: the tool-result text, outbound tool name/args, the
  reply text, and the message history (used for task-drift);
- the **return shape** each hook expects to rewrite content / block / require
  approval.

The field readers in `index.ts` are deliberately lenient (multiple candidate
keys) and fail open, so a wrong guess degrades to "no change", never a crash.
Also confirm `tool_result_persist` fires *before the model reads* the result
(the docs say "before final persistence").
