// airlock — openclaw plugin entry options.
//
// Split out of index.ts so the registration logic — which hook names attach to
// which handlers, with what options, and the AIRLOCK_DISABLE gate — is unit-
// testable WITHOUT importing the openclaw runtime. index.ts only feeds these
// options to definePluginEntry from the host SDK.

import {
  toolResultPersist,
  beforeToolCall,
  messageSending,
  llmInput,
} from "./hooks.ts";

// Outer per-hook timeout so a hung sidecar can't pin the host turn. before_tool_call
// may make two serial sidecar calls (egress + align), so allow headroom over the
// per-call AIRLOCK_SIDECAR_TIMEOUT_MS (default 4s); on timeout the host drops the
// hook result and proceeds (fail open).
const HOOK_TIMEOUT_MS = Number(process.env.AIRLOCK_HOOK_TIMEOUT_MS ?? "6000");

export interface HookApi {
  on(
    hookName: string,
    handler: (event: any, ctx: any) => unknown,
    opts?: { priority?: number; timeoutMs?: number },
  ): void;
}

export const entryOptions = {
  id: "airlock",
  name: "airlock",
  description:
    "Prompt-injection / exfiltration guard: true-strip injected tool output, " +
    "gate exfil tool calls, and neutralize exfil sinks in outgoing replies.",
  configSchema: { type: "object", additionalProperties: false, properties: {} },
  register(api: HookApi): void {
    // Evaluated at registration time (when the gateway loads the plugin).
    if ((process.env.AIRLOCK_DISABLE ?? "0") !== "0") return;
    // Ingress: strip injected bytes out of tool output before the model reads it.
    api.on("tool_result_persist", toolResultPersist, { priority: 50, timeoutMs: HOOK_TIMEOUT_MS });
    // Action: block / require-approval on outbound exfil tool calls.
    api.on("before_tool_call", beforeToolCall, { priority: 50, timeoutMs: HOOK_TIMEOUT_MS });
    // Egress: rewrite or withhold the outgoing assistant message.
    api.on("message_sending", messageSending, { priority: 50, timeoutMs: HOOK_TIMEOUT_MS });
    // Observation-only: feed conversation history to the (opt-in) task-drift check.
    api.on("llm_input", llmInput, { timeoutMs: HOOK_TIMEOUT_MS });
  },
};
