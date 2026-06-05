// airlock — openclaw plugin entry.
//
// THIN binding only: it maps openclaw's hook signatures onto the tested,
// harness-neutral helpers in guard.ts (which call the Python core via the
// sidecar). All security logic lives in guard.ts / the Python core — never here.
//
// CONFIRM against a live openclaw build: the exact hook names, the ctx field
// names (how to read the tool result text / outbound args / reply text), and the
// return shape each hook expects to rewrite/block. The mappings below follow the
// documented model (https://docs.openclaw.ai/plugins/hooks) and are isolated so
// only this file needs adjusting if the API differs. Helpers fail open, so a
// wrong field read degrades to "no change", never to a broken session.

import {
  sanitizeToolResult,
  gateToolCall,
  sanitizeReply,
  checkAlignment,
} from "./guard.ts";
import type { TraceStep } from "./core-client.ts";

const DISABLED = (process.env.AIRLOCK_DISABLE ?? "0") !== "0";

// --- best-effort field extraction (kept lenient; CONFIRM exact shapes) -------
function toolResultText(ctx: any): string {
  const c = ctx?.result?.content ?? ctx?.content ?? ctx?.toolResult ?? ctx?.output;
  if (typeof c === "string") return c;
  if (Array.isArray(c)) {
    return c.map((b) => (typeof b === "string" ? b : b?.text ?? "")).join("\n");
  }
  return typeof c === "object" && c ? (c.text ?? "") : "";
}
function userIntent(ctx: any): string {
  return ctx?.userIntent ?? ctx?.task ?? ctx?.session?.intent ?? "";
}
function traceSteps(ctx: any): TraceStep[] {
  const msgs = ctx?.messages ?? ctx?.transcript ?? [];
  if (!Array.isArray(msgs)) return [];
  const steps: TraceStep[] = [];
  for (const m of msgs) {
    const content = typeof m?.content === "string" ? m.content : (m?.text ?? "");
    if (!content) continue;
    steps.push({ role: m?.role === "user" ? "user" : "assistant", content });
  }
  return steps;
}

// === openclaw external-plugin hooks ==========================================
export const plugin = {
  name: "airlock",
  version: "0.1.0",

  // Rewrite the model-visible tool result BEFORE it is persisted/read (true strip).
  async tool_result_persist(ctx: any) {
    if (DISABLED) return undefined;
    const text = toolResultText(ctx);
    if (!text) return undefined;
    const r = await sanitizeToolResult(text, userIntent(ctx));
    if (!r.changed) return undefined;
    // CONFIRM: return shape openclaw uses to replace persisted content.
    return { content: r.content };
  },

  // Gate an outbound/exec tool call: block or require user approval on exfil,
  // and (if a backend is configured) on task-drift.
  async before_tool_call(ctx: any) {
    if (DISABLED) return undefined;
    const tool = ctx?.toolName ?? ctx?.tool ?? ctx?.name ?? "";
    const input = ctx?.input ?? ctx?.args ?? ctx?.parameters ?? {};

    const eg = await gateToolCall(String(tool), input);
    if (eg.action !== "allow") {
      // CONFIRM: openclaw's block / requireApproval return shape.
      return eg.action === "block"
        ? { block: true, reason: eg.reason }
        : { requireApproval: true, reason: eg.reason };
    }
    const al = await checkAlignment(traceSteps(ctx));
    if (al.action !== "allow") {
      return al.action === "block"
        ? { block: true, reason: al.reason }
        : { requireApproval: true, reason: al.reason };
    }
    return undefined;
  },

  // Rewrite the outgoing reply to neutralize exfiltration sinks before it leaves.
  async before_agent_reply(ctx: any) {
    if (DISABLED) return undefined;
    const text = ctx?.reply ?? ctx?.message ?? ctx?.text ?? "";
    if (!text) return undefined;
    const r = await sanitizeReply(String(text));
    if (!r.changed) return undefined;
    // CONFIRM: return shape openclaw uses to rewrite the reply.
    return { reply: r.text, note: r.reason };
  },
};

export default plugin;
