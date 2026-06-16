// airlock — openclaw hook handlers.
//
// These implement OpenClaw's plugin hooks against the REAL event/ctx/return
// shapes (verified against the openclaw@2026.6.1 plugin SDK) and map them onto
// the harness-neutral decision helpers in guard.ts. They are deliberately split
// out of index.ts (the SDK binding) so they can be unit-tested against the live
// Python sidecar WITHOUT importing the openclaw runtime.
//
// Everything FAILS OPEN: any unexpected event shape or sidecar fault degrades to
// "no change"/"allow" (return undefined), never a throw that could break the
// host turn. All detection logic lives in guard.ts / the Python core — these
// handlers only translate OpenClaw's I/O.

import {
  sanitizeToolResult,
  gateToolCall,
  sanitizeReply,
  checkAlignment,
  scanForLeaks,
} from "./guard.ts";
import type { TraceStep } from "./core-client.ts";

// --- minimal mirrors of the openclaw plugin-SDK event/result types ----------
// (openclaw@2026.6.1 dist/plugin-sdk/hook-types*.d.ts)
interface TextContentBlock {
  type: "text";
  text: string;
}
type ContentBlock = TextContentBlock | { type: string; [k: string]: unknown };

interface ToolResultMessage {
  role?: string;
  toolName?: string;
  toolCallId?: string;
  content?: ContentBlock[] | string;
  details?: unknown;
  isError?: boolean;
  [k: string]: unknown;
}

export interface ToolResultPersistEvent {
  toolName?: string;
  toolCallId?: string;
  message?: ToolResultMessage;
  isSynthetic?: boolean;
}
export interface ToolResultPersistResult {
  message?: ToolResultMessage;
}

export interface BeforeToolCallEvent {
  toolName: string;
  params?: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
}
export interface RequireApproval {
  title: string;
  description: string;
  severity?: "info" | "warning" | "critical";
  timeoutBehavior?: "allow" | "deny";
  // Constrain the decision set so the host cannot offer "allow-always" (a
  // one-click permanent bypass of the exfil gate).
  allowedDecisions?: Array<"allow-once" | "allow-always" | "deny">;
  pluginId?: string;
}
export interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
  requireApproval?: RequireApproval;
}

export interface MessageSendingEvent {
  to?: string;
  content?: string;
  metadata?: Record<string, unknown>;
}
export interface MessageSendingResult {
  content?: string;
  cancel?: boolean;
  cancelReason?: string;
  metadata?: Record<string, unknown>;
}

export interface LlmInputEvent {
  runId?: string;
  sessionId?: string;
  prompt?: string;
  historyMessages?: unknown[];
}
interface AgentCtx {
  sessionKey?: string;
  runId?: string;
}

// --- helpers ----------------------------------------------------------------
// Model-visible text carried by a block, regardless of its `type` and regardless
// of whether the string sits under `text`/`content`/`value`. Scanning ALL of
// these (not just type==="text" .text) closes the red-team bypass where an
// injection rode in a non-"text" block or under an alternate key (F2). A block
// with NO such string (e.g. an image with only `source`/base64) returns "" and is
// treated as structural — preserved untouched.
// Keys that hold binary/structural data (image bytes, MIME types, ids), never
// model-visible instruction text — skipped so an image block stays "structural"
// (preserved) and its base64 isn't mistaken for scannable text. (Text authored
// directly under one of these keys would go unscanned, but the host — not the
// attacker — controls block key names, and these are reserved for non-text data.)
const _SKIP_KEYS = new Set([
  "type", "source", "data", "mimetype", "mediatype", "blob", "bytes", "base64",
  "id", "toolcallid", "tool_call_id",
]);
function _blockText(b: unknown, depth = 0): string {
  if (b == null || depth > 5) return "";
  if (typeof b === "string") return b;
  if (Array.isArray(b)) return b.map((x) => _blockText(x, depth + 1)).filter(Boolean).join("\n");
  if (typeof b === "object") {
    const parts: string[] = [];
    for (const [k, v] of Object.entries(b as Record<string, unknown>)) {
      if (_SKIP_KEYS.has(k.toLowerCase())) continue;
      const t = _blockText(v, depth + 1); // recurse: nested resource/document text (MCP) too
      if (t) parts.push(t);
    }
    return parts.join("\n");
  }
  return "";
}

function _blocksOf(msg: ToolResultMessage | undefined): ContentBlock[] {
  if (!msg) return [];
  const c = msg.content;
  if (typeof c === "string") return [{ type: "text", text: c }];
  return Array.isArray(c) ? c : [];
}

function toGate(action: "block" | "requireApproval", reason: string): BeforeToolCallResult {
  if (action === "block") return { block: true, blockReason: reason };
  // requireApproval is an OBJECT in OpenClaw (not a boolean). timeoutBehavior
  // "deny" fails safe on no answer; allowedDecisions omits "allow-always" so a
  // single approval can't persist a permanent bypass of the exfil gate.
  return {
    requireApproval: {
      title: "airlock",
      description: reason,
      severity: "warning",
      timeoutBehavior: "deny",
      allowedDecisions: ["allow-once", "deny"],
      pluginId: "airlock",
    },
  };
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? "";
  } catch {
    return "";
  }
}

// === hooks ===================================================================

// tool_result_persist: TRUE-STRIP injected bytes out of a tool result before the
// model reads it. The result text lives in event.message.content (TextContent
// blocks); we replace those blocks with the sanitized/quarantined text and
// return { message } — the documented rewrite shape for this hook.
export async function toolResultPersist(
  event: ToolResultPersistEvent,
): Promise<ToolResultPersistResult | undefined> {
  try {
    const msg = event?.message;
    const blocks = _blocksOf(msg);
    const combined = blocks.map((b) => _blockText(b)).filter(Boolean).join("\n");
    if (!combined.trim()) return undefined;
    const r = await sanitizeToolResult(combined, "");
    if (!r.changed) return undefined;
    // Flagged: replace ALL text-bearing blocks with the single sanitized/quarantined
    // block (so injected text in any block — including non-"text" ones — is
    // neutralized), and preserve purely structural blocks (images/binary) untouched.
    const structural = blocks.filter((b) => !_blockText(b));
    const content: ContentBlock[] = [{ type: "text", text: r.content }, ...structural];
    return { message: { ...(msg as ToolResultMessage), content } };
  } catch {
    return undefined; // fail open
  }
}

// before_tool_call: gate an outbound/exec tool whose args look like data
// exfiltration, then (opt-in) a task-drift check. Tool name is event.toolName,
// args are event.params. Block -> { block, blockReason }; soft -> { requireApproval }.
export async function beforeToolCall(
  event: BeforeToolCallEvent,
): Promise<BeforeToolCallResult | undefined> {
  try {
    const tool = String(event?.toolName ?? "");
    const input = (event?.params ?? {}) as Record<string, unknown>;

    const eg = await gateToolCall(tool, input);
    if (eg.action !== "allow") return toGate(eg.action, eg.reason);

    // Task-drift only does anything when an alignment backend is configured on
    // the sidecar (otherwise checkAlignment is a no-op). before_tool_call carries
    // no conversation history, so we use the transcript captured by the llm_input
    // observer for this run. CONFIRM: llm_input delivery may require
    // `allowConversationAccess` for this plugin entry on the live host.
    const steps = recallTrace(event?.runId);
    if (steps.length) {
      const al = await checkAlignment(steps);
      if (al.action !== "allow") return toGate(al.action, al.reason);
    } else if (!event?.runId && TRACE.size && (process.env.AIRLOCK_DEBUG ?? "0") !== "0") {
      // before_tool_call.runId is optional; without it we can't correlate the
      // captured transcript, so task-drift is silently skipped for this call.
      // Surface it under AIRLOCK_DEBUG rather than letting it look like a pass.
      console.error("[airlock] before_tool_call missing runId — task-drift skipped");
    }
    return undefined;
  } catch {
    return undefined; // fail open
  }
}

// message_sending: rewrite the outgoing assistant message to neutralize
// exfiltration sinks / redact secrets, or withhold it entirely. Text is
// event.content; rewrite via { content }, withhold via { cancel, cancelReason }.
export async function messageSending(
  event: MessageSendingEvent,
): Promise<MessageSendingResult | undefined> {
  try {
    // Defense-in-depth: if the outgoing metadata carries a secret/PII, withhold
    // the whole message. We deliberately do NOT rewrite metadata in place — it is
    // usually host routing/threading data and editing it risks breaking delivery
    // — so a *confirmed* leak (secret/PII only, not heuristic url-exfil) fails safe.
    const meta = event?.metadata;
    if (meta && typeof meta === "object") {
      const leak = await scanForLeaks(safeStringify(meta));
      if (leak.leak) {
        return { cancel: true, cancelReason: `airlock egress: outgoing metadata leaks ${leak.labels.join(", ")}` };
      }
    }
    const text = String(event?.content ?? "");
    if (!text) return undefined;
    const r = await sanitizeReply(text);
    if (r.blocked) return { cancel: true, cancelReason: r.reason };
    if (r.changed) return { content: r.text };
    return undefined;
  } catch {
    return undefined; // fail open
  }
}

// llm_input: observation-only. Capture the conversation history per run so
// before_tool_call can feed it to the (opt-in) task-drift check. Returns nothing.
const TRACE = new Map<string, TraceStep[]>();
const TRACE_MAX = 256; // bound memory: drop the oldest entry past this many runs

function recordTrace(key: string, steps: TraceStep[]): void {
  if (!key) return;
  TRACE.set(key, steps);
  if (TRACE.size > TRACE_MAX) {
    const oldest = TRACE.keys().next().value;
    if (oldest !== undefined) TRACE.delete(oldest);
  }
}
export function recallTrace(key: string | undefined): TraceStep[] {
  if (!key) return [];
  return TRACE.get(key) ?? [];
}

export function llmInput(event: LlmInputEvent, _ctx?: AgentCtx): undefined {
  try {
    // Key on event.runId (REQUIRED on llm_input per the SDK contract) so the
    // write key provably matches before_tool_call's recall key.
    const key = String(event?.runId ?? "");
    if (!key) return undefined;
    const steps: TraceStep[] = [];
    for (const m of event?.historyMessages ?? []) {
      const mm = m as { role?: string; content?: unknown; text?: unknown };
      const content =
        typeof mm?.content === "string"
          ? mm.content
          : typeof mm?.text === "string"
            ? mm.text
            : "";
      if (!content) continue;
      steps.push({ role: mm.role === "user" ? "user" : "assistant", content });
    }
    if (typeof event?.prompt === "string" && event.prompt) {
      steps.push({ role: "user", content: event.prompt });
    }
    recordTrace(key, steps);
  } catch {
    // fail open: task-drift simply won't have history for this run
  }
  return undefined;
}
