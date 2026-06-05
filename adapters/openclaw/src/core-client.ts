// airlock — openclaw core client.
//
// Reaches the shared Python guard core over a loopback HTTP sidecar
// (`python3 -m guard_core.server`), so Stages 0/1/2/3/4/6 are NOT reimplemented
// in TypeScript. Every call FAILS OPEN: if the sidecar is unreachable or errors,
// the result is a benign "allow" so the host agent is never broken by the guard.

export interface IngressVerdict {
  decision: "allow" | "flag" | "block";
  severity: number;
  techniques: string[];
  reasons: string[];
  smuggled_payload: string;
  stage2_available: boolean;
  clean_text: string;
  reanchor: string;
  error?: string;
}

export interface EgressFinding {
  kind: string;
  label: string;
  snippet: string;
  weight: number;
}

export interface EgressVerdict {
  decision: "allow" | "flag" | "block";
  severity: number;
  sanitized_text: string;
  findings: EgressFinding[];
  error?: string;
}

export interface AlignVerdict {
  available: boolean;
  decision: "allow" | "flag" | "block";
  score?: number;
  detail?: string;
  error?: string;
}

export interface TraceStep {
  role: "user" | "assistant";
  content: string;
}

const BASE_URL =
  process.env.AIRLOCK_SIDECAR_URL ??
  `http://127.0.0.1:${process.env.AIRLOCK_SIDECAR_PORT ?? "8787"}`;

const TIMEOUT_MS = Number(process.env.AIRLOCK_SIDECAR_TIMEOUT_MS ?? "4000");

async function post<T>(path: string, body: unknown, failOpen: T): Promise<T> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
      signal: ctrl.signal,
    });
    if (!res.ok) {
      return { ...failOpen, error: `sidecar ${res.status}` };
    }
    return (await res.json()) as T;
  } catch (e) {
    // Unreachable / timeout / parse error -> fail open.
    return { ...failOpen, error: String(e) };
  } finally {
    clearTimeout(t);
  }
}

export function ingress(text: string, intent = ""): Promise<IngressVerdict> {
  const failOpen: IngressVerdict = {
    decision: "allow", severity: 0, techniques: [], reasons: [],
    smuggled_payload: "", stage2_available: false, clean_text: text, reanchor: "",
  };
  if (!text || !text.trim()) return Promise.resolve(failOpen);
  return post<IngressVerdict>("/ingress", { text, intent }, failOpen);
}

export function egress(args: { text?: string; url?: string; command?: string }): Promise<EgressVerdict> {
  const failOpen: EgressVerdict = {
    decision: "allow", severity: 0, sanitized_text: args.text ?? "", findings: [],
  };
  return post<EgressVerdict>("/egress", args, failOpen);
}

export function align(steps: TraceStep[]): Promise<AlignVerdict> {
  const failOpen: AlignVerdict = { available: false, decision: "allow" };
  if (!steps || steps.length === 0) return Promise.resolve(failOpen);
  return post<AlignVerdict>("/align", { steps }, failOpen);
}

export async function health(): Promise<{ ok: boolean; error?: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${BASE_URL}/health`, { signal: ctrl.signal });
    return (await res.json()) as { ok: boolean };
  } catch (e) {
    return { ok: false, error: String(e) };
  } finally {
    clearTimeout(t);
  }
}
