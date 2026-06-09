// Ambient declaration of the slice of OpenClaw's plugin SDK this adapter uses.
//
// The real, fully-typed module ships with the `openclaw` package
// (`openclaw/plugin-sdk/core`). We declare a minimal compatible surface here so
// the adapter typechecks and the offline round-trip test runs WITHOUT vendoring
// the (large, 55-dep) openclaw package. At runtime the gateway resolves the real
// module from its own node_modules; this ambient decl only affects `tsc`.
//
// Shapes mirror openclaw@2026.6.1 (verified against the published
// dist/plugin-sdk/*.d.ts and bundled example plugins). Keep in sync if the host
// SDK changes; handlers fail open, so drift degrades to "no change", never a crash.

declare module "openclaw/plugin-sdk/core" {
  export interface OpenClawPluginApi {
    /** Register a lifecycle hook handler. Handler is `(event, ctx) => result`. */
    on<E = unknown, C = unknown, R = unknown>(
      hookName: string,
      handler: (event: E, ctx: C) => R | Promise<R>,
      opts?: { priority?: number; timeoutMs?: number },
    ): void;
    [key: string]: unknown;
  }

  export interface DefinePluginEntryOptions {
    id: string;
    name: string;
    description: string;
    configSchema?: unknown;
    register: (api: OpenClawPluginApi) => void;
  }

  /** Canonical entry helper for non-channel (tool/hook/service) plugins. */
  export function definePluginEntry(opts: DefinePluginEntryOptions): unknown;
}
