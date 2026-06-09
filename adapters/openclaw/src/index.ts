// airlock — openclaw plugin entry (thin SDK binding).
//
// Feeds the host-runtime-agnostic `entryOptions` to the host's definePluginEntry.
// All registration logic lives in entry.ts (unit-tested without the openclaw
// runtime); all hook logic in hooks.ts; all detection in guard.ts / the Python
// core.
//
// Verified against the openclaw@2026.6.1 plugin SDK and bundled example plugins:
// the default export must be definePluginEntry({ id, name, description,
// register(api) }) and hooks attach via api.on(...) — a plain object of
// hook-named methods is NOT loaded. See entry.ts / README for what is verified
// vs. still CONFIRM-on-a-live-host (the SDK import specifier, the manifest, and
// whether the gateway loads this .ts entry directly or needs compiled ./dist).

import { definePluginEntry } from "openclaw/plugin-sdk/core";
import { entryOptions } from "./entry.ts";

export default definePluginEntry(entryOptions);
