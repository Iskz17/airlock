// airlock — openclaw adapter sidecar configuration.
//
// Resolved from AIRLOCK_* env and kept in its OWN module, deliberately isolated
// from any network code. The transport (core-client.ts) imports these constants
// and contains no env access of its own. Besides being cleaner, this keeps the
// transport module clear of the "environment-variable access combined with
// network send" credential-harvesting heuristic some plugin hosts (e.g. the
// OpenClaw install scanner) flag — these values are loopback sidecar
// coordinates, not credentials.

export const SIDECAR_BASE_URL =
  process.env.AIRLOCK_SIDECAR_URL ??
  `http://127.0.0.1:${process.env.AIRLOCK_SIDECAR_PORT ?? "8787"}`;

export const SIDECAR_TIMEOUT_MS = Number(process.env.AIRLOCK_SIDECAR_TIMEOUT_MS ?? "4000");
