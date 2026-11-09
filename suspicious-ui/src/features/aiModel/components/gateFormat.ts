import type { Gate, GateCheck } from "../api";

export const NA = "not available";
/** Numbers and short strings only; anything else is "not available". */
export const show = (v: unknown): string =>
  typeof v === "number" && Number.isFinite(v) ? String(Math.round(v * 10_000) / 10_000) : typeof v === "string" && v ? v.slice(0, 300) : NA;

/** Failed checks first, then by name. A check without a boolean `passed` counts as failed. */
export function sortedChecks(checks: Gate["checks"]): [string, GateCheck][] {
  if (!checks || typeof checks !== "object") return [];
  return Object.entries(checks)
    .filter(([, c]) => c && typeof c === "object")
    .sort(([an, a], [bn, b]) => Number(a.passed === true) - Number(b.passed === true) || an.localeCompare(bn));
}

export const failedNames = (gate: Gate | null) => sortedChecks(gate?.checks ?? null).filter(([, c]) => c.passed !== true).map(([n]) => n);

