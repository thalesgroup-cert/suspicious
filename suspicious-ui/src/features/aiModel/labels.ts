/** Plain-words text for the 409 `codes` Plan F's promote and rollback endpoints return. */
export const CODE_TEXT: Record<string, string> = {
  not_shadow: "The version is not in shadow.",
  too_young: "The shadow period has not run its minimum days yet.",
  too_few_results: "Too few live results have been compared so far.",
  unreviewed_flips: "Some critical verdict flips are not reviewed yet.",
  unreviewed_campaigns: "Some campaign changes are not reviewed yet.",
  recheck_missing: "The gate has not been rechecked yet.",
  recheck_failed: "The last gate recheck failed.",
  recheck_stale: "The last gate recheck is out of date; run it again.",
  profile_window: "The campaign profile changed and the shadow has not covered a full window yet.",
  job_running: "A retrain or recheck job is running.",
  no_previous: "There is no previous version to roll back to.",
  state_changed: "The state changed while you were acting; reload and try again.",
};

export type RefusalContext = "retrain" | "breaker" | "action";

// Retrain and breaker refusals carry a fixed message and no codes, so the wording comes from the endpoint.
const CONTEXT_TEXT: Partial<Record<RefusalContext, string>> = {
  retrain: "The retrain was refused: a job may already be running, or the data is not ready.",
};

const FALLBACK = "The server could not apply the change.";

type Conflict = { response?: { status?: number; data?: { detail?: unknown; codes?: unknown } } };

export function refusalMessage(error: unknown, context: RefusalContext = "action"): string {
  const res = (error as Conflict | null)?.response;
  if (res?.status !== 409) return "Could not reach the server; nothing was changed.";
  const codes = Array.isArray(res.data?.codes) ? (res.data.codes as string[]) : [];
  if (codes.length) return codes.map((c) => CODE_TEXT[c] ?? c).join(" ");
  const ctx = CONTEXT_TEXT[context];
  if (ctx) return ctx;
  return typeof res.data?.detail === "string" && res.data.detail ? res.data.detail : FALLBACK;
}
