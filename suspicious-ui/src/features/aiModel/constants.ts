/** Mirrors of server limits the response does not carry; keep in step with the backend. */
/** registry.MAX_SHADOW_MIN_DAYS */
export const MAX_SHADOW_DAYS = 365;
/** promotion.SHADOW_MIN_RESULTS */
export const SHADOW_MIN_RESULTS = 500;
/** Ruling G12: poll while a recheck or retrain job runs. */
export const JOB_POLL_MS = 10_000;
/** Longest note the resolve endpoint accepts (ResolveSerializer). */
export const RESOLVE_NOTE_MAX = 2000;
