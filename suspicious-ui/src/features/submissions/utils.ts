import type {
  SubmissionOrdering,
  SubmissionResult,
  SubmissionStatus,
  SubmissionType,
} from "@/features/submissions/api";

export {
  clamp,
  normalizeScore,
  normalizeConfidence,
  getRiskTone,
  getConfidenceTone,
  readStatus,
  readType,
  summarizeForReading,
  prettySummary,
  fmtDate,
  kindLabel,
  groupReportsByArtifact,
  type ReportGroup,
  type ReportLike,
} from "@/shared/lib/scoreUtils";
import { getRiskTone } from "@/shared/lib/scoreUtils";

// Submissions-specific helpers

export function prettyResult(result?: SubmissionResult) {
  switch (result) {
    case "SAFE": return "Safe";
    case "INCONCLUSIVE": return "Inconclusive";
    case "UNCHALLENGED": return "Unchallenged";
    case "ALLOW_LISTED": return "Allow listed";
    case "FAILURE": return "Failure";
    case "SUSPICIOUS": return "Suspicious";
    case "DANGEROUS": return "Dangerous";
    default: return result || "Unknown";
  }
}

export function withinDates(rowIso: string, from?: string, to?: string) {
  if (!from && !to) return true;
  const t = new Date(rowIso).getTime();
  if (Number.isNaN(t)) return true;

  if (from) {
    const f = new Date(from + "T00:00:00").getTime();
    if (!Number.isNaN(f) && t < f) return false;
  }
  if (to) {
    const tt = new Date(to + "T23:59:59").getTime();
    if (!Number.isNaN(tt) && t > tt) return false;
  }
  return true;
}

export function toBackendOrdering(
  sort: "date_desc" | "date_asc" | "id_desc" | "id_asc"
): SubmissionOrdering {
  if (sort === "date_desc") return "-created_at";
  if (sort === "date_asc") return "created_at";
  if (sort === "id_desc") return "-id";
  return "id";
}

/** Only a successful run carries a risk signal; failed or unfinished runs have none. */
export const reportSucceeded = (r: { status?: string | null }) => String(r.status ?? "").toLowerCase() === "success";

/**
 * Label for a run that did not succeed. Backend statuses: Waiting, InProgress, Success, Failure, Deleted.
 * Only Failure is a failure: Deleted means Cortex no longer has the job (it may have succeeded once).
 */
export function unfinishedLabel(status?: string | null): "Running" | "Queued" | "Expired" | "Failed" | "Unknown" {
  const s = String(status ?? "").toLowerCase();
  if (s === "inprogress") return "Running";
  if (s === "waiting") return "Queued";
  if (s === "deleted") return "Expired";
  if (s === "failure") return "Failed";
  return "Unknown";
}

/** Theme palette key for a risk tone, so each theme paints risk in its own tuned error/warning/success. */
export function riskPalette(score?: number | null): "error" | "warning" | "success" {
  const label = getRiskTone(score).label;
  return label === "High risk" ? "error" : label === "Needs attention" ? "warning" : "success";
}

// Constants

export const STATUS_OPTIONS: Array<SubmissionStatus | "ALL"> = [
  "ALL", "NEW", "IN_PROGRESS", "DONE", "CHALLENGED", "UNKNOWN",
];

export const TYPE_OPTIONS: Array<SubmissionType | "ALL"> = [
  "ALL", "FILE", "MAIL", "URL", "IP", "HASH", "UNKNOWN",
];

export const RESULT_OPTIONS: Array<SubmissionResult | "ALL"> = [
  "ALL", "DANGEROUS", "SUSPICIOUS", "INCONCLUSIVE", "SAFE",
  "FAILURE", "UNCHALLENGED", "ALLOW_LISTED", "UNKNOWN",
];
