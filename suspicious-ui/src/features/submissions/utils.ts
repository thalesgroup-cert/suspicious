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
  getSubCategoryProbabilities,
  type ReportGroup,
  type ReportLike,
  type SubCategoryProbability,
} from "@/shared/lib/scoreUtils";

// ---------------------------------------------------------------------------
// Submissions-specific helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

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
