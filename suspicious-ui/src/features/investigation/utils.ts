import type { InvestigationDetails } from "@/features/investigation/api";

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

// ---------------------------------------------------------------------------
// Investigation-specific helpers
// ---------------------------------------------------------------------------

export function short(s: string, n = 42) {
  const t = (s ?? "").trim();
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
}

export function pickScore(d?: InvestigationDetails) {
  return d?.case_infos?.score ?? null;
}
export function pickConfidence(d?: InvestigationDetails) {
  return d?.case_infos?.confidence ?? null;
}
export function pickClassification(d?: InvestigationDetails) {
  return d?.case_infos?.classification ?? "UNKNOWN";
}
