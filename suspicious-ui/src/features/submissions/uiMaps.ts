// src/features/submissions/uiMaps.ts
import type { SubmissionStatus } from "@/features/submissions/api";

export const STATUS_META: Record<
  SubmissionStatus | "UNKNOWN",
  { label: string; muiColor?: "success" | "warning" | "error" | "info" }
> = {
  NEW: { label: "New", muiColor: "info" },
  IN_PROGRESS: { label: "In progress", muiColor: "warning" },
  DONE: { label: "Done", muiColor: "success" },
  FAILED: { label: "Failed", muiColor: "error" },
  REJECTED: { label: "Rejected", muiColor: "error" },
  CHALLENGED: { label: "Challenged", muiColor: "warning" },
  UNKNOWN: { label: "Unknown" },
};

export const RESULT_META: Record<
  string,
  { label: string; muiColor?: "success" | "warning" | "error" | "info" }
> = {
  SAFE: { label: "Safe", muiColor: "success" },
  "SAFE-ALLOW_LISTED": { label: "Safe", muiColor: "success" },
  SUSPICIOUS: { label: "Suspicious", muiColor: "warning" },
  UNWANTED: { label: "Unwanted", muiColor: "warning" },
  INCONCLUSIVE: { label: "Inconclusive", muiColor: "info" },
  DANGEROUS: { label: "Dangerous", muiColor: "error" },
  MALICIOUS: { label: "Malicious", muiColor: "error" },
  FAILURE: { label: "Failure" },
  FAILED: { label: "Failed" },
  UNKNOWN: { label: "Unknown" },
};
