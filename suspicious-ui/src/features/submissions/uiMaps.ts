// src/features/submissions/uiMaps.ts

import type {
  SubmissionStatus,
  SubmissionResult,
} from "@/features/submissions/api";

type MuiTone = "success" | "warning" | "error" | "info";

export const STATUS_META: Record<
  SubmissionStatus,
  { label: string; muiColor?: MuiTone }
> = {
  NEW: {
    label: "New",
    muiColor: "info",
  },

  IN_PROGRESS: {
    label: "In progress",
    muiColor: "warning",
  },

  DONE: {
    label: "Completed",
    muiColor: "success",
  },

  CHALLENGED: {
    label: "Challenged",
    muiColor: "warning",
  },

  UNKNOWN: {
    label: "Unknown",
  },
};

export const RESULT_META: Record<
  SubmissionResult,
  { label: string; muiColor?: MuiTone }
> = {
  SAFE: {
    label: "Safe",
    muiColor: "success",
  },

  ALLOW_LISTED: {
    label: "Allow listed",
    muiColor: "success",
  },

  SUSPICIOUS: {
    label: "Suspicious",
    muiColor: "warning",
  },

  INCONCLUSIVE: {
    label: "Inconclusive",
    muiColor: "info",
  },

  UNCHALLENGED: {
    label: "Unchallenged",
    muiColor: "info",
  },

  DANGEROUS: {
    label: "Dangerous",
    muiColor: "error",
  },

  FAILURE: {
    label: "Failure",
    muiColor: "error",
  },

  UNKNOWN: {
    label: "Unknown",
  },
};