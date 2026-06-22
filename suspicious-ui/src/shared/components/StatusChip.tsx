//
// Renders a submission status badge whose color comes from the semantic
// color store (useStatusColors). Switching to the Okabe-Ito colorblind-safe
// preset in ProfilePage updates these chips everywhere immediately.
//
// Color + icon dual encoding: every status has a distinct icon so color
// is never the sole differentiator — accessible by design.

import * as React from "react";
import {
  HourglassTopOutlined,
  CheckCircleOutlined,
  ErrorOutlineOutlined,
  ReportProblemOutlined,
  HelpOutlineOutlined,
  NewReleasesOutlined,
} from "@mui/icons-material";
import { useStatusColors } from "@/styles/colorStore";
import { Badge } from "@/shared/components/Badge";
import type { StatusKey } from "@/styles/colorStore";

// SubmissionStatus values as they arrive from the API
export type SubmissionStatus =
  | "NEW"
  | "IN_PROGRESS"
  | "DONE"
  | "FAILED"
  | "REJECTED"
  | "CHALLENGED"
  | "UNKNOWN";

// Maps each API status to:
//   storeKey — the StatusKey used to look up the hex color
//   label    — display text
//   icon     — distinct icon (color is never the sole indicator)
const STATUS_META: Record<
  SubmissionStatus | "UNKNOWN",
  { storeKey: StatusKey; label: string; icon: React.ReactNode }
> = {
  NEW: {
    storeKey: "new",
    label:    "NEW",
    icon:     <NewReleasesOutlined fontSize="small" />,
  },
  IN_PROGRESS: {
    storeKey: "in_progress",
    label:    "IN PROGRESS",
    icon:     <HourglassTopOutlined fontSize="small" />,
  },
  DONE: {
    storeKey: "done",
    label:    "DONE",
    icon:     <CheckCircleOutlined fontSize="small" />,
  },
  FAILED: {
    storeKey: "failure",
    label:    "FAILED",
    icon:     <ErrorOutlineOutlined fontSize="small" />,
  },
  REJECTED: {
    storeKey: "failure",       // rejected = processing failed
    label:    "REJECTED",
    icon:     <ReportProblemOutlined fontSize="small" />,
  },
  CHALLENGED: {
    storeKey: "challenged",
    label:    "CHALLENGED",
    icon:     <ReportProblemOutlined fontSize="small" />,
  },
  UNKNOWN: {
    storeKey: "unknown",
    label:    "UNKNOWN",
    icon:     <HelpOutlineOutlined fontSize="small" />,
  },
};

export function StatusChip({
  status,
  minWidth,
}: {
  status: SubmissionStatus | string;
  minWidth?: number;
}) {
  const statusColors = useStatusColors();

  const key = ((status ?? "UNKNOWN") as string).toUpperCase() as SubmissionStatus | "UNKNOWN";
  const meta = STATUS_META[key] ?? STATUS_META.UNKNOWN;
  const hex  = statusColors[meta.storeKey]?.main;

  return (
    <Badge
      label={meta.label}
      color={hex}
      icon={meta.icon}
      minWidth={minWidth ?? 128}
    />
  );
}