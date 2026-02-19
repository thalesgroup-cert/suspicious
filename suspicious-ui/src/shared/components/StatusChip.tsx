// src/shared/components/StatusChip.tsx
import * as React from "react";
import HourglassTopOutlined from "@mui/icons-material/HourglassTopOutlined";
import CheckCircleOutlined from "@mui/icons-material/CheckCircleOutlined";
import ErrorOutlineOutlined from "@mui/icons-material/ErrorOutlineOutlined";
import ReportProblemOutlined from "@mui/icons-material/ReportProblemOutlined";
import type { SubmissionStatus } from "@/shared/hooks/api";
import { Badge } from "@/shared/components/Badge";

const STATUS_META: Record<
  SubmissionStatus | "UNKNOWN",
  { label: string; color: "success" | "warning" | "error" | "info" | "default"; icon: React.ReactNode }
> = {
  NEW: { label: "NEW", color: "info", icon: <HourglassTopOutlined fontSize="small" /> },
  IN_PROGRESS: { label: "IN PROGRESS", color: "warning", icon: <HourglassTopOutlined fontSize="small" /> },
  DONE: { label: "DONE", color: "success", icon: <CheckCircleOutlined fontSize="small" /> },
  FAILED: { label: "FAILED", color: "error", icon: <ErrorOutlineOutlined fontSize="small" /> },
  REJECTED: { label: "REJECTED", color: "error", icon: <ReportProblemOutlined fontSize="small" /> },
  UNKNOWN: { label: "UNKNOWN", color: "default", icon: <ErrorOutlineOutlined fontSize="small" /> },
};

export function StatusChip({ status, minWidth }: { status: SubmissionStatus; minWidth?: number }) {
  const s = ((status ?? "UNKNOWN") as string).toUpperCase() as SubmissionStatus | "UNKNOWN";
  const m = STATUS_META[s] ?? STATUS_META.UNKNOWN;
  return <Badge label={m.label} color={m.color} icon={m.icon} minWidth={minWidth ?? 128} />;
}
