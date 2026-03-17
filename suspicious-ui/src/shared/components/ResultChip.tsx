// src/shared/components/ResultChip.tsx
import * as React from "react";
import { Badge } from "@/shared/components/Badge";

const RESULT_META: Record<
  string,
  { label: string; color: "success" | "warning" | "error" | "info" | "default" }
> = {
  SAFE: { label: "SAFE", color: "success" },
  "SAFE-ALLOW_LISTED": { label: "SAFE", color: "success" },
  SUSPICIOUS: { label: "SUSPICIOUS", color: "warning" },
  UNWANTED: { label: "UNWANTED", color: "warning" },
  INCONCLUSIVE: { label: "INCONCLUSIVE", color: "info" },
  FAILURE: { label: "FAILURE", color: "default" },
  FAILED: { label: "FAILED", color: "default" },
  DANGEROUS: { label: "DANGEROUS", color: "error" },
  MALICIOUS: { label: "MALICIOUS", color: "error" },
  UNKNOWN: { label: "UNKNOWN", color: "default" },
};

export function ResultChip({ result, minWidth }: { result: string; minWidth?: number }) {
  const r = (result ?? "UNKNOWN").toUpperCase();
  const m = RESULT_META[r] ?? { label: r, color: "default" as const };

  return <Badge label={m.label} color={m.color} minWidth={minWidth ?? 128} />;
}
