
import * as React from "react";
import {
  CheckCircleOutlined,
  WarningAmberOutlined,
  ErrorOutlined,
  HelpOutlineOutlined,
  RemoveCircleOutlineOutlined,
  GppBadOutlined,
} from "@mui/icons-material";
import { useResultColors, useStatusColors } from "@/styles/colorStore";
import { Badge } from "@/shared/components/Badge";
import type { ResultKey, StatusKey } from "@/styles/colorStore";

type ResultMeta = {
  group:    "result" | "status";
  storeKey: ResultKey | StatusKey;
  label:    string;
  icon:     React.ReactNode;
};

const RESULT_META: Record<string, ResultMeta> = {
  SAFE: {
    group:    "result",
    storeKey: "safe",
    label:    "SAFE",
    icon:     <CheckCircleOutlined fontSize="small" />,
  },
  "SAFE-ALLOW_LISTED": {
    group:    "result",
    storeKey: "safe",
    label:    "SAFE",
    icon:     <CheckCircleOutlined fontSize="small" />,
  },
  ALLOW_LISTED: {
    group:    "result",
    storeKey: "safe",
    label:    "ALLOW-LISTED",
    icon:     <CheckCircleOutlined fontSize="small" />,
  },
  SUSPICIOUS: {
    group:    "result",
    storeKey: "suspicious",
    label:    "SUSPICIOUS",
    icon:     <WarningAmberOutlined fontSize="small" />,
  },
  UNWANTED: {
    group:    "result",
    storeKey: "suspicious",
    label:    "UNWANTED",
    icon:     <WarningAmberOutlined fontSize="small" />,
  },
  INCONCLUSIVE: {
    group:    "result",
    storeKey: "inconclusive",
    label:    "INCONCLUSIVE",
    icon:     <RemoveCircleOutlineOutlined fontSize="small" />,
  },
  DANGEROUS: {
    group:    "result",
    storeKey: "dangerous",
    label:    "DANGEROUS",
    icon:     <ErrorOutlined fontSize="small" />,
  },
  MALICIOUS: {
    group:    "result",
    storeKey: "dangerous",
    label:    "MALICIOUS",
    icon:     <GppBadOutlined fontSize="small" />,
  },
  FAILURE: {
    group:    "status",
    storeKey: "failure",
    label:    "FAILURE",
    icon:     <ErrorOutlined fontSize="small" />,
  },
  FAILED: {
    group:    "status",
    storeKey: "failure",
    label:    "FAILED",
    icon:     <ErrorOutlined fontSize="small" />,
  },
  UNKNOWN: {
    group:    "status",
    storeKey: "unknown",
    label:    "UNKNOWN",
    icon:     <HelpOutlineOutlined fontSize="small" />,
  },
};

export function ResultChip({
  result,
  minWidth,
}: {
  result: string;
  minWidth?: number;
}) {
  const resultColors = useResultColors();
  const statusColors  = useStatusColors();

  const key  = (result ?? "UNKNOWN").toUpperCase();
  const meta = RESULT_META[key] ?? {
    group:    "status",
    storeKey: "unknown",
    label:    key,
    icon:     <HelpOutlineOutlined fontSize="small" />,
  } satisfies ResultMeta;

  const hex =
    meta.group === "result"
      ? resultColors[meta.storeKey as ResultKey]?.main
      : statusColors[meta.storeKey as StatusKey]?.main;

  return (
    <Badge
      label={meta.label}
      color={hex}
      icon={meta.icon}
      minWidth={minWidth ?? 128}
    />
  );
}