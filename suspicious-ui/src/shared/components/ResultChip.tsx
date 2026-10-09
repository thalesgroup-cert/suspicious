
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

function metaFor(result: string): ResultMeta {
  const key = (result ?? "UNKNOWN").toUpperCase();
  return RESULT_META[key] ?? {
    group:    "status",
    storeKey: "unknown",
    label:    key,
    icon:     <HelpOutlineOutlined fontSize="small" />,
  } satisfies ResultMeta;
}

/** The user's colour for a verdict (same mapping as the chip); the neutral "unknown" colour otherwise. */
// Kept beside RESULT_META so the chip and the drawer accent can never disagree; costs only fast-refresh of this file.
// eslint-disable-next-line react-refresh/only-export-components
export function useResultHex(result: string): string | undefined {
  const resultColors = useResultColors();
  const statusColors  = useStatusColors();
  const meta = metaFor(result);
  return meta.group === "result"
    ? resultColors[meta.storeKey as ResultKey]?.main
    : statusColors[meta.storeKey as StatusKey]?.main;
}

export function ResultChip({
  result,
  minWidth,
  size,
}: {
  result: string;
  minWidth?: number;
  size?: "small" | "medium";
}) {
  const meta = metaFor(result);
  const hex = useResultHex(result);

  return (
    <Badge
      label={meta.label}
      color={hex}
      icon={meta.icon}
      minWidth={minWidth ?? 128}
      size={size}
    />
  );
}