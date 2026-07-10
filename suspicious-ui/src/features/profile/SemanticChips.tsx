
import * as React from "react";
import { Box, Chip, Tooltip } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  CheckCircleOutlined,
  WarningAmberOutlined,
  ErrorOutlined,
  HelpOutlineOutlined,
  TaskAltOutlined,
  SyncOutlined,
  FiberNewOutlined,
  CancelOutlined,
  ReportProblemOutlined,
  DeviceUnknownOutlined,
} from "@mui/icons-material";
import {
  useResultColors,
  useStatusColors,
  hexToBg,
  contrastText,
  type ResultKey,
  type StatusKey,
  RESULT_LABELS,
  STATUS_LABELS,
} from "@/styles/colorStore";

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

const RESULT_ICONS: Record<ResultKey, React.ReactElement> = {
  safe: <CheckCircleOutlined />,
  suspicious: <WarningAmberOutlined />,
  dangerous: <ErrorOutlined />,
  inconclusive: <HelpOutlineOutlined />,
};

const STATUS_ICONS: Record<StatusKey, React.ReactElement> = {
  done: <TaskAltOutlined />,
  in_progress: <SyncOutlined />,
  new: <FiberNewOutlined />,
  failure: <CancelOutlined />,
  challenged: <ReportProblemOutlined />,
  unknown: <DeviceUnknownOutlined />,
};

// ---------------------------------------------------------------------------
// Shared chip renderer
// ---------------------------------------------------------------------------

type SemanticChipProps = {
  /** The hex color for this chip */
  color: string;
  /** Label text */
  label: string;
  /** Icon element */
  icon: React.ReactElement;
  /** Size — small (default) or medium */
  size?: "small" | "medium";
  /** If true renders as a filled pill (e.g. in a table cell badge) */
  filled?: boolean;
  /** Optional tooltip override */
  tooltip?: string;
  /** Optional sx override */
  sx?: object;
};

function SemanticChip({
  color,
  label,
  icon,
  size = "small",
  filled = false,
  tooltip,
  sx,
}: SemanticChipProps) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const bg = filled ? color : hexToBg(color, isDark);
  const border = filled
    ? "none"
    : `1px solid ${alpha(color, isDark ? 0.4 : 0.35)}`;
  const fg = filled ? contrastText(color) : color;

  const chip = (
    <Chip
      size={size}
      icon={React.cloneElement(icon as React.ReactElement<any>, {
        sx: {
          fontSize: size === "small" ? "14px !important" : "16px !important",
          color: `${fg} !important`,
          ml: "6px !important",
        },
      })}
      label={label}
      sx={{
        height: size === "small" ? 24 : 28,
        fontWeight: 800,
        fontSize: size === "small" ? 11 : 12.5,
        letterSpacing: "0.02em",
        bgcolor: bg,
        color: fg,
        border,
        borderRadius: 2,
        transition: "all .15s ease",
        "& .MuiChip-label": { px: 1, lineHeight: 1 },
        ...sx,
      }}
    />
  );

  if (tooltip) {
    return (
      <Tooltip title={tooltip} placement="top" arrow>
        {chip}
      </Tooltip>
    );
  }
  return chip;
}

// ---------------------------------------------------------------------------
// ResultChip — for safe / suspicious / dangerous / inconclusive
// ---------------------------------------------------------------------------

type ResultChipProps = {
  value: ResultKey;
  size?: "small" | "medium";
  filled?: boolean;
  tooltip?: string;
  sx?: object;
};

export function ResultChip({ value, ...rest }: ResultChipProps) {
  const colors = useResultColors();
  return (
    <SemanticChip
      color={colors[value].main}
      label={RESULT_LABELS[value]}
      icon={RESULT_ICONS[value]}
      {...rest}
    />
  );
}

// ---------------------------------------------------------------------------
// StatusChip — for done / in_progress / new / failure / challenged / unknown
// ---------------------------------------------------------------------------

type StatusChipProps = {
  value: StatusKey;
  size?: "small" | "medium";
  filled?: boolean;
  tooltip?: string;
  sx?: object;
};

export function StatusChip({ value, ...rest }: StatusChipProps) {
  const colors = useStatusColors();
  return (
    <SemanticChip
      color={colors[value].main}
      label={STATUS_LABELS[value]}
      icon={STATUS_ICONS[value]}
      {...rest}
    />
  );
}

