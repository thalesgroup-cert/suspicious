import type { ComponentType } from "react";
import CheckCircle from "@mui/icons-material/CheckCircle";
import ErrorOutlined from "@mui/icons-material/ErrorOutlined";
import InfoOutlined from "@mui/icons-material/InfoOutlined";
import RemoveCircleOutlined from "@mui/icons-material/RemoveCircleOutlined";
import WarningAmber from "@mui/icons-material/WarningAmber";
import { Box } from "@mui/material";
import type { SvgIconProps } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import { ensureContrast, flatten } from "@/shared/lib/contrast";
import { useResultColors } from "@/styles/colorStore";
import type { Connector } from "./connectors";

export type StatusTone = "ok" | "warning" | "danger" | "neutral" | "info";

const ICONS: Record<StatusTone, ComponentType<SvgIconProps>> = {
  ok: CheckCircle,
  warning: WarningAmber,
  danger: ErrorOutlined,
  neutral: RemoveCircleOutlined,
  info: InfoOutlined,
};

/** Icon + word, never colour alone. Palette colours are pushed to 4.5:1 (text) and 3:1 (icon) on the page paper. */
export function StatusLabel({ tone, label, size = "medium" }: { tone: StatusTone; label: string; size?: "small" | "medium" }) {
  const theme = useTheme();
  const result = useResultColors();
  const paper = theme.palette.background.paper;
  const base = {
    ok: result.safe.main,
    warning: result.suspicious.main,
    danger: result.dangerous.main,
    // text.secondary and primary can be translucent or non-hex; flattening gives the opaque colour the user sees.
    neutral: flatten(theme.palette.text.secondary, paper),
    info: flatten(theme.palette.primary.main, paper),
  }[tone];
  const Icon = ICONS[tone];
  const small = size === "small";
  return (
    <Box sx={{ display: "inline-flex", alignItems: "center", gap: 0.5, minWidth: 0 }}>
      <Icon sx={{ fontSize: small ? 16 : 20, color: ensureContrast(base, paper, 3), flexShrink: 0 }} />
      <Box
        component="span"
        sx={{
          color: ensureContrast(base, paper, 4.5),
          typography: small ? "caption" : "body2",
        }}
      >
        {label}
      </Box>
    </Box>
  );
}

/**
 * Unhealthy wins over connected, but never over disabled; an unknown health (null) says nothing.
 * Lives beside the label so panels import both from one file.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function connectorStatus(c: Pick<Connector, "status" | "last_health_ok">): { tone: StatusTone; label: string } {
  if (c.status === "disabled") return { tone: "neutral", label: "Disabled" };
  if (c.last_health_ok === false) return { tone: "danger", label: "Unhealthy" };
  return c.status === "connected" ? { tone: "ok", label: "Connected" } : { tone: "warning", label: "Incomplete" };
}
