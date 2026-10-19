import type { ComponentType } from "react";
import CheckCircle from "@mui/icons-material/CheckCircle";
import ErrorOutlined from "@mui/icons-material/ErrorOutlined";
import InfoOutlined from "@mui/icons-material/InfoOutlined";
import RemoveCircleOutlined from "@mui/icons-material/RemoveCircleOutlined";
import WarningAmber from "@mui/icons-material/WarningAmber";
import { Box } from "@mui/material";
import type { SvgIconProps } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import { composite, ensureContrast, flatten } from "@/shared/lib/contrast";
import { useResultColors } from "@/styles/colorStore";
import { CONNECTOR_STATUS_LABEL } from "../labels";
import type { Connector } from "./connectors";

export type StatusTone = "ok" | "warning" | "danger" | "neutral" | "info";

const ICONS: Record<StatusTone, ComponentType<SvgIconProps>> = {
  ok: CheckCircle,
  warning: WarningAmber,
  danger: ErrorOutlined,
  neutral: RemoveCircleOutlined,
  info: InfoOutlined,
};

/** Icon + word, never colour alone. Palette colours are pushed to 4.5:1 (text) and 3:1 (icon) on every surface the label sits on. */
export function StatusLabel({ tone, label, size = "medium" }: { tone: StatusTone; label: string; size?: "small" | "medium" }) {
  const theme = useTheme();
  const result = useResultColors();
  const paper = theme.palette.background.paper;
  const primary = flatten(theme.palette.primary.main, paper);
  // Paper, a hovered selected connector row (primary tint, AppLayout/ConnectorList) and the bare shell (AppLayout's primary glow over the page colour).
  const surfaces = [
    paper,
    composite(primary, theme.palette.mode === "dark" ? 0.2 : 0.12, paper),
    composite(primary, 0.07, theme.palette.background.default),
  ];
  const readable = (color: string, min: number) => surfaces.reduce((out, bg) => ensureContrast(out, bg, min), color);
  const base = {
    ok: result.safe.main,
    warning: result.suspicious.main,
    danger: result.dangerous.main,
    // text.secondary and primary can be translucent or non-hex; flattening gives the opaque colour the user sees.
    neutral: flatten(theme.palette.text.secondary, paper),
    info: primary,
  }[tone];
  const Icon = ICONS[tone];
  const small = size === "small";
  return (
    <Box sx={{ display: "inline-flex", alignItems: "center", gap: 0.5, minWidth: 0 }}>
      <Icon data-tone={tone} sx={{ fontSize: small ? 16 : 20, color: readable(base, 3), flexShrink: 0 }} />
      <Box
        component="span"
        sx={{
          color: readable(base, 4.5),
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
  const label = CONNECTOR_STATUS_LABEL[c.status];
  if (c.status === "disabled") return { tone: "neutral", label };
  if (c.last_health_ok === false) return { tone: "danger", label: "Unhealthy" };
  return { tone: c.status === "connected" ? "ok" : "warning", label };
}
