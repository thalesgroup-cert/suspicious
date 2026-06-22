import { Box, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";

import type { PcaPoint } from "@/features/campaigns/api";
import { classColor } from "@/features/campaigns/utils";

export function ClassificationTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ value?: number; color?: string }>;
  label?: string;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  if (!active || !payload?.length) return null;

  const value = payload[0]?.value ?? 0;
  const color = payload[0]?.color ?? classColor(label || "UNKNOWN");

  return (
    <Box
      sx={{
        background: isDark
          ? "rgba(15,23,42,0.95)"
          : alpha(theme.palette.background.paper, 0.97),
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
        borderRadius: 2,
        px: 1.25,
        py: 1,
        backdropFilter: "blur(6px)",
        minWidth: 130,
      }}
    >
      <Typography
        sx={{ fontSize: 12, fontWeight: 700, color: "text.primary", mb: 0.5 }}
      >
        {label}
      </Typography>
      <Typography sx={{ fontSize: 12, fontWeight: 600, color }}>
        Value: {value}
      </Typography>
    </Box>
  );
}

export function PcaTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ payload?: PcaPoint }>;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  if (!active || !payload?.length) return null;

  const point = payload[0]?.payload;
  if (!point) return null;

  const refs = Array.isArray(point.sourceRefs) ? point.sourceRefs : [];

  return (
    <Box
      sx={{
        background: isDark
          ? "rgba(15,23,42,0.96)"
          : alpha(theme.palette.background.paper, 0.97),
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
        borderRadius: 2,
        px: 1.25,
        py: 1,
        minWidth: 200,
        maxWidth: 300,
        backdropFilter: "blur(6px)",
      }}
    >
      {/* Verdict label */}
      <Typography
        sx={{ fontSize: 12, fontWeight: 800, color: "text.primary", mb: 0.5 }}
      >
        {point.label || "UNKNOWN"}
      </Typography>

      {/* Mail subject — primary context line */}
      {point.mail_subject ? (
        <Typography
          sx={{
            fontSize: 12,
            color: "text.primary",
            mb: 0.5,
            fontStyle: "italic",
            overflow: "hidden",
            textOverflow: "ellipsis",
            display: "-webkit-box",
            WebkitLineClamp: 2,
            WebkitBoxOrient: "vertical",
          }}
        >
          {point.mail_subject}
        </Typography>
      ) : null}

      {/* Case ID */}
      {point.suspicious_case_id ? (
        <Typography sx={{ fontSize: 11, color: "text.secondary", mb: 0.5 }}>
          Case #{point.suspicious_case_id}
        </Typography>
      ) : null}

      {/* Campaign source refs */}
      {refs.length ? (
        <Typography
          sx={{
            fontSize: 11,
            color: isDark ? "#93C5FD" : theme.palette.primary.main,
            wordBreak: "break-word",
          }}
        >
          {refs.slice(0, 3).join(", ")}
          {refs.length > 3 ? "…" : ""}
        </Typography>
      ) : (
        <Typography sx={{ fontSize: 11, color: "text.disabled" }}>
          No campaign refs
        </Typography>
      )}
    </Box>
  );
}

export function VolumeTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{
    dataKey?: string;
    name?: string;
    value?: number;
    color?: string;
  }>;
  label?: string;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  if (!active || !payload?.length) return null;

  return (
    <Box
      sx={{
        background: isDark
          ? "rgba(15,23,42,0.95)"
          : alpha(theme.palette.background.paper, 0.97),
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
        borderRadius: 2,
        px: 1.5,
        py: 1,
        backdropFilter: "blur(6px)",
      }}
    >
      <Typography
        sx={{ fontSize: 12, fontWeight: 700, color: "text.primary", mb: 0.5 }}
      >
        {label}
      </Typography>
      {payload.map((p) => (
        <Typography
          key={p.dataKey}
          sx={{ fontSize: 12, fontWeight: 600, color: p.color }}
        >
          {p.name}: {p.value}
        </Typography>
      ))}
    </Box>
  );
}
