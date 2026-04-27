// src/features/dashboard/components/ThreatDistributionPanel.tsx
import * as React from "react";
import { Box, Chip, Stack, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { alpha } from "@mui/material/styles";
import { ShieldOutlined } from "@mui/icons-material";
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
} from "recharts";

import { SoftCard } from "./SoftCard";
import { useResultColors, useStatusColors } from "@/styles/colorStore";
import { useThemeMode } from "@/styles/ThemeStore";

type DangerCounts = {
  failure: number;
  safe: number;
  inconclusive: number;
  suspicious: number;
  dangerous: number;
};

const DANGER_ORDER = ["Failure", "Safe", "Inconclusive", "Suspicious", "Dangerous"] as const;
type DangerLabel = (typeof DANGER_ORDER)[number];

function sum(values: number[]) {
  return values.reduce((a, b) => a + b, 0);
}

function toDonut(d: DangerCounts, colors: Record<DangerLabel, string>) {
  return (DANGER_ORDER as readonly DangerLabel[])
    .map((name) => {
      const key = name.toLowerCase() as keyof DangerCounts;
      const value = (d[key] ?? 0) as number;
      return { name, value, color: colors[name] };
    })
    .filter((x) => x.value > 0);
}

function ThreatTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; color?: string }>;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  if (!active || !payload?.length) return null;

  const item = payload[0];
  const label = item?.name ?? "Unknown";
  const value = item?.value ?? 0;
  const color = item?.color ?? "#94A3B8";

  return (
    <Box
      sx={{
        background: isDark ? "rgba(15,23,42,0.95)" : alpha(theme.palette.background.paper, 0.97),
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
        borderRadius: 2,
        px: 1.25,
        py: 1,
        backdropFilter: "blur(6px)",
        minWidth: 130,
      }}
    >
      <Typography sx={{ fontSize: 12, fontWeight: 700, mb: 0.5, color: "text.primary" }}>
        {label}
      </Typography>
      <Typography sx={{ fontSize: 12, fontWeight: 600, color }}>
        Value: {typeof value === "number" ? value.toLocaleString() : "—"}
      </Typography>
    </Box>
  );
}

export default function ThreatDistributionPanel(props: { dangerCounts: DangerCounts }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const { capabilities } = useThemeMode();
  const { effects } = capabilities;

  // Read from the user's semantic color store so this panel respects
  // colorblind-safe presets and custom color choices from ProfilePage.
  const resultColors = useResultColors();
  const statusColors  = useStatusColors();

  // Map the DangerLabel keys to their semantic color store equivalents.
  // "Failure" maps to status.failure (not a result) — it's a processing
  // failure, not an analysis outcome, so it reads from statusColors.
  const dangerColors: Record<DangerLabel, string> = React.useMemo(() => ({
    Safe:         resultColors.safe.main,
    Suspicious:   resultColors.suspicious.main,
    Dangerous:    resultColors.dangerous.main,
    Inconclusive: resultColors.inconclusive.main,
    Failure:      statusColors.failure.main,
  }), [resultColors, statusColors]);

  const donut = React.useMemo(
    () => toDonut(props.dangerCounts, dangerColors),
    [props.dangerCounts, dangerColors]
  );
  const total = React.useMemo(() => sum(donut.map((d) => d.value)), [donut]);
  const danger = props.dangerCounts;

  // donut stroke adapts to theme
  const donutStroke = isDark ? "rgba(255,255,255,.10)" : alpha(theme.palette.divider, 0.35);
  // legend dot border adapts to theme
  const dotBorder = isDark ? "rgba(255,255,255,.18)" : alpha(theme.palette.divider, 0.5);

  return (
    <SoftCard
      title="Threat distribution"
      icon={<ShieldOutlined />}
      right={<Chip size="small" label="Monthly" variant="outlined" />}
      fillHeight
    >
      <Box
        className={effects.hasHeatEffect ? "sun-orb" : undefined}
        sx={{ flex: 1, minHeight: 220 }}
      >
        {donut.length ? (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={donut}
                dataKey="value"
                nameKey="name"
                innerRadius={66}
                outerRadius={90}
                isAnimationActive={false}
                stroke={donutStroke}
                strokeWidth={1}
              >
                {donut.map((entry) => (
                  <Cell key={entry.name} fill={dangerColors[entry.name as DangerLabel]} />
                ))}
              </Pie>

              <text x="50%" y="47%" textAnchor="middle" dominantBaseline="central">
                <tspan
                  style={{
                    fontWeight: 950,
                    fontSize: 24,
                    fill: theme.palette.text.primary,
                  }}
                >
                  {total}
                </tspan>
              </text>
              <text x="50%" y="60%" textAnchor="middle" dominantBaseline="central">
                <tspan
                  style={{
                    opacity: 0.72,
                    fontSize: 12,
                    fill: theme.palette.text.secondary,
                  }}
                >
                  signals
                </tspan>
              </text>

              <RechartsTooltip content={<ThreatTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <Stack sx={{ height: "100%" }} alignItems="center" justifyContent="center">
            <Typography color="text.secondary" variant="body2">No data</Typography>
          </Stack>
        )}
      </Box>

      <Stack spacing={0.7} sx={{ mt: 1, flexShrink: 0 }}>
        {(DANGER_ORDER as readonly DangerLabel[]).map((label) => {
          const key = label.toLowerCase() as keyof DangerCounts;
          const value = (danger[key] ?? 0) as number;

          return (
            <Stack
              key={label}
              direction="row"
              justifyContent="space-between"
              alignItems="center"
              className={effects.hasContaminationEffect && label === "Dangerous" ? "contaminated" : undefined}
            >
              <Stack direction="row" spacing={1} alignItems="center">
                <Box
                  aria-hidden
                  sx={{
                    width: 10,
                    height: 10,
                    borderRadius: 99,
                    backgroundColor: dangerColors[label],
                    border: `1px solid ${dotBorder}`,
                  }}
                />
                <Typography
                  variant="body2"
                  sx={{ fontWeight: 500, fontSize: 14 }}
                  color="text.secondary"
                >
                  {label}
                </Typography>
              </Stack>
              <Typography
                variant="body2"
                sx={{ fontWeight: 900, fontSize: 14 }}
                color="text.primary"
              >
                {value.toLocaleString()}
              </Typography>
            </Stack>
          );
        })}
      </Stack>
    </SoftCard>
  );
}