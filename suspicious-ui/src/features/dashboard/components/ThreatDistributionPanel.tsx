// file: src/features/dashboard/components/ThreatDistributionPanel.tsx
import * as React from "react";
import { Box, Chip, Divider, Stack, Typography } from "@mui/material";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip as RechartsTooltip } from "recharts";

type DangerCounts = {
  failure: number;
  safe: number;
  inconclusive: number;
  suspicious: number;
  dangerous: number;
  malicious: number;
};

const DANGER_ORDER = ["Failure", "Safe", "Inconclusive", "Suspicious", "Dangerous", "Malicious"] as const;
type DangerLabel = (typeof DANGER_ORDER)[number];

// Same palette as HomePage. If you want to avoid hardcoding, move these into theme tokens later.
const DANGER_COLORS: Record<DangerLabel, string> = {
  Failure: "#64748B", // slate
  Safe: "#22C55E", // green
  Inconclusive: "#A3A3A3", // neutral
  Suspicious: "#F59E0B", // amber
  Dangerous: "#F97316", // orange
  Malicious: "#EF4444", // red
};

function sum(values: number[]) {
  return values.reduce((a, b) => a + b, 0);
}

function toDonut(d: DangerCounts) {
  return (DANGER_ORDER as readonly DangerLabel[])
    .map((name) => {
      const key = name.toLowerCase() as keyof DangerCounts;
      const value = (d[key] ?? 0) as number;
      return { name, value };
    })
    .filter((x) => x.value > 0);
}

export default function ThreatDistributionPanel(props: { dangerCounts: DangerCounts }) {
  const donut = React.useMemo(() => toDonut(props.dangerCounts), [props.dangerCounts]);
  const total = React.useMemo(() => sum(donut.map((d) => d.value)), [donut]);

  const danger = props.dangerCounts;

  return (
    <Box
      sx={{
        borderRadius: 3,
        border: "1px solid",
        borderColor: "divider",
        bgcolor: "background.paper",
        p: 2,
      }}
    >
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
        <Typography sx={{ fontWeight: 900, fontSize: 14 }}>Threat distribution</Typography>
        <Chip size="small" label="Monthly" variant="outlined" />
      </Stack>

      <Divider sx={{ mb: 1.5, opacity: 0.35 }} />

      <Box sx={{ height: 220 }}>
        {donut.length ? (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={donut}
                dataKey="value"
                nameKey="name"
                innerRadius={62}
                outerRadius={86}
                isAnimationActive={false}
                stroke="rgba(255,255,255,.10)"
                strokeWidth={1}
              >
                {donut.map((entry) => (
                  <Cell key={entry.name} fill={DANGER_COLORS[entry.name as DangerLabel]} />
                ))}
              </Pie>

              {/* center total */}
              <text x="50%" y="48%" textAnchor="middle" dominantBaseline="central">
                <tspan style={{ fontWeight: 950, fontSize: 22, fill: "white" }}>{total}</tspan>
              </text>
              <text x="50%" y="60%" textAnchor="middle" dominantBaseline="central">
                <tspan style={{ opacity: 0.75, fontSize: 12, fill: "white" }}>signals</tspan>
              </text>

              <RechartsTooltip
                formatter={(v: any) => (typeof v === "number" ? v.toLocaleString() : "—")}
              />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <Stack sx={{ height: "100%" }} alignItems="center" justifyContent="center">
            <Typography color="text.secondary" variant="body2">
              No data
            </Typography>
          </Stack>
        )}
      </Box>

      <Stack spacing={0.6} sx={{ mt: 1 }}>
        {(DANGER_ORDER as readonly DangerLabel[]).map((label) => {
          const key = label.toLowerCase() as keyof DangerCounts;
          const value = (danger[key] ?? 0) as number;

          return (
            <Stack key={label} direction="row" justifyContent="space-between" alignItems="center">
              <Stack direction="row" spacing={1} alignItems="center">
                <Box
                  aria-hidden
                  sx={{
                    width: 10,
                    height: 10,
                    borderRadius: 99,
                    backgroundColor: DANGER_COLORS[label],
                    border: "1px solid rgba(255,255,255,.18)",
                  }}
                />
                <Typography variant="body2" color="text.secondary">
                  {label}
                </Typography>
              </Stack>

              <Typography variant="body2" sx={{ fontWeight: 900 }}>
                {value}
              </Typography>
            </Stack>
          );
        })}
      </Stack>
    </Box>
  );
}
