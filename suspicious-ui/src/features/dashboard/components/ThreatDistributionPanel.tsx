// file: src/features/dashboard/components/ThreatDistributionPanel.tsx
import * as React from "react";
import { Box, Card, CardContent, Chip, Divider, Stack, Typography } from "@mui/material";
import { ShieldOutlined } from "@mui/icons-material";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip as RechartsTooltip } from "recharts";

type DangerCounts = {
  failure: number;
  safe: number;
  inconclusive: number;
  suspicious: number;
  dangerous: number;
};

const DANGER_ORDER = ["Failure", "Safe", "Inconclusive", "Suspicious", "Dangerous"] as const;
type DangerLabel = (typeof DANGER_ORDER)[number];

const DANGER_COLORS: Record<DangerLabel, string> = {
  Failure: "#64748B",
  Safe: "#22C55E",
  Inconclusive: "#A3A3A3",
  Suspicious: "#F59E0B",
  Dangerous: "#EF4444",
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

function GlassCard(props: React.PropsWithChildren<{
  title: string;
  icon?: React.ReactNode;
  right?: React.ReactNode;
}>) {
  return (
    <Card
      sx={{
        height: "100%",
        borderRadius: 3,
        border: "1px solid rgba(255,255,255,.10)",
        background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
      }}
    >
      <CardContent
        sx={{
          height: "100%",
          p: { xs: 1.5, md: 2 },
          display: "flex",
          flexDirection: "column",
          minHeight: 0,
        }}
      >
        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1, flexShrink: 0 }}>
          <Stack direction="row" spacing={0.9} alignItems="center">
            <Box
              sx={{
                width: 34,
                height: 34,
                borderRadius: 2,
                display: "grid",
                placeItems: "center",
                border: "1px solid rgba(255,255,255,.12)",
                background:
                  "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                "& svg": { fontSize: 18 },
              }}
            >
              {props.icon}
            </Box>
            <Typography fontWeight={900} fontSize={15}>
              {props.title}
            </Typography>
          </Stack>
          {props.right}
        </Stack>

        <Divider sx={{ opacity: 0.25, mb: 1.5, flexShrink: 0 }} />
        <Box sx={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
          {props.children}
        </Box>
      </CardContent>
    </Card>
  );
}

function ThreatTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; color?: string }>;
}) {
  if (!active || !payload?.length) return null;

  const item = payload[0];
  const label = item?.name ?? "Unknown";
  const value = item?.value ?? 0;
  const color = item?.color ?? "#94A3B8";

  return (
    <Box
      sx={{
        background: "rgba(15,23,42,0.95)",
        border: "1px solid rgba(255,255,255,0.12)",
        borderRadius: 2,
        px: 1.25,
        py: 1,
        backdropFilter: "blur(6px)",
        minWidth: 130,
      }}
    >
      <Typography
        sx={{
          fontSize: 12,
          fontWeight: 700,
          color: "#E2E8F0",
          mb: 0.5,
        }}
      >
        {label}
      </Typography>

      <Typography
        sx={{
          fontSize: 12,
          fontWeight: 600,
          color,
        }}
      >
        Value: {typeof value === "number" ? value.toLocaleString() : "—"}
      </Typography>
    </Box>
  );
}

export default function ThreatDistributionPanel(props: { dangerCounts: DangerCounts }) {
  const donut = React.useMemo(() => toDonut(props.dangerCounts), [props.dangerCounts]);
  const total = React.useMemo(() => sum(donut.map((d) => d.value)), [donut]);
  const danger = props.dangerCounts;

  return (
    <GlassCard
      title="Threat distribution"
      icon={<ShieldOutlined />}
      right={<Chip size="small" label="Monthly" variant="outlined" />}
    >
      <Box sx={{ flex: 1, minHeight: 220 }}>
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
                stroke="rgba(255,255,255,.10)"
                strokeWidth={1}
              >
                {donut.map((entry) => (
                  <Cell key={entry.name} fill={DANGER_COLORS[entry.name as DangerLabel]} />
                ))}
              </Pie>

              <text x="50%" y="47%" textAnchor="middle" dominantBaseline="central">
                <tspan style={{ fontWeight: 950, fontSize: 24, fill: "currentColor" }}>
                  {total}
                </tspan>
              </text>
              <text x="50%" y="60%" textAnchor="middle" dominantBaseline="central">
                <tspan style={{ opacity: 0.72, fontSize: 12, fill: "currentColor" }}>
                  signals
                </tspan>
              </text>

              <RechartsTooltip content={<ThreatTooltip />} />
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

      <Stack spacing={0.7} sx={{ mt: 1, flexShrink: 0 }}>
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
                <Typography variant="body2" sx={{ fontWeight: 500, fontSize: 14 }} color="text.secondary">
                  {label}
                </Typography>
              </Stack>

              <Typography variant="body2" sx={{ fontWeight: 900, fontSize: 14 }} color="text.primary">
                {value.toLocaleString()}
              </Typography>
            </Stack>
          );
        })}
      </Stack>
    </GlassCard>
  );
}