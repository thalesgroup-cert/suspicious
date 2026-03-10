// file: src/features/dashboard/components/TopPrefixesPanel.tsx
import * as React from "react";
import { Box, Card, CardContent, Chip, Divider, Stack, Typography } from "@mui/material";
import { SellOutlined } from "@mui/icons-material";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Cell,
} from "recharts";

type PrefixItem = { label: string; value: number };

const BAR_COLOR = "#38BDF8";

function compactLabel(text: string, max = 12) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function GlassCard(props: React.PropsWithChildren<{
  title: string;
  icon?: React.ReactNode;
  right?: React.ReactNode;
}>) {
  return (
    <Card
      sx={{
        borderRadius: 3,
        border: "1px solid rgba(255,255,255,.10)",
        background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
      }}
    >
      <CardContent sx={{ p: { xs: 1.5, md: 2 } }}>
        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
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

        <Divider sx={{ opacity: 0.25, mb: 1.5 }} />
        {props.children}
      </CardContent>
    </Card>
  );
}

function PrefixTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ value?: number; color?: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;

  const value = payload[0]?.value ?? 0;
  const color = payload[0]?.color ?? BAR_COLOR;

  return (
    <Box
      sx={{
        background: "rgba(15,23,42,0.95)",
        border: "1px solid rgba(255,255,255,0.12)",
        borderRadius: 2,
        px: 1.25,
        py: 1,
        backdropFilter: "blur(6px)",
        minWidth: 140,
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
        Count: {typeof value === "number" ? value.toLocaleString() : "—"}
      </Typography>
    </Box>
  );
}

export default function TopPrefixesPanel(props: { data: PrefixItem[] }) {
  const chartData = React.useMemo(
    () =>
      props.data.map((item) => ({
        ...item,
        shortLabel: compactLabel(item.label, 12),
      })),
    [props.data]
  );

  return (
    <GlassCard
      title="Top prefixes"
      icon={<SellOutlined />}
      right={<Chip size="small" label="Top 10" variant="outlined" />}
    >
      <Box sx={{ height: 365 }}>
        {chartData.length ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
              <XAxis
                dataKey="shortLabel"
                tick={{ fontSize: 11 }}
                interval={0}
                height={56}
              />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip
                content={<PrefixTooltip />}
                cursor={{ fill: "rgba(148,163,184,0.10)" }}
              />
              <Bar dataKey="value" radius={[8, 8, 0, 0]} isAnimationActive={false}>
                {chartData.map((entry) => (
                  <Cell key={entry.label} fill={BAR_COLOR} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <Stack sx={{ height: "100%" }} alignItems="center" justifyContent="center">
            <Typography color="text.secondary" variant="body2">
              No prefixes for this period
            </Typography>
          </Stack>
        )}
      </Box>
    </GlassCard>
  );
}