// file: src/features/dashboard/components/KpiTrendPanels.tsx
import * as React from "react";
import { Box, Chip, Stack, Typography } from "@mui/material";
import {
  ResponsiveContainer,
  ComposedChart,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Area,
} from "recharts";
import {
  GroupsOutlined,
  Inventory2Outlined,
  PersonAddAltOutlined,
  TrendingUpOutlined,
  TrendingDownOutlined,
  TrendingFlatOutlined,
} from "@mui/icons-material";

type Spark = {
  labels: string[]; // oldest -> newest (e.g., "Oct 25")
  newUsers: Array<number | null>;
  reporters: Array<number | null>;
  submissions: Array<number | null>;
};

type MetricKey = "newUsers" | "reporters" | "submissions";

function toChartData(labels: string[], values: Array<number | null>) {
  return labels.map((label, i) => ({
    label,
    value: typeof values[i] === "number" ? (values[i] as number) : null,
  }));
}

function formatNumber(v: unknown) {
  return typeof v === "number" ? v.toLocaleString() : "—";
}

function lastTwoNumbers(values: Array<number | null>) {
  // find last two non-null values (robust if some months are missing)
  let last: number | null = null;
  let prev: number | null = null;

  for (let i = values.length - 1; i >= 0; i--) {
    const v = values[i];
    if (typeof v !== "number") continue;
    if (last == null) last = v;
    else {
      prev = v;
      break;
    }
  }
  return { prev, last };
}

function GlassCard(props: {
  title: string;
  icon: React.ReactNode;
  right?: React.ReactNode;
  children: React.ReactNode;
}) {
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
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
        spacing={2}
        sx={{ mb: 1 }}
      >
        <Stack direction="row" spacing={1} alignItems="center">
          <Box
            sx={{
              width: 36,
              height: 36,
              borderRadius: 2.25,
              display: "grid",
              placeItems: "center",
              border: "1px solid",
              borderColor: "divider",
              bgcolor: "rgba(255,255,255,.03)",
            }}
          >
            {props.icon}
          </Box>
          <Typography sx={{ fontWeight: 950, fontSize: 14 }}>{props.title}</Typography>
        </Stack>
        {props.right}
      </Stack>

      {props.children}
    </Box>
  );
}

function TrendDeltaChip(props: { values: Array<number | null> }) {
  const { prev, last } = React.useMemo(() => lastTwoNumbers(props.values), [props.values]);

  if (typeof prev !== "number" || typeof last !== "number") return null;

  const d = last - prev;

  if (d > 0) {
    return (
      <Chip
        size="small"
        icon={<TrendingUpOutlined fontSize="small" />}
        label={`+${d.toLocaleString()}`}
        color="success"
        variant="filled"
        sx={{ fontWeight: 900 }}
      />
    );
  }

  if (d < 0) {
    return (
      <Chip
        size="small"
        icon={<TrendingDownOutlined fontSize="small" />}
        label={`${d.toLocaleString()}`}
        color="error"
        variant="filled"
        sx={{ fontWeight: 900 }}
      />
    );
  }

  // d === 0
  return (
    <Chip
      size="small"
      icon={<TrendingFlatOutlined fontSize="small" />}
      label="0"
      variant="outlined"
      sx={{ fontWeight: 900, borderColor: "rgba(255,255,255,.18)" }}
    />
  );
}

function TrendPanel(props: {
  title: string;
  icon: React.ReactNode;
  chipLabel: string;
  data: Array<{ label: string; value: number | null }>;
  onOpenTrends?: () => void;
}) {
  const lastValue = props.data.length ? props.data[props.data.length - 1]?.value : null;

  // Extract raw series for delta chip
  const series = React.useMemo(() => props.data.map((d) => d.value), [props.data]);

  return (
    <GlassCard
      title={props.title}
      icon={props.icon}
      right={
        <Stack direction="row" spacing={1} alignItems="center">
          <TrendDeltaChip values={series} />
          <Chip size="small" label={props.chipLabel} variant="outlined" />
        </Stack>
      }
    >
      <Stack direction="row" alignItems="baseline" justifyContent="space-between" sx={{ mb: 1 }}>
        <Typography sx={{ fontSize: 28, fontWeight: 950, lineHeight: 1 }}>
          {formatNumber(lastValue)}
        </Typography>

        {props.onOpenTrends ? (
          <Box
            role="button"
            tabIndex={0}
            onClick={props.onOpenTrends}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                props.onOpenTrends?.();
              }
            }}
            sx={{
              fontSize: 12,
              color: "text.secondary",
              cursor: "pointer",
              borderRadius: 2,
              px: 1,
              py: 0.5,
              "&:hover": { bgcolor: "rgba(255,255,255,.03)" },
              "&:focus-visible": { boxShadow: "0 0 0 2px rgba(255,255,255,.22)" },
            }}
            aria-label={`Open ${props.title} trends`}
          >
            View details
          </Box>
        ) : null}
      </Stack>

      <Box sx={{ height: 220 }}>
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={props.data}>
            <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
            <XAxis dataKey="label" tick={{ fontSize: 12 }} interval="preserveStartEnd" />
            <YAxis tick={{ fontSize: 12 }} width={44} />
            <Tooltip
              formatter={(v: any) => (typeof v === "number" ? v.toLocaleString() : "—")}
              labelStyle={{ fontWeight: 900 }}
            />
            <Area
              type="monotone"
              dataKey="value"
              name={props.title}
              fillOpacity={0.22}
              strokeWidth={2}
              isAnimationActive={false}
              connectNulls={false}
            />
          </ComposedChart>
        </ResponsiveContainer>
      </Box>

      <Typography variant="body2" color="text.secondary" sx={{ mt: 1, fontSize: 12 }}>
        Compares last available month vs previous month in the selected window.
      </Typography>
    </GlassCard>
  );
}

export default function KpiTrendPanels(props: {
  spark: Spark;
  trendWindow: number;
  onOpenTrends?: (metric?: MetricKey) => void;
}) {
  const newUsersData = React.useMemo(
    () => toChartData(props.spark.labels, props.spark.newUsers),
    [props.spark.labels, props.spark.newUsers]
  );
  const reportersData = React.useMemo(
    () => toChartData(props.spark.labels, props.spark.reporters),
    [props.spark.labels, props.spark.reporters]
  );
  const submissionsData = React.useMemo(
    () => toChartData(props.spark.labels, props.spark.submissions),
    [props.spark.labels, props.spark.submissions]
  );

  const chip = `Last ${props.trendWindow} mo`;

  const openNewUsers = React.useCallback(() => {
    props.onOpenTrends?.("newUsers");
  }, [props.onOpenTrends]);

  const openReporters = React.useCallback(() => {
    props.onOpenTrends?.("reporters");
  }, [props.onOpenTrends]);

  const openSubmissions = React.useCallback(() => {
    props.onOpenTrends?.("submissions");
  }, [props.onOpenTrends]);

  const canOpen = !!props.onOpenTrends;

  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", md: "repeat(3, 1fr)" },
        gap: 2,
      }}
    >
      <TrendPanel
        title="New users"
        icon={<PersonAddAltOutlined fontSize="small" />}
        chipLabel={chip}
        data={newUsersData}
        onOpenTrends={canOpen ? openNewUsers : undefined}
      />
      <TrendPanel
        title="Total reporters"
        icon={<GroupsOutlined fontSize="small" />}
        chipLabel={chip}
        data={reportersData}
        onOpenTrends={canOpen ? openReporters : undefined}
      />
      <TrendPanel
        title="Total submissions"
        icon={<Inventory2Outlined fontSize="small" />}
        chipLabel={chip}
        data={submissionsData}
        onOpenTrends={canOpen ? openSubmissions : undefined}
      />
    </Box>
  );
}
