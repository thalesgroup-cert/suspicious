// src/features/dashboard/components/KpiGrid.tsx
import * as React from "react";
import { Box, Chip, Stack, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { alpha } from "@mui/material/styles";
import {
  GroupsOutlined,
  Inventory2Outlined,
  PersonAddAltOutlined,
} from "@mui/icons-material";
import {
  BarChart,
  Bar,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { SoftCard } from "./SoftCard";
import { useStatusColors } from "@/styles/colorStore";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Kpis = {
  new_users: number;
  total_reporters: number;
  total_cases: number;
};

export type KpiMetricKey = "new_users" | "total_reporters" | "total_cases";

type Spark = {
  labels: string[];
  newUsers: Array<number | null>;
  reporters: Array<number | null>;
  submissions: Array<number | null>;
};

type MiniDatum = {
  label: string;
  v: number;
  raw: number | null;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// KPI bar color comes from the status color store (in_progress = activity in flight)
function toMiniSeries(labels: string[], values: Array<number | null>): MiniDatum[] {
  return labels.map((label, i) => ({
    label,
    v: typeof values[i] === "number" ? (values[i] as number) : 0,
    raw: values[i] ?? null,
  }));
}

function formatNumber(v: unknown) {
  return typeof v === "number" ? v.toLocaleString() : "—";
}

// ---------------------------------------------------------------------------
// MiniTooltip — theme-aware
// ---------------------------------------------------------------------------

function MiniTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ payload?: MiniDatum; color?: string }>;
  label?: string;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  if (!active || !payload?.length) return null;

  const point = payload[0]?.payload;
  // Fallback colour — never actually rendered since color always comes from Cell
  const color = payload[0]?.color ?? "#38BDF8";
  if (!point) return null;

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
        Value: {point.raw == null ? "—" : Number(point.raw).toLocaleString()}
      </Typography>
    </Box>
  );
}

// ---------------------------------------------------------------------------
// ClickableMiniBar
// ---------------------------------------------------------------------------

function ClickableMiniBar(props: {
  ariaLabel: string;
  data: MiniDatum[];
  barColor: string;
  onActivate?: () => void;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!props.onActivate) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      props.onActivate();
    }
  };

  return (
    <Box
      role={props.onActivate ? "button" : undefined}
      tabIndex={props.onActivate ? 0 : -1}
      aria-label={props.ariaLabel}
      onClick={props.onActivate}
      onKeyDown={onKeyDown}
      sx={{
        mt: 1.25,
        height: 88,
        borderRadius: 2,
        outline: "none",
        cursor: props.onActivate ? "pointer" : "default",
        "&:hover": props.onActivate
          ? {
              bgcolor: isDark
                ? "rgba(255,255,255,.03)"
                : alpha(theme.palette.action.hover, 0.06),
            }
          : undefined,
        "&:focus-visible": props.onActivate
          ? {
              boxShadow: `0 0 0 2px ${alpha(theme.palette.primary.main, 0.35)}`,
            }
          : undefined,
        px: 0.25,
        py: 0.25,
      }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={props.data} barCategoryGap={4}>
          <CartesianGrid
            strokeDasharray="3 3"
            opacity={isDark ? 0.18 : 0.3}
            vertical={false}
            stroke={isDark ? undefined : alpha(theme.palette.divider, 0.6)}
          />
          <XAxis dataKey="label" hide />
          <YAxis hide domain={[0, "dataMax"]} />
          <Tooltip
            content={<MiniTooltip />}
            cursor={{
              fill: isDark
                ? "rgba(148,163,184,0.10)"
                : alpha(theme.palette.action.hover, 0.12),
            }}
          />
          <Bar dataKey="v" isAnimationActive={false} radius={[6, 6, 0, 0]}>
            {props.data.map((d, i) => (
              <Cell key={`${d.label}-${i}`} fill={props.barColor} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Box>
  );
}

// ---------------------------------------------------------------------------
// KpiCard
// ---------------------------------------------------------------------------

function KpiCard(props: {
  title: string;
  value: number | string;
  subtitle: string;
  icon: React.ReactNode;
  barColor: string;
  miniBars?: MiniDatum[];
  onOpenTrends?: () => void;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <SoftCard
      title={props.title}
      icon={props.icon}
      right={<Chip size="small" label="Monthly" variant="outlined" />}
    >
      <Stack
        direction="row"
        alignItems="baseline"
        justifyContent="space-between"
        sx={{ mb: 0.5 }}
      >
        <Typography sx={{ fontSize: 30, fontWeight: 950, lineHeight: 1.05 }}>
          {props.value}
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
              "&:hover": {
                bgcolor: isDark
                  ? "rgba(255,255,255,.03)"
                  : alpha(theme.palette.action.hover, 0.06),
              },
              "&:focus-visible": {
                boxShadow: `0 0 0 2px ${alpha(theme.palette.primary.main, 0.35)}`,
              },
            }}
            aria-label={`Open ${props.title} trends`}
          >
            View details
          </Box>
        ) : null}
      </Stack>

      <Typography variant="caption" color="text.secondary">
        {props.subtitle}
      </Typography>

      {props.miniBars?.length ? (
        <ClickableMiniBar
          ariaLabel={`${props.title} trend${props.onOpenTrends ? " (open details)" : ""}`}
          data={props.miniBars}
          barColor={props.barColor}
          onActivate={props.onOpenTrends}
        />
      ) : (
        <Box sx={{ mt: 1.25, height: 88 }} />
      )}
    </SoftCard>
  );
}

// ---------------------------------------------------------------------------
// KpiGrid (default export)
// ---------------------------------------------------------------------------

export default function KpiGrid(props: {
  kpis: Kpis;
  spark?: Spark;
  onOpenTrends?: (metric?: KpiMetricKey) => void;
}) {
  const labels = props.spark?.labels ?? [];

  // KPI bars use in_progress color from the status store — represents
  // "activity happening this month" which matches the metric semantics.
  // With Okabe-Ito preset this becomes #0072B2 (blue), still distinct from
  // the green/vermilion used for trend arrows.
  const statusColors = useStatusColors();
  const kpiBarColor = statusColors.in_progress.main;

  const newUsersBars = React.useMemo(
    () => (props.spark ? toMiniSeries(labels, props.spark.newUsers) : []),
    [props.spark, labels]
  );
  const reportersBars = React.useMemo(
    () => (props.spark ? toMiniSeries(labels, props.spark.reporters) : []),
    [props.spark, labels]
  );
  const submissionsBars = React.useMemo(
    () => (props.spark ? toMiniSeries(labels, props.spark.submissions) : []),
    [props.spark, labels]
  );

  const openNewUsers    = React.useCallback(() => { props.onOpenTrends?.("new_users"); },       [props.onOpenTrends]);
  const openReporters   = React.useCallback(() => { props.onOpenTrends?.("total_reporters"); }, [props.onOpenTrends]);
  const openSubmissions = React.useCallback(() => { props.onOpenTrends?.("total_cases"); },     [props.onOpenTrends]);
  const canOpen = !!props.onOpenTrends;

  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", md: "repeat(3, 1fr)" },
        gap: 2,
      }}
    >
      <KpiCard
        title="New users"
        value={formatNumber(props.kpis.new_users)}
        subtitle="Reporters created this month"
        icon={<PersonAddAltOutlined fontSize="small" />}
        barColor={kpiBarColor}
        miniBars={newUsersBars}
        onOpenTrends={canOpen ? openNewUsers : undefined}
      />
      <KpiCard
        title="Total reporters"
        value={formatNumber(props.kpis.total_reporters)}
        subtitle="Distinct reporting identities"
        icon={<GroupsOutlined fontSize="small" />}
        barColor={kpiBarColor}
        miniBars={reportersBars}
        onOpenTrends={canOpen ? openReporters : undefined}
      />
      <KpiCard
        title="Total submissions"
        value={formatNumber(props.kpis.total_cases)}
        subtitle="Cases submitted this month"
        icon={<Inventory2Outlined fontSize="small" />}
        barColor={kpiBarColor}
        miniBars={submissionsBars}
        onOpenTrends={canOpen ? openSubmissions : undefined}
      />
    </Box>
  );
}