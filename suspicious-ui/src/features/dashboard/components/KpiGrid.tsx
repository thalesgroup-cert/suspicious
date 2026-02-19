// file: src/features/dashboard/components/KpiGrid.tsx
import * as React from "react";
import { Box, Card, CardContent, Stack, Typography } from "@mui/material";
import { GroupsOutlined, Inventory2Outlined, PersonAddAltOutlined } from "@mui/icons-material";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type Kpis = {
  new_users: number;
  total_reporters: number;
  total_cases: number;
};

export type KpiMetricKey = "new_users" | "total_reporters" | "total_cases";

type Spark = {
  labels: string[]; // oldest -> newest
  newUsers: Array<number | null>;
  reporters: Array<number | null>;
  submissions: Array<number | null>;
};

function toMiniSeries(labels: string[], values: Array<number | null>) {
  return labels.map((label, i) => ({
    label,
    // Recharts wants a number; keep null separately for tooltip
    v: typeof values[i] === "number" ? (values[i] as number) : 0,
    raw: values[i] ?? null,
  }));
}

function MiniTooltip(props: any) {
  const payload = props?.payload?.[0]?.payload;
  if (!payload) return null;
  return (
    <Box
      sx={{
        px: 1,
        py: 0.75,
        borderRadius: 2,
        border: "1px solid",
        borderColor: "divider",
        bgcolor: "background.paper",
        fontSize: 12,
      }}
    >
      <Box style={{ fontWeight: 900 }}>{payload.label}</Box>
      <Box style={{ color: "rgba(255,255,255,.75)" }}>
        {payload.raw == null ? "—" : Number(payload.raw).toLocaleString()}
      </Box>
    </Box>
  );
}

function ClickableMiniBar(props: {
  ariaLabel: string;
  data: Array<{ label: string; v: number; raw: number | null }>;
  onActivate?: () => void;
}) {
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
        height: 56,
        borderRadius: 2,
        outline: "none",
        cursor: props.onActivate ? "pointer" : "default",
        // subtle “interactive area” affordance without heavy chrome
        "&:hover": props.onActivate ? { bgcolor: "rgba(255,255,255,.03)" } : undefined,
        "&:focus-visible": props.onActivate
          ? { boxShadow: "0 0 0 2px rgba(255,255,255,.22)" }
          : undefined,
        px: 0.5,
        py: 0.25,
      }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={props.data} barCategoryGap={3}>
          {/* Keep axes hidden to reduce noise */}
          <XAxis dataKey="label" hide />
          <YAxis hide domain={[0, "dataMax"]} />
          <Tooltip content={<MiniTooltip />} />
          <Bar dataKey="v" isAnimationActive={false} radius={[6, 6, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </Box>
  );
}

function KpiCard(props: {
  title: string;
  value: number | string;
  subtitle: string;
  icon: React.ReactNode;
  miniBars?: Array<{ label: string; v: number; raw: number | null }>;
  onOpenTrends?: () => void;
}) {
  return (
    <Card
      sx={{
        borderRadius: 3,
        border: "1px solid",
        borderColor: "divider",
        bgcolor: "background.paper",
        height: "100%",
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Stack direction="row" alignItems="flex-start" justifyContent="space-between" spacing={2}>
          <Box>
            <Typography variant="overline" color="text.secondary">
              {props.title}
            </Typography>
            <Typography sx={{ fontSize: 30, fontWeight: 950, lineHeight: 1.05 }}>
              {props.value}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {props.subtitle}
            </Typography>
          </Box>

          <Box
            sx={{
              width: 44,
              height: 44,
              borderRadius: 2.5,
              display: "grid",
              placeItems: "center",
              border: "1px solid",
              borderColor: "divider",
              bgcolor: "rgba(255,255,255,.03)",
            }}
          >
            {props.icon}
          </Box>
        </Stack>

        {props.miniBars?.length ? (
          <ClickableMiniBar
            ariaLabel={`${props.title} trend (open details)`}
            data={props.miniBars}
            onActivate={props.onOpenTrends}
          />
        ) : (
          <Box sx={{ mt: 1.25, height: 56 }} />
        )}
      </CardContent>
    </Card>
  );
}

export default function KpiGrid(props: {
  kpis: Kpis;
  spark?: Spark;
  onOpenTrends?: (metric?: KpiMetricKey) => void;
}) {
  const labels = props.spark?.labels ?? [];

  const newUsersBars = React.useMemo(() => {
    if (!props.spark) return [];
    return toMiniSeries(labels, props.spark.newUsers);
  }, [props.spark, labels]);

  const reportersBars = React.useMemo(() => {
    if (!props.spark) return [];
    return toMiniSeries(labels, props.spark.reporters);
  }, [props.spark, labels]);

  const submissionsBars = React.useMemo(() => {
    if (!props.spark) return [];
    return toMiniSeries(labels, props.spark.submissions);
  }, [props.spark, labels]);

  // ✅ Safe handlers (avoid TS2722)
  const openNewUsers = React.useCallback(() => {
    props.onOpenTrends?.("new_users");
  }, [props.onOpenTrends]);

  const openReporters = React.useCallback(() => {
    props.onOpenTrends?.("total_reporters");
  }, [props.onOpenTrends]);

  const openSubmissions = React.useCallback(() => {
    props.onOpenTrends?.("total_cases");
  }, [props.onOpenTrends]);

  // If handler not provided, pass undefined so the mini chart isn't focusable/clickable.
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
        value={props.kpis.new_users}
        subtitle="Reporters created this month"
        icon={<PersonAddAltOutlined fontSize="small" />}
        miniBars={newUsersBars}
        onOpenTrends={canOpen ? openNewUsers : undefined}
      />

      <KpiCard
        title="Total reporters"
        value={props.kpis.total_reporters}
        subtitle="Distinct reporting identities"
        icon={<GroupsOutlined fontSize="small" />}
        miniBars={reportersBars}
        onOpenTrends={canOpen ? openReporters : undefined}
      />

      <KpiCard
        title="Total submissions"
        value={props.kpis.total_cases}
        subtitle="Cases submitted this month"
        icon={<Inventory2Outlined fontSize="small" />}
        miniBars={submissionsBars}
        onOpenTrends={canOpen ? openSubmissions : undefined}
      />
    </Box>
  );
}