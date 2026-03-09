import * as React from "react";
import {
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  Stack,
  Typography,
} from "@mui/material";
import {
  GroupsOutlined,
  Inventory2Outlined,
  PersonAddAltOutlined,
} from "@mui/icons-material";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  Tooltip,
  XAxis,
  YAxis,
  Cell,
  CartesianGrid,
} from "recharts";

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

const KPI_BAR_COLOR = "#38BDF8";

function toMiniSeries(labels: string[], values: Array<number | null>): MiniDatum[] {
  return labels.map((label, i) => ({
    label,
    v: typeof values[i] === "number" ? values[i] : 0,
    raw: values[i] ?? null,
  }));
}

function formatNumber(v: unknown) {
  return typeof v === "number" ? v.toLocaleString() : "—";
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

function MiniTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ payload?: MiniDatum; color?: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;

  const point = payload[0]?.payload;
  const color = payload[0]?.color ?? KPI_BAR_COLOR;

  if (!point) return null;

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
        Value: {point.raw == null ? "—" : Number(point.raw).toLocaleString()}
      </Typography>
    </Box>
  );
}

function ClickableMiniBar(props: {
  ariaLabel: string;
  data: MiniDatum[];
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
        height: 88,
        borderRadius: 2,
        outline: "none",
        cursor: props.onActivate ? "pointer" : "default",
        "&:hover": props.onActivate ? { bgcolor: "rgba(255,255,255,.03)" } : undefined,
        "&:focus-visible": props.onActivate
          ? { boxShadow: "0 0 0 2px rgba(255,255,255,.22)" }
          : undefined,
        px: 0.25,
        py: 0.25,
      }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={props.data} barCategoryGap={4}>
          <CartesianGrid strokeDasharray="3 3" opacity={0.18} vertical={false} />
          <XAxis dataKey="label" hide />
          <YAxis hide domain={[0, "dataMax"]} />
          <Tooltip
            content={<MiniTooltip />}
            cursor={{ fill: "rgba(148,163,184,0.10)" }}
          />
          <Bar dataKey="v" isAnimationActive={false} radius={[6, 6, 0, 0]}>
            {props.data.map((d, i) => (
              <Cell key={`${d.label}-${i}`} fill={KPI_BAR_COLOR} />
            ))}
          </Bar>
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
  miniBars?: MiniDatum[];
  onOpenTrends?: () => void;
}) {
  return (
    <GlassCard
      title={props.title}
      icon={props.icon}
      right={
        <Chip
          size="small"
          label="Monthly"
          variant="outlined"
        />
      }
    >
      <Stack direction="row" alignItems="baseline" justifyContent="space-between" sx={{ mb: 0.5 }}>
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
              "&:hover": { bgcolor: "rgba(255,255,255,.03)" },
              "&:focus-visible": { boxShadow: "0 0 0 2px rgba(255,255,255,.22)" },
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
          onActivate={props.onOpenTrends}
        />
      ) : (
        <Box sx={{ mt: 1.25, height: 88 }} />
      )}
    </GlassCard>
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

  const openNewUsers = React.useCallback(() => {
    props.onOpenTrends?.("new_users");
  }, [props.onOpenTrends]);

  const openReporters = React.useCallback(() => {
    props.onOpenTrends?.("total_reporters");
  }, [props.onOpenTrends]);

  const openSubmissions = React.useCallback(() => {
    props.onOpenTrends?.("total_cases");
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
      <KpiCard
        title="New users"
        value={formatNumber(props.kpis.new_users)}
        subtitle="Reporters created this month"
        icon={<PersonAddAltOutlined fontSize="small" />}
        miniBars={newUsersBars}
        onOpenTrends={canOpen ? openNewUsers : undefined}
      />

      <KpiCard
        title="Total reporters"
        value={formatNumber(props.kpis.total_reporters)}
        subtitle="Distinct reporting identities"
        icon={<GroupsOutlined fontSize="small" />}
        miniBars={reportersBars}
        onOpenTrends={canOpen ? openReporters : undefined}
      />

      <KpiCard
        title="Total submissions"
        value={formatNumber(props.kpis.total_cases)}
        subtitle="Cases submitted this month"
        icon={<Inventory2Outlined fontSize="small" />}
        miniBars={submissionsBars}
        onOpenTrends={canOpen ? openSubmissions : undefined}
      />
    </Box>
  );
}