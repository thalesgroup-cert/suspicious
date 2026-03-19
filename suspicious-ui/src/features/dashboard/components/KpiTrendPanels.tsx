import * as React from "react";
import { Box, Card, CardContent, Chip, Divider, Stack, Typography } from "@mui/material";
import {
  GroupsOutlined,
  Inventory2Outlined,
  PersonAddAltOutlined,
  TrendingUpOutlined,
  TrendingDownOutlined,
  TrendingFlatOutlined,
} from "@mui/icons-material";

type Spark = {
  labels: string[];
  newUsers: Array<number | null>;
  reporters: Array<number | null>;
  submissions: Array<number | null>;
};

type MetricKey = "newUsers" | "reporters" | "submissions";

function formatNumber(v: unknown) {
  return typeof v === "number" ? v.toLocaleString() : "—";
}

function lastTwoNumbers(values: Array<number | null>) {
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

function GlassCard(props: React.PropsWithChildren<{
  title: string;
  icon?: React.ReactNode;
  right?: React.ReactNode;
}>) {
  return (
    <Card
      sx={{
        height: "100%",
        minHeight: 180,
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

function TrendIcon(props: { values: Array<number | null> }) {
  const { prev, last } = React.useMemo(() => lastTwoNumbers(props.values), [props.values]);

  let icon: React.ReactNode = null;
  let color = "text.secondary";

  if (typeof prev !== "number" || typeof last !== "number") {
    icon = <TrendingFlatOutlined sx={{ fontSize: 100, opacity: 0.45 }} />;
    color = "text.disabled";
  } else {
    const d = last - prev;

    if (d > 0) {
      icon = <TrendingUpOutlined sx={{ fontSize: 60 }} />;
      color = "#22C55E";
    } else if (d < 0) {
      icon = <TrendingDownOutlined sx={{ fontSize: 60 }} />;
      color = "#EF4444";
    } else {
      icon = <TrendingFlatOutlined sx={{ fontSize: 60 }} />;
      color = "text.secondary";
    }
  }

  return (
    <Stack
      alignItems="center"
      justifyContent="center"
      spacing={1}
      sx={{
        flex: 1,
        minHeight: 0,
        color,
      }}
    >
      <Box sx={{ display: "grid", placeItems: "center", lineHeight: 1 }}>
        {icon}
      </Box>

      <Typography
        sx={{
          fontSize: 30,
          fontWeight: 950,
          lineHeight: 1,
          color: "text.primary",
        }}
      >
        {formatNumber(last)}
      </Typography>
    </Stack>
  );
}

function TrendPanel(props: {
  title: string;
  icon: React.ReactNode;
  chipLabel: string;
  values: Array<number | null>;
  onOpenTrends?: () => void;
}) {
  return (
    <GlassCard title={props.title} icon={props.icon}>
      <Box sx={{ flex: 1, minHeight: 0, display: "flex" }}>
        <TrendIcon values={props.values} />
      </Box>
    </GlassCard>
  );
}

export default function KpiTrendPanels(props: {
  spark: Spark;
  trendWindow: number;
  onOpenTrends?: (metric?: MetricKey) => void;
}) {
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
        values={props.spark.newUsers}
        onOpenTrends={canOpen ? openNewUsers : undefined}
      />
      <TrendPanel
        title="Total reporters"
        icon={<GroupsOutlined fontSize="small" />}
        chipLabel={chip}
        values={props.spark.reporters}
        onOpenTrends={canOpen ? openReporters : undefined}
      />
      <TrendPanel
        title="Total submissions"
        icon={<Inventory2Outlined fontSize="small" />}
        chipLabel={chip}
        values={props.spark.submissions}
        onOpenTrends={canOpen ? openSubmissions : undefined}
      />
    </Box>
  );
}