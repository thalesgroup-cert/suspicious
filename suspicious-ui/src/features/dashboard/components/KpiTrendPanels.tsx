// src/features/dashboard/components/KpiTrendPanels.tsx
import * as React from "react";
import { Box, Stack, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import {
  GroupsOutlined,
  Inventory2Outlined,
  PersonAddAltOutlined,
  TrendingUpOutlined,
  TrendingDownOutlined,
  TrendingFlatOutlined,
} from "@mui/icons-material";

import { SoftCard } from "./SoftCard";

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
    else { prev = v; break; }
  }

  return { prev, last };
}

function TrendIcon(props: { values: Array<number | null> }) {
  const theme = useTheme();
  const { prev, last } = React.useMemo(() => lastTwoNumbers(props.values), [props.values]);

  let icon: React.ReactNode = null;
  let color: string = theme.palette.text.disabled;

  if (typeof prev !== "number" || typeof last !== "number") {
    icon = <TrendingFlatOutlined sx={{ fontSize: 100, opacity: 0.45 }} />;
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
      color = theme.palette.text.secondary as string;
    }
  }

  return (
    <Stack
      alignItems="center"
      justifyContent="center"
      spacing={1}
      sx={{ flex: 1, minHeight: 0, color }}
    >
      <Box sx={{ display: "grid", placeItems: "center", lineHeight: 1 }}>
        {icon}
      </Box>
      <Typography sx={{ fontSize: 30, fontWeight: 950, lineHeight: 1, color: "text.primary" }}>
        {formatNumber(last)}
      </Typography>
    </Stack>
  );
}

function TrendPanel(props: {
  title: string;
  icon: React.ReactNode;
  values: Array<number | null>;
}) {
  return (
    <SoftCard title={props.title} icon={props.icon} fillHeight>
      <TrendIcon values={props.values} />
    </SoftCard>
  );
}

export default function KpiTrendPanels(props: {
  spark: Spark;
  trendWindow: number;
  onOpenTrends?: (metric?: MetricKey) => void;
}) {
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", md: "repeat(3, 1fr)" },
        gap: 2,
        height: "100%",
      }}
    >
      <TrendPanel
        title="New users"
        icon={<PersonAddAltOutlined fontSize="small" />}
        values={props.spark.newUsers}
      />
      <TrendPanel
        title="Total reporters"
        icon={<GroupsOutlined fontSize="small" />}
        values={props.spark.reporters}
      />
      <TrendPanel
        title="Total submissions"
        icon={<Inventory2Outlined fontSize="small" />}
        values={props.spark.submissions}
      />
    </Box>
  );
}