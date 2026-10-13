import * as React from "react";
import { Box, Stack, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import { SoftCard } from "./SoftCard";
import { Sparkline } from "./Sparkline";
import type { DashboardSummary } from "@/features/dashboard/api";
import { delta, monthName, onCard, percents, plural } from "@/features/dashboard/format";
import { useResultColors } from "@/styles/colorStore";

// Weeks are Monday-based and cut at the month's edges (and at today), so the ends can be short.
const SPARK_LABEL = "Reports per week (first and last weeks may be partial)";

const sum = (o: Record<string, number>) => Object.values(o).reduce((a, b) => a + b, 0);

export function Kpi(props: { title: string; value: number | string; marker?: string; children?: React.ReactNode }) {
  return (
    <SoftCard title={props.title}>
      <Stack spacing={0.5} sx={{ alignItems: "flex-start" }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
          {props.marker ? (
            <Box aria-hidden sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: props.marker }} />
          ) : null}
          <Typography variant="h1" component="p">
            {props.value.toLocaleString()}
          </Typography>
        </Stack>
        {props.children}
      </Stack>
    </SoftCard>
  );
}

export function Line({ children }: { children: React.ReactNode }) {
  return (
    <Typography variant="body2" color="text.secondary">
      {children}
    </Typography>
  );
}

export default function KpiTrendPanels({ summary: s }: { summary: DashboardSummary }) {
  const theme = useTheme();
  const result = useResultColors();
  const prevMonth = monthName(s.month === 1 ? 12 : s.month - 1);
  const finished = sum(s.outcomes);
  // Same rounding as the Outcomes panel, so the two never show different shares.
  const o = s.outcomes;
  const dangerousPct = percents([o.safe, o.inconclusive, o.suspicious, o.dangerous, o.failure])[3];
  const prevFinished = sum(s.previous.outcomes);

  return (
    <Box
      sx={{
        display: "grid",
        // Columns follow the panel's own width, which the user can resize.
        gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
        gap: 2,
        height: "100%",
      }}
    >
      <Kpi title="Reports" value={s.reports}>
        <Line>{delta(prevMonth, s.reports, s.previous.reports, s.previous.reports > 0)}</Line>
        {s.trend.length > 1 ? (
          // The visible caption names the line; the SVG's own label carries the values.
          <Stack direction="row" spacing={1.5} sx={{ alignItems: "flex-end", pt: 0.5 }}>
            <Box sx={{ color: onCard(theme.palette.primary.main, theme.palette, 3), lineHeight: 0 }}>
              <Sparkline values={s.trend.map((p) => p.reports)} label={SPARK_LABEL} />
            </Box>
            <Typography variant="caption" color="text.secondary">
              per week, first and last weeks may be partial
            </Typography>
          </Stack>
        ) : (
          <Sparkline values={s.trend.map((p) => p.reports)} label={SPARK_LABEL} />
        )}
      </Kpi>

      <Kpi title="Dangerous" value={s.outcomes.dangerous} marker={onCard(result.dangerous.main, theme.palette, 3)}>
        {finished > 0 ? (
          <Line>
            {o.dangerous > 0 && dangerousPct === 0 ? "<1" : dangerousPct}% of {plural(finished, "case")} with a verdict
          </Line>
        ) : null}
        <Line>{delta(prevMonth, s.outcomes.dangerous, s.previous.outcomes.dangerous, prevFinished > 0)}</Line>
      </Kpi>

      <Kpi title="Reporters" value={s.reporters}>
        {s.new_users > 0 ? (
          <Line>
            {plural(s.new_users, "account")} created in {monthName(s.month)}
          </Line>
        ) : null}
      </Kpi>
    </Box>
  );
}
