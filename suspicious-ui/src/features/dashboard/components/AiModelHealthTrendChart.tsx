import * as React from "react";
import {
  Box,
  Stack,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip as MuiTooltip,
  Typography,
} from "@mui/material";
import { InfoOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";

import type { AiModelRun } from "@/features/dashboard/api";

const MODEL_LABELS: Record<string, string> = {
  safe_suspicious: "Safe vs Suspicious",
  spam_dangerous: "Spam vs Dangerous",
  safe: "Safe (interne/externe)",
  unwanted: "Unwanted (spam/newsletter)",
  dangerous: "Dangerous (sous-type)",
};

// Validated categorical palette (dataviz skill, slots 1-5) - fixed order,
// never reassigned per-render, so a series always keeps the same hue even
// if some labels are absent from a given time window.
const SERIES_COLORS: Record<string, { light: string; dark: string }> = {
  safe_suspicious: { light: "#2a78d6", dark: "#3987e5" }, // blue
  spam_dangerous: { light: "#eb6834", dark: "#d95926" }, // orange
  safe: { light: "#1baf7a", dark: "#199e70" }, // aqua
  unwanted: { light: "#eda100", dark: "#c98500" }, // yellow
  dangerous: { light: "#e87ba4", dark: "#d55181" }, // magenta
};

const SERIES_ORDER = Object.keys(SERIES_COLORS);

type Metric = "f1_score" | "accuracy" | "f1_score_golden";

const METRIC_META: Record<
  Metric,
  { label: string; short: string; toggle: string; description: string }
> = {
  f1_score: {
    label: "F1-score",
    short: "F1",
    toggle: "F1",
    description:
      "Équilibre entre la precision (parmi les mails signalés comme malveillants, combien le sont vraiment) et le recall (parmi les mails vraiment malveillants, combien ont été détectés). Calculé sur un échantillon de test tiré aléatoirement du dataset à chaque cycle de réentraînement.",
  },
  accuracy: {
    label: "Précision (accuracy)",
    short: "Précision",
    toggle: "Précision",
    description:
      "Pourcentage de prédictions correctes, toutes classes confondues."
  },
  f1_score_golden: {
    label: "F1-score sur le golden set",
    short: "F1 (golden)",
    toggle: "Golden",
    description:
      "F1-score mesuré sur un jeu de mails fixe (le \"golden set\"), jamais utilisé pour l'entraînement et identique d'un cycle à l'autre. Contrairement au F1-score classique (échantillon de test différent à chaque cycle), c'est la seule courbe vraiment comparable dans le temps - une hausse ici reflète un vrai progrès du modèle.",
  },
};

type PivotRow = { ts: number; run_timestamp: string } & Record<string, number | string>;

function metricValue(run: AiModelRun, metric: Metric): number | null {
  if (metric === "f1_score") return run.f1_score;
  if (metric === "accuracy") return run.accuracy;
  return run.f1_score_golden;
}

function pivotByRun(runs: AiModelRun[], metric: Metric): PivotRow[] {
  const byTs = new Map<string, PivotRow>();
  for (const run of runs) {
    if (!run.run_timestamp) continue;
    const value = metricValue(run, metric);
    if (value === null) continue;
    let row = byTs.get(run.run_timestamp);
    if (!row) {
      row = { run_timestamp: run.run_timestamp, ts: new Date(run.run_timestamp).getTime() };
      byTs.set(run.run_timestamp, row);
    }
    row[run.label] = value;
  }
  return [...byTs.values()].sort((a, b) => a.ts - b.ts);
}

function formatTick(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function CustomTooltip({
  active,
  payload,
  label,
  isDark,
  dividerColor,
  metric,
}: {
  active?: boolean;
  payload?: Array<{ dataKey: string; value: number | undefined; color: string }>;
  label?: number;
  isDark: boolean;
  dividerColor: string;
  metric: Metric;
}) {
  if (!active || !payload?.length) return null;
  const sorted = [...payload].sort((a, b) => (b.value ?? 0) - (a.value ?? 0));
  return (
    <Box
      sx={{
        px: 1.25,
        py: 1,
        borderRadius: 1.5,
        background: isDark ? "rgba(22,22,26,.97)" : "rgba(255,255,255,.98)",
        border: `1px solid ${dividerColor}`,
        boxShadow: "0 8px 24px rgba(0,0,0,.18)",
        minWidth: 200,
      }}
    >
      <Typography sx={{ fontSize: 11, fontWeight: 700, color: "text.secondary", mb: 0.5 }}>
        {typeof label === "number" ? formatTick(label) : ""} · {METRIC_META[metric].short}
      </Typography>
      <Stack spacing={0.4}>
        {sorted.map((entry) => (
          <Stack key={entry.dataKey} direction="row" spacing={0.75} sx={{ alignItems: "center" }}>
            <Box
              sx={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                backgroundColor: entry.color,
                flexShrink: 0,
              }}
            />
            <Typography sx={{ fontSize: 11, color: "text.primary", flex: 1 }} noWrap>
              {MODEL_LABELS[entry.dataKey] ?? entry.dataKey}
            </Typography>
            <Typography sx={{ fontSize: 11, fontWeight: 700, color: "text.primary" }}>
              {typeof entry.value === "number" ? entry.value.toFixed(3) : "—"}
            </Typography>
          </Stack>
        ))}
      </Stack>
    </Box>
  );
}

export default function AiModelHealthTrendChart({ runs }: { runs: AiModelRun[] }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const [metric, setMetric] = React.useState<Metric>("f1_score");

  const data = React.useMemo(() => pivotByRun(runs, metric), [runs, metric]);
  const labels = React.useMemo(() => {
    const present = new Set(
      runs.filter((r) => metricValue(r, metric) !== null).map((r) => r.label)
    );
    return SERIES_ORDER.filter((l) => present.has(l));
  }, [runs, metric]);

  const gridColor = alpha(theme.palette.divider, isDark ? 0.16 : 0.45);
  const axisColor = alpha(theme.palette.text.secondary, 0.65);
  const dividerColor = alpha(theme.palette.divider, isDark ? 0.3 : 0.9);
  const surfaceColor = isDark ? theme.palette.background.paper : "#ffffff";

  const header = (
    <Stack
      direction="row"
      sx={{ alignItems: "center", justifyContent: "space-between", mb: 0.5, flexShrink: 0 }}
    >
      <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }}>
        <Typography sx={{ fontSize: 12, fontWeight: 700, color: "text.secondary" }}>
          Évolution du {METRIC_META[metric].label.toLowerCase()} par modèle
        </Typography>
        <MuiTooltip title={METRIC_META[metric].description} arrow placement="top">
          <InfoOutlined sx={{ fontSize: 14, color: "text.secondary", cursor: "help" }} />
        </MuiTooltip>
      </Stack>
      <ToggleButtonGroup
        size="small"
        exclusive
        value={metric}
        onChange={(_, next) => next && setMetric(next)}
        sx={{
          height: 24,
          "& .MuiToggleButton-root": {
            fontSize: 10,
            fontWeight: 700,
            py: 0,
            px: 1,
            lineHeight: "22px",
            textTransform: "none",
          },
        }}
      >
        <ToggleButton value="f1_score">F1</ToggleButton>
        <ToggleButton value="accuracy">Précision</ToggleButton>
        <ToggleButton value="f1_score_golden">Golden</ToggleButton>
      </ToggleButtonGroup>
    </Stack>
  );

  if (data.length < 2) {
    return (
      <Box sx={{ flexShrink: 0 }}>
        {header}
        <Box sx={{ display: "grid", placeItems: "center", height: 160 }}>
          <Typography sx={{ fontSize: 12, color: "text.secondary", textAlign: "center", px: 2 }}>
            {metric === "f1_score_golden"
              ? "Pas encore assez de cycles évalués sur le golden set (retrain model monthly/golden_set.py) pour tracer une évolution."
              : "Au moins 2 cycles de réentraînement sont nécessaires pour tracer une évolution."}
          </Typography>
        </Box>
      </Box>
    );
  }

  return (
    <Box sx={{ width: "100%", flexShrink: 0 }}>
      {header}
      <Box sx={{ height: 228, width: "100%" }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 0, right: 8, bottom: 0, left: -16 }}>
            <CartesianGrid stroke={gridColor} horizontal vertical={false} />
            <Legend
              verticalAlign="top"
              height={30}
              wrapperStyle={{ fontSize: 11 }}
              formatter={(value: string) => (
                <span style={{ color: theme.palette.text.secondary }}>
                  {MODEL_LABELS[value] ?? value}
                </span>
              )}
              iconType="plainline"
              iconSize={14}
            />
            <XAxis
              dataKey="ts"
              type="number"
              domain={["dataMin", "dataMax"]}
              tickFormatter={formatTick}
              tick={{ fontSize: 10, fill: axisColor }}
              stroke={gridColor}
              tickLine={false}
              minTickGap={48}
            />
            <YAxis
              domain={[0, 1]}
              ticks={[0, 0.25, 0.5, 0.75, 1]}
              tick={{ fontSize: 10, fill: axisColor }}
              stroke={gridColor}
              tickLine={false}
              width={30}
              label={{
                value: METRIC_META[metric].short,
                angle: -90,
                position: "insideLeft",
                offset: 14,
                style: { fontSize: 10, fill: axisColor, textAnchor: "middle" },
              }}
            />
            <Tooltip
              content={(props) => (
                <CustomTooltip
                  {...(props as any)}
                  isDark={isDark}
                  dividerColor={dividerColor}
                  metric={metric}
                />
              )}
              cursor={{ stroke: axisColor, strokeWidth: 1 }}
            />
            {labels.map((label) => (
              <Line
                key={label}
                type="monotone"
                dataKey={label}
                name={label}
                stroke={isDark ? SERIES_COLORS[label].dark : SERIES_COLORS[label].light}
                strokeWidth={2}
                strokeLinecap="round"
                dot={{ r: 4, strokeWidth: 2, stroke: surfaceColor }}
                activeDot={{ r: 6, strokeWidth: 2, stroke: surfaceColor }}
                connectNulls={false}
                isAnimationActive={false}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </Box>
    </Box>
  );
}
