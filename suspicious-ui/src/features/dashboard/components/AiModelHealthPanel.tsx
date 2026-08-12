import * as React from "react";
import { Box, Stack, Typography, Chip } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { useQuery } from "@tanstack/react-query";
import { PsychologyOutlined, TrendingUp, TrendingDown, TrendingFlat } from "@mui/icons-material";

import { SoftCard } from "./SoftCard";
import AiModelHealthTrendChart from "./AiModelHealthTrendChart";
import { getAiModelRuns, type AiModelRun } from "@/features/dashboard/api";

const MODEL_LABELS: Record<string, string> = {
  dangerous: "Dangerous (sous-type)",
  safe: "Safe (interne/externe)",
  unwanted: "Unwanted (spam/newsletter)",
  spam_dangerous: "Spam vs Dangerous",
  safe_suspicious: "Safe vs Suspicious",
};

type LatestAndPrevious = { latest: AiModelRun; previous: AiModelRun | null };

function groupByLabel(runs: AiModelRun[]): Map<string, LatestAndPrevious> {
  const byLabel = new Map<string, AiModelRun[]>();
  for (const run of runs) {
    const list = byLabel.get(run.label) ?? [];
    list.push(run);
    byLabel.set(run.label, list);
  }

  const out = new Map<string, LatestAndPrevious>();
  for (const [label, list] of byLabel) {
    const sorted = [...list].sort(
      (a, b) => new Date(b.run_timestamp).getTime() - new Date(a.run_timestamp).getTime()
    );
    out.set(label, { latest: sorted[0], previous: sorted[1] ?? null });
  }
  return out;
}

function TrendChip({ latest, previous }: { latest: number; previous: number | null }) {
  if (previous === null) {
    return <Chip size="small" label="premier run" variant="outlined" sx={{ fontSize: 11 }} />;
  }
  const delta = latest - previous;
  const pct = previous > 0 ? (delta / previous) * 100 : 0;
  const color = delta > 0.001 ? "success" : delta < -0.001 ? "error" : "default";
  const Icon = delta > 0.001 ? TrendingUp : delta < -0.001 ? TrendingDown : TrendingFlat;
  return (
    <Chip
      size="small"
      color={color as any}
      icon={<Icon sx={{ fontSize: 14 }} />}
      label={`${delta >= 0 ? "+" : ""}${pct.toFixed(1)}%`}
      sx={{ fontSize: 11, fontWeight: 700 }}
    />
  );
}

export default function AiModelHealthPanel() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const { data, isLoading, isError } = useQuery({
    queryKey: ["ai-model-runs"],
    // 1000 = DashboardLimitOffsetPagination's max_limit - the last-50 window
    // used to silently drop July's runs once daily volume grew past ~50/day
    // (July's whole history disappeared behind newer rows), so pull the
    // full history the server allows instead of guessing a cutoff.
    queryFn: () => getAiModelRuns(1000),
  });

  const grouped = React.useMemo(() => groupByLabel(data ?? []), [data]);
  const labels = Object.keys(MODEL_LABELS).filter((l) => grouped.has(l));

  return (
    <SoftCard title="AI Model Health" icon={<PsychologyOutlined />}>
      {isLoading ? (
        <Typography sx={{ fontSize: 13, color: "text.secondary" }}>Chargement…</Typography>
      ) : isError ? (
        <Typography sx={{ fontSize: 13, color: "error.main" }}>
          Impossible de charger l'historique des entraînements.
        </Typography>
      ) : labels.length === 0 ? (
        <Typography sx={{ fontSize: 13, color: "text.secondary" }}>
          Aucun run de réentraînement enregistré pour l'instant.
        </Typography>
      ) : (
        <Stack spacing={1} sx={{ overflow: "hidden", height: "100%", minHeight: 0 }}>
          <AiModelHealthTrendChart runs={data ?? []} />
          <Stack spacing={1} sx={{ overflowY: "auto", minHeight: 0 }}>
          {labels.map((label) => {
            const { latest, previous } = grouped.get(label)!;
            return (
              <Box
                key={label}
                sx={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  px: 1.25,
                  py: 1,
                  borderRadius: 2,
                  border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
                }}
              >
                <Stack spacing={0.25} sx={{ minWidth: 0 }}>
                  <Typography sx={{ fontSize: 13, fontWeight: 700 }} noWrap>
                    {MODEL_LABELS[label] ?? label}
                  </Typography>
                  <Typography sx={{ fontSize: 11, color: "text.secondary" }}>
                    F1 {latest.f1_score.toFixed(3)} · Accuracy {latest.accuracy.toFixed(3)}
                    {latest.promoted ? " · déployé" : ""}
                  </Typography>
                </Stack>
                <TrendChip
                  latest={latest.f1_score}
                  previous={previous ? previous.f1_score : null}
                />
              </Box>
            );
          })}
          </Stack>
        </Stack>
      )}
    </SoftCard>
  );
}
