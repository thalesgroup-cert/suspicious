// src/shared/components/AnalyzerPanel.tsx
import * as React from "react";
import {
  Alert,
  Box,
  Chip,
  Divider,
  LinearProgress,
  Stack,
  Typography,
} from "@mui/material";
import type { AnalyzerHit } from "@/shared/hooks/detailsNormalize";

function scoreColor(score: number) {
  if (score < 3) return "success";
  if (score < 6) return "warning";
  return "error";
}

/**
 * Dependency-free "chart-like" panel:
 * - each analyzer row shows score & confidence as bars
 * - keeps the spirit of the old Chart.js visualization without adding libs
 */
export function AnalyzerPanel({ analyzers }: { analyzers: AnalyzerHit[] }) {
  if (!analyzers.length) {
    return <Alert severity="info">No analyzers triggered for this submission.</Alert>;
  }

  // stable ordering: highest score first, then confidence
  const sorted = [...analyzers].sort((a, b) => (b.score - a.score) || (b.confidence - a.confidence));

  return (
    <Box
      sx={{
        borderRadius: 3,
        border: "1px solid rgba(255,255,255,.10)",
        background: "rgba(0,0,0,.20)",
        p: 1.5,
      }}
    >
      <Stack spacing={1}>
        <Typography sx={{ fontWeight: 950 }} >Analyzers</Typography>
        <Typography variant="body2" color="text.secondary">
          Score (0–10) and Confidence (0–100).
        </Typography>

        <Divider sx={{ opacity: 0.25 }} />

        {sorted.map((a, idx) => {
          const lvl = (a.level ?? "").toString().trim();
          const st = (a.status ?? "").toString().trim();

          return (
            <Box key={`${a.analyzer_name}-${idx}`} sx={{ py: 0.75 }}>
              <Stack direction="row" spacing={1} sx={{ alignItems: "center", justifyContent: "space-between" }} >
                <Typography sx={{ pr: 1, minWidth: 0, flex: 1, fontWeight: 900 }}>
                  {a.analyzer_name}
                </Typography>

                <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }} >
                  {st ? <Chip size="small" label={st} variant="outlined" sx={{ fontWeight: 850 }} /> : null}
                  {lvl ? <Chip size="small" label={lvl.toUpperCase()} variant="outlined" sx={{ fontWeight: 850 }} /> : null}
                </Stack>
              </Stack>

              <Stack spacing={0.5} sx={{ mt: 0.75 }}>
                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                  <Typography variant="caption" sx={{ width: 82 }} color="text.secondary">
                    Score
                  </Typography>
                  <Box sx={{ flex: 1 }}>
                    <LinearProgress
                      variant="determinate"
                      value={(a.score / 10) * 100}
                      color={scoreColor(a.score) as any}
                      sx={{ height: 8, borderRadius: 999 }}
                    />
                  </Box>
                  <Typography variant="caption" sx={{ width: 46, textAlign: "right", fontWeight: 900 }}>
                    {a.score.toFixed(1)}
                  </Typography>
                </Stack>

                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                  <Typography variant="caption" sx={{ width: 82 }} color="text.secondary">
                    Confidence
                  </Typography>
                  <Box sx={{ flex: 1 }}>
                    <LinearProgress
                      variant="determinate"
                      value={a.confidence}
                      sx={{ height: 8, borderRadius: 999 }}
                    />
                  </Box>
                  <Typography variant="caption" sx={{ width: 46, textAlign: "right", fontWeight: 900 }}>
                    {Math.round(a.confidence)}%
                  </Typography>
                </Stack>
              </Stack>
            </Box>
          );
        })}
      </Stack>
    </Box>
  );
}
