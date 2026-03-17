// src/shared/components/AnalyzerRows.tsx
import * as React from "react";
import { Alert, Box, Chip, Divider, LinearProgress, Stack, Typography } from "@mui/material";
import type { AnalyzerHit } from "@/shared/hooks/detailsNormalize";

function scoreColor(score: number) {
  if (score < 3) return "success";
  if (score < 6) return "warning";
  return "error";
}

export function AnalyzerRows({ analyzers }: { analyzers: AnalyzerHit[] }) {
  if (!analyzers.length) return <Alert severity="info">No analyzers found.</Alert>;

  return (
    <Box
      sx={{
        borderRadius: 3,
        border: "1px solid rgba(255,255,255,.10)",
        background: "rgba(0,0,0,.20)",
        p: 1.25,
      }}
    >
      <Stack spacing={1}>
        {analyzers.map((a, idx) => {
          const lvl = (a.level ?? "").toString().trim();
          const st = (a.status ?? "").toString().trim();

          return (
            <Box key={`${a.analyzer_name}-${idx}`}>
              <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
                <Typography fontWeight={900} sx={{ minWidth: 0, flex: 1, pr: 1 }}>
                  {a.analyzer_name}
                </Typography>
                <Stack direction="row" spacing={0.75} alignItems="center" sx={{ flexWrap: "wrap" }}>
                  {st ? <Chip size="small" label={st} variant="outlined" sx={{ fontWeight: 850 }} /> : null}
                  {lvl ? <Chip size="small" label={lvl.toUpperCase()} variant="outlined" sx={{ fontWeight: 850 }} /> : null}
                </Stack>
              </Stack>

              <Stack spacing={0.5} sx={{ mt: 0.75 }}>
                <Stack direction="row" spacing={1} alignItems="center">
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

                <Stack direction="row" spacing={1} alignItems="center">
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

              {idx !== analyzers.length - 1 ? <Divider sx={{ opacity: 0.2, mt: 1 }} /> : null}
            </Box>
          );
        })}
      </Stack>
    </Box>
  );
}
