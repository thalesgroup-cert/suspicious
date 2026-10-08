import { Alert, Typography } from "@mui/material";

import type { AnalysisHealth } from "./api";

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** Warns when part of the analysis behind the verdict is missing or still running. */
export function AnalysisHealthBanner({ health }: { health?: AnalysisHealth | null }) {
  if (!health || (health.failed === 0 && health.pending === 0)) return null;
  const names = [...new Set(health.failures.map((f) => f.analyzer))].join(", ");
  return (
    <Alert severity={health.failed ? "warning" : "info"} sx={{ py: 0.5 }}>
      {health.failed > 0 && (
        <Typography variant="body2">
          {health.failed} of {health.total} analyzers failed{names ? ` (${names})` : ""}: the verdict has lower confidence.
        </Typography>
      )}
      {health.pending > 0 && (
        <Typography variant="body2">{plural(health.pending, "analyzer")} still running.</Typography>
      )}
    </Alert>
  );
}
