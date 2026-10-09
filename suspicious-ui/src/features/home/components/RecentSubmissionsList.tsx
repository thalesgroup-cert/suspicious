import { Link as RouterLink } from "react-router";
import { Box, Button, Stack, Typography } from "@mui/material";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import type { SubmissionRow } from "@/features/home/api";
import { fmtDate, short } from "@/features/home/utils";

/** Phone layout: verdict next to the ID, artifact on one line, meta below. */
export function RecentSubmissionsList({
  rows,
  hrefFor,
}: {
  rows: SubmissionRow[];
  hrefFor: (row: SubmissionRow) => string;
}) {
  return (
    <Stack component="ul" sx={{ listStyle: "none", m: 0, px: 1.5, pb: 1.5 }}>
      {rows.map((r) => (
        <Box
          component="li"
          key={String(r.id)}
          sx={{ py: 1.25, borderTop: 1, borderColor: "divider", minWidth: 0 }}
        >
          <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", gap: 1 }}>
            <Button
              size="small"
              variant="contained"
              component={RouterLink}
              to={hrefFor(r)}
              sx={{ borderRadius: 3, textTransform: "none", fontWeight: 950 }}
            >
              {r.id}
            </Button>
            <ResultChip result={r.result as any} minWidth={96} />
          </Stack>
          <Typography noWrap title={r.artifact ?? ""} sx={{ minWidth: 0, mt: 0.75 }}>
            {short(r.artifact, 64) || "—"}
          </Typography>
          <Stack direction="row" sx={{ alignItems: "center", gap: 1, mt: 0.75, flexWrap: "wrap" }}>
            <StatusChip status={r.status as any} minWidth={96} />
            <Typography variant="body2" color="text.secondary">
              {(r.type ?? "—").toString().toUpperCase()} · {fmtDate(r.created_at)}
            </Typography>
          </Stack>
        </Box>
      ))}
    </Stack>
  );
}
