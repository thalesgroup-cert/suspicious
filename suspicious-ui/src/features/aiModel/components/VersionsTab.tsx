import * as React from "react";
import { Alert, Box, Button, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from "@mui/material";

import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";

import type { VersionRow } from "../api";
import { useAiModelStatus, useAiModelVersions, useRollback } from "../hooks";
import { refusalMessage } from "../labels";
import { PAGE, Pager } from "./Pager";

// Mirror stats.AGE_WARNING_DAYS and stats.MIN_PURITY in ai_model/stats.py.
const MIN_PURITY_PCT = 80;
const AGE_WARNING_DAYS = 60;
// Floor to one decimal so a value just under the threshold never reads as the threshold.
const pct = (p: number) => `${Math.floor(p * 1000) / 10}%`;
const day = (iso: string) => new Date(iso).toLocaleDateString();
const versionName = (id: string) => (id === "v0" ? "v0 (the original model)" : id);

function warnings(v: VersionRow): string[] {
  const out: string[] = [];
  if (v.purity.warning) out.push(`Low purity: ${pct(v.purity.purity ?? 0)} of ${v.purity.labelled} labelled members are Dangerous, below the ${MIN_PURITY_PCT}% threshold.`);
  if (v.age_warning) out.push(`Created more than ${AGE_WARNING_DAYS} days ago.`);
  return out;
}

export function VersionsTab() {
  const [offset, setOffset] = React.useState(0);
  const [confirm, setConfirm] = React.useState<VersionRow | null>(null);
  // The latest outcome only, so an old refusal does not outlive a later success.
  const [outcome, setOutcome] = React.useState<string | null>(null);
  const q = useAiModelVersions({ limit: PAGE, offset });
  const status = useAiModelStatus();
  const rollback = useRollback();

  if (q.isError) return <Alert severity="error">Could not load the version history.</Alert>;
  if (!q.data) return <Typography>Loading</Typography>;
  const { results, count } = q.data;
  const activeId = status.data?.active?.version_id;

  return (
    <Box>
      {count === 0 ? (
        <Typography>No versions yet.</Typography>
      ) : (
        <TableContainer>
          <Table size="small" aria-label="Version history">
            <TableHead>
              <TableRow>
                {["Version", "Status", "Created", "Trigger", "Scored", "Dangerous", "Campaigns created", "Campaigns joined", "Alerts", "Purity", "Warnings", "Action"].map((h) => (
                  <TableCell key={h} component="th" scope="col">{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {results.map((v) => (
                <TableRow key={v.version_id}>
                  <TableCell component="th" scope="row">{versionName(v.version_id)}</TableCell>
                  <TableCell>{v.status}</TableCell>
                  <TableCell>{day(v.created_at)}</TableCell>
                  <TableCell>{v.trigger}</TableCell>
                  <TableCell>{v.stats.scored}</TableCell>
                  <TableCell>{v.stats.dangerous}</TableCell>
                  <TableCell>{v.stats.created}</TableCell>
                  <TableCell>{v.stats.joined}</TableCell>
                  <TableCell>{v.stats.alerts}</TableCell>
                  <TableCell>
                    {v.purity.purity === null ? "no labelled members" : `${pct(v.purity.purity)} of ${v.purity.labelled} labelled`}
                  </TableCell>
                  <TableCell>
                    {warnings(v).map((w) => (
                      <Typography key={w} variant="body2">{w}</Typography>
                    ))}
                  </TableCell>
                  <TableCell>
                    {v.status === "previous" && (
                      <Button size="small" disabled={rollback.isPending} aria-label={`Rollback to ${v.version_id}`} onClick={() => setConfirm(v)}>
                        Rollback
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <Pager count={count} offset={offset} onChange={setOffset} label="versions" />
      <Box role="status">{outcome && <Typography variant="body2">{outcome}</Typography>}</Box>
      <ConfirmDialog
        open={confirm !== null}
        title="Roll back to the previous version?"
        body={`${confirm ? versionName(confirm.version_id) : ""} becomes the active model again and replaces ${activeId ? versionName(activeId) : "the current model"}.`}
        confirmLabel="Roll back"
        destructive
        onCancel={() => setConfirm(null)}
        onConfirm={() => {
          const target = confirm?.version_id ?? "";
          setConfirm(null);
          rollback.mutate({ version_id: target }, {
            onSuccess: () => setOutcome(`Rolled back to ${versionName(target)}.`),
            onError: (e) => setOutcome(refusalMessage(e)),
          });
        }}
      />
    </Box>
  );
}
