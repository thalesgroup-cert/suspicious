import * as React from "react";
import { Alert, Box, Button, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";

import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";

import { useAiModelJobs, useAiModelStatus, useResetBreaker } from "../hooks";
import { refusalMessage } from "../labels";
import { RetrainButton } from "./RetrainButton";

// Mirrors stats.AGE_WARNING_DAYS in ai_model/stats.py (the status payload has no age flag).
const AGE_WARNING_DAYS = 60;
const day = (iso: string) => new Date(iso).toLocaleDateString();
const ageDays = (iso: string) => Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);

export function OverviewTab({ onSeeCandidate }: { onSeeCandidate(): void }) {
  const { data: s, isError } = useAiModelStatus();
  const reset = useResetBreaker();
  const jobs = useAiModelJobs(s?.job_running ?? false);
  const [confirm, setConfirm] = React.useState(false);
  // The breaker state seen when a reset succeeded; the note hides once the published state moves.
  const [resetAt, setResetAt] = React.useState<string | null>(null);
  if (isError) return <Alert severity="error">Could not load the AI model status.</Alert>;
  if (!s) return <Typography>Loading</Typography>;

  const health = s.health.ok === null ? "never checked" : s.health.ok ? "ok" : "failing";
  const sources = Object.keys(s.ledger.by_source);
  const classes = [...new Set(sources.flatMap((k) => Object.keys(s.ledger.by_source[k])))];
  const age = s.active ? ageDays(s.active.created_at) : 0;
  const { schedule } = s;

  return (
    <Stack spacing={2}>
      <Box>
        <Typography>Connector health: {health}</Typography>
        {s.health.ok === false && s.health.detail && <Typography variant="body2">{s.health.detail}</Typography>}
        {s.health.checked_at && <Typography variant="body2">Checked {day(s.health.checked_at)}</Typography>}
      </Box>

      <Box>
        <Typography>Circuit breaker: {s.breaker.state}</Typography>
        {(s.breaker.state === "open" || s.breaker.state === "half-open") && (
          <Button size="small" onClick={() => setConfirm(true)}>
            Reset breaker
          </Button>
        )}
        <Box role="status">
          {resetAt !== null && resetAt === s.breaker.state && <Typography variant="body2">The breaker was reset.</Typography>}
          {reset.isError && <Typography variant="body2">{refusalMessage(reset.error, "breaker")}</Typography>}
        </Box>
        <ConfirmDialog
          open={confirm}
          title="Reset the circuit breaker?"
          body="Calls to the inference server resume. If the server is still down, the breaker opens again after the next failures."
          confirmLabel="Reset"
          onCancel={() => setConfirm(false)}
          onConfirm={() => {
            setConfirm(false);
            setResetAt(null);
            reset.mutate(undefined, { onSuccess: () => setResetAt(s.breaker.state) });
          }}
        />
      </Box>

      <Box>
        {s.active ? (
          <>
            <Typography>
              Active version: {s.active.version_id}, {age} {age === 1 ? "day" : "days"} old
            </Typography>
            {s.active.version_id === "v0" && <Typography variant="body2">Confidence not calibrated.</Typography>}
            {age > AGE_WARNING_DAYS && (
              <Alert severity="warning">This version is older than {AGE_WARNING_DAYS} days. Consider a retrain.</Alert>
            )}
          </>
        ) : (
          <Typography>No active version.</Typography>
        )}
      </Box>

      <Box>
        <Typography variant="subtitle2" component="h4">
          Labels by class and source
        </Typography>
        <Table size="small" aria-label="Labels by class and source">
          <TableHead>
            <TableRow>
              <TableCell>Source</TableCell>
              {classes.map((c) => (
                <TableCell key={c} align="right">
                  {c}
                </TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {sources.map((src) => (
              <TableRow key={src}>
                <TableCell component="th" scope="row">
                  {src}
                </TableCell>
                {classes.map((c) => (
                  <TableCell key={c} align="right">
                    {s.ledger.by_source[src][c] ?? 0}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <Typography variant="body2">
          {s.ledger.trainable} trainable, {s.ledger.flagged} flagged.
        </Typography>
      </Box>

      <Box>
        <Typography>
          {schedule.enabled
            ? schedule.next_run
              ? `Automatic retrain every ${schedule.interval_days} days, next about ${day(schedule.next_run)}`
              : `Automatic retrain every ${schedule.interval_days} days`
            : "Automatic retrain: Off"}
        </Typography>
        {schedule.enabled && schedule.backoff_until && (
          <Typography variant="body2">Waiting until {day(schedule.backoff_until)} after a failed run.</Typography>
        )}
      </Box>

      <RetrainButton jobRunning={s.job_running} job={jobs.data?.results[0] ?? s.jobs[0]} onSeeCandidate={onSeeCandidate} />
    </Stack>
  );
}
