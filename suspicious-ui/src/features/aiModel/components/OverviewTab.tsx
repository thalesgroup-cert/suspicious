import * as React from "react";
import { Alert, Box, Button, Chip, Paper, Stack, Typography } from "@mui/material";

import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";

import { useAiModelJobs, useAiModelStatus, useResetBreaker } from "../hooks";
import { refusalMessage } from "../labels";
import { RetrainButton } from "./RetrainButton";

// Mirrors stats.AGE_WARNING_DAYS in ai_model/stats.py (the status payload has no age flag).
const AGE_WARNING_DAYS = 60;
const day = (iso: string) => new Date(iso).toLocaleDateString();
const ageDays = (iso: string) => Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);

type Props = { onSeeCandidate(): void; onSeeShadow?(): void; onSeeLedger?(): void };

export function OverviewTab({ onSeeCandidate, onSeeShadow, onSeeLedger }: Props) {
  const { data: s, isError } = useAiModelStatus();
  const reset = useResetBreaker();
  const jobs = useAiModelJobs(s?.job_running ?? false);
  const [confirm, setConfirm] = React.useState(false);
  // "waiting": reset succeeded, status still shows the old open state; "seen": status shows it cleared.
  const [resetNote, setResetNote] = React.useState<null | "waiting" | "seen">(null);
  if (isError) return <Alert severity="error">Could not load the AI model status.</Alert>;
  if (!s) return <Typography>Loading</Typography>;

  const tripped = s.breaker.state === "open" || s.breaker.state === "half-open";
  // Adjusting state during render: keep the note once the breaker clears, drop it if it trips again.
  if (resetNote === "waiting" && !tripped) setResetNote("seen");
  else if (resetNote === "seen" && tripped) setResetNote(null);

  const age = s.active ? ageDays(s.active.created_at) : 0;
  const { schedule } = s;
  const healthy = s.health.ok === true;
  const healthText = s.health.ok === null ? "Not checked yet" : healthy ? "Inference server reachable" : "Inference server not reachable";
  const next: { text: string; action?: () => void; label: string } | null =
    s.counts.candidate > 0 ? { text: "A new model is waiting for your decision.", action: onSeeCandidate, label: "See the new model" }
    : s.shadow ? { text: "A new model is being tested on live mail.", action: onSeeShadow, label: "See the test" }
    : null;

  return (
    <Stack spacing={2}>
      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography variant="overline" color="text.secondary">Model in use</Typography>
        {s.active ? (
          <>
            <Typography variant="h6" component="h3">
              {s.active.version_id === "v0" ? "The original model (v0)" : s.active.version_id}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {age} {age === 1 ? "day" : "days"} old{s.active.version_id === "v0" ? " · confidence scores are not calibrated" : ""}
            </Typography>
            {age > AGE_WARNING_DAYS && (
              <Alert severity="warning" sx={{ mt: 1 }}>This model is older than {AGE_WARNING_DAYS} days. Consider a retrain.</Alert>
            )}
          </>
        ) : (
          <Typography>No model in use.</Typography>
        )}
      </Paper>

      {next && (
        <Alert severity="info" action={next.action && <Button color="inherit" size="small" onClick={next.action}>{next.label}</Button>}>
          {next.text}
        </Alert>
      )}

      <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap", rowGap: 1 }} aria-label="Status">
        <Chip color={s.health.ok === false ? "error" : healthy ? "success" : "default"} label={healthText} />
        <Chip color={tripped ? "warning" : "success"} variant={tripped ? "filled" : "outlined"}
          label={tripped ? "Calls paused after failures" : "Calls to the server allowed"} />
      </Stack>
      {s.health.ok === false && s.health.detail && <Typography variant="body2">{s.health.detail}</Typography>}
      {s.health.checked_at && <Typography variant="body2" color="text.secondary">Server last checked {day(s.health.checked_at)}.</Typography>}
      {tripped && (
        <Box>
          <Button size="small" variant="outlined" onClick={() => setConfirm(true)}>Reset breaker</Button>
        </Box>
      )}
      <Box role="status">
        {resetNote !== null && <Typography variant="body2">The breaker was reset.</Typography>}
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
          setResetNote(null);
          reset.mutate(undefined, { onSuccess: () => setResetNote("waiting") });
        }}
      />

      <Box>
        <Typography variant="subtitle2" component="h4">Training data</Typography>
        <Typography variant="body2">
          {s.ledger.trainable} labelled mails ready to train on
          {s.ledger.flagged ? `, ${s.ledger.flagged} flagged for your attention` : ", none flagged"}.{" "}
          {onSeeLedger && <Button size="small" onClick={onSeeLedger}>See the labels</Button>}
        </Typography>
      </Box>

      <Box>
        <Typography variant="subtitle2" component="h4">Retraining</Typography>
        <Typography variant="body2">
          {schedule.enabled
            ? schedule.next_run
              ? `Automatic: every ${schedule.interval_days} days, next about ${day(schedule.next_run)}.`
              : `Automatic: every ${schedule.interval_days} days.`
            : "Automatic retraining is off. Retrain by hand when you want a new model."}
        </Typography>
        {schedule.enabled && schedule.backoff_until && (
          <Typography variant="body2">Waiting until {day(schedule.backoff_until)} after a failed run.</Typography>
        )}
      </Box>

      {/* The jobs cache is only fresh while a job runs; once it ends the status holds the truth. */}
      <RetrainButton jobRunning={s.job_running} job={s.job_running ? (jobs.data?.results[0] ?? s.jobs[0]) : s.jobs[0]} onSeeCandidate={onSeeCandidate} />
    </Stack>
  );
}
