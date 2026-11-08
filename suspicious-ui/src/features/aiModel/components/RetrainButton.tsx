import * as React from "react";
import { Box, Button, Stack, Typography } from "@mui/material";

import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";

import type { JobRow } from "../api";
import { useRetrain } from "../hooks";
import { refusalMessage } from "../labels";

/** A 409 carries a generic message, so only `job_running` from the status can disable the button. */
export function RetrainButton({ jobRunning, job, onSeeCandidate }: { jobRunning: boolean; job?: JobRow; onSeeCandidate(): void }) {
  const [open, setOpen] = React.useState(false);
  const retrain = useRetrain();
  const refusal = retrain.isError ? refusalMessage(retrain.error, "retrain") : "";
  return (
    <Stack spacing={1} sx={{ alignItems: "flex-start" }}>
      <Button variant="outlined" disabled={jobRunning || retrain.isPending} onClick={() => setOpen(true)}>
        Retrain now
      </Button>
      <Box role="status">
        {refusal && <Typography variant="body2">{refusal}</Typography>}
        {job && (
          <Typography variant="body2">
            Last job{job.kind === "recheck" ? " (gate recheck)" : ""}: {job.state}
            {job.rows != null ? `, ${job.rows} rows` : ""}
            {job.excluded_rows ? `, ${job.excluded_rows} excluded` : ""}
          </Typography>
        )}
      </Box>
      {job?.kind === "retrain" && job.state === "succeeded" && !jobRunning && (
        <Button size="small" onClick={onSeeCandidate}>
          See candidate
        </Button>
      )}
      <ConfirmDialog
        open={open}
        title="Start a retrain?"
        body="This trains a new candidate from the labelled mail. It does not change the active model."
        confirmLabel="Start retrain"
        onCancel={() => setOpen(false)}
        onConfirm={() => {
          setOpen(false);
          retrain.mutate({});
        }}
      />
    </Stack>
  );
}
