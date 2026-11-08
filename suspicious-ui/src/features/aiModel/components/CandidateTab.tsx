import * as React from "react";
import { Alert, Box, Button, Stack, Typography } from "@mui/material";

import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";

import { useAiModelCandidates, useAiModelStatus, useDiscard, useShadowStart } from "../hooks";
import { refusalMessage } from "../labels";
import { failedNames, GateTable } from "./GateTable";

export function CandidateTab() {
  const list = useAiModelCandidates();
  const status = useAiModelStatus();
  const start = useShadowStart();
  const discard = useDiscard();
  const [dialog, setDialog] = React.useState<null | "start" | "discard">(null);

  if (list.isError) return <Alert severity="error">Could not load the candidates.</Alert>;
  if (!list.data) return <Typography>Loading</Typography>;
  // The list also holds the running shadow; the newest real candidate is the one to act on.
  const c = list.data.results.find((r) => r.status === "candidate");
  if (!c) return <Typography>No candidate. Start a retrain from the Overview tab.</Typography>;

  const shadowExists = !!status.data?.shadow;
  const canStart = c.eligible && !shadowExists && !start.isPending;
  const failed = failedNames(c.gate);
  const err = start.isError ? refusalMessage(start.error) : discard.isError ? refusalMessage(discard.error) : "";
  const close = () => setDialog(null);

  return (
    <Stack spacing={2}>
      <Box>
        <Typography>
          Candidate {c.version_id}, {c.rows ?? "unknown"} rows, {c.excluded_rows ?? 0} excluded
        </Typography>
        <Typography variant="body2">
          Trigger {c.trigger}, created <time dateTime={c.created_at}>{new Date(c.created_at).toLocaleDateString()}</time>
        </Typography>
      </Box>

      <GateTable gate={c.gate} />

      <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
        <Button variant="contained" disabled={!canStart} onClick={() => setDialog("start")}>
          Start shadow
        </Button>
        <Button color="error" disabled={discard.isPending} onClick={() => setDialog("discard")}>
          Discard
        </Button>
      </Stack>

      <Box role="status">
        {!c.eligible && (
          <Typography variant="body2">
            Not eligible{failed.length ? `: ${failed.join(", ")}` : ": the gate result is not available"}
          </Typography>
        )}
        {c.eligible && shadowExists && <Typography variant="body2">A shadow is already running. Promote or discard it first.</Typography>}
        {err && <Typography variant="body2">{err}</Typography>}
      </Box>

      <ConfirmDialog
        open={dialog === "start"}
        title="Start the shadow period?"
        body={`${c.version_id} will score live mail next to the active model. It does not change any verdict.`}
        confirmLabel="Start shadow"
        onCancel={close}
        onConfirm={() => {
          close();
          start.mutate({ version_id: c.version_id });
        }}
      />
      <ConfirmDialog
        open={dialog === "discard"}
        title="Discard this candidate?"
        body={`${c.version_id} is removed from the list and cannot be used again.`}
        confirmLabel="Discard"
        destructive
        onCancel={close}
        onConfirm={() => {
          close();
          discard.mutate({ version_id: c.version_id });
        }}
      />
    </Stack>
  );
}
