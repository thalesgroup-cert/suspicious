import * as React from "react";
import { Alert, Box, Button, Stack, Typography } from "@mui/material";

import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";

import { useAiModelCandidates, useAiModelStatus, useDiscard, useShadowStart } from "../hooks";
import { checkName, refusalMessage, triggerName } from "../labels";
import { failedNames } from "./gateFormat";
import { GateTable } from "./GateTable";

export function CandidateTab({ onSeeOverview }: { onSeeOverview?(): void }) {
  const list = useAiModelCandidates();
  const status = useAiModelStatus();
  const start = useShadowStart();
  const discard = useDiscard();
  const [dialog, setDialog] = React.useState<null | "start" | "discard">(null);

  if (list.isError) return <Alert severity="error">Could not load the candidates.</Alert>;
  if (!list.data) return <Typography>Loading</Typography>;
  // The list also holds the running shadow; the newest real candidate is the one to act on.
  const c = list.data.results.find((r) => r.status === "candidate");
  if (!c) {
    return (
      <Stack spacing={1} sx={{ alignItems: "flex-start" }}>
        <Typography>No new model is waiting.</Typography>
        <Typography variant="body2" color="text.secondary">
          A new model appears here after a retrain. You check it, test it on live mail, then decide whether to use it.
        </Typography>
        {onSeeOverview && <Button variant="outlined" onClick={onSeeOverview}>Go to Overview to retrain</Button>}
      </Stack>
    );
  }

  const shadowExists = !!status.data?.shadow;
  const canStart = c.eligible && !shadowExists && !start.isPending;
  const failed = failedNames(c.gate);
  const err = start.isError ? refusalMessage(start.error) : discard.isError ? refusalMessage(discard.error) : "";
  const close = () => setDialog(null);

  return (
    <Stack spacing={2}>
      <Box>
        <Typography variant="h6" component="h3">New model {c.version_id}</Typography>
        <Typography variant="body2" color="text.secondary">
          Trained {triggerName(c.trigger).toLowerCase()} on <time dateTime={c.created_at}>{new Date(c.created_at).toLocaleDateString()}</time>
          {" "}from {c.rows ?? "an unknown number of"} labelled mails ({c.excluded_rows ?? 0} left out).
        </Typography>
        <Alert severity={c.eligible ? "success" : "warning"} sx={{ mt: 1 }}>
          {c.eligible
            ? "It passed the quality check. Test it on live mail before using it."
            : `It did not pass the quality check${failed.length ? `: ${failed.map(checkName).join(", ")}` : ""}. It cannot be tested.`}
        </Alert>
      </Box>

      <GateTable gate={c.gate} />

      <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
        <Button variant="contained" disabled={!canStart} onClick={() => setDialog("start")}>
          Test on live mail
        </Button>
        <Button color="error" disabled={discard.isPending} onClick={() => setDialog("discard")}>
          Discard
        </Button>
      </Stack>

      <Box role="status">
        {c.eligible && shadowExists && <Typography variant="body2">Another model is already being tested. Promote or discard it first.</Typography>}
        {err && <Typography variant="body2">{err}</Typography>}
      </Box>

      <ConfirmDialog
        open={dialog === "start"}
        title="Test this model on live mail?"
        body={`${c.version_id} will score live mail next to the model in use. It does not change any verdict.`}
        confirmLabel="Start testing"
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
          discard.mutate({ version_id: c.version_id, expected_status: "candidate" });
        }}
      />
    </Stack>
  );
}
