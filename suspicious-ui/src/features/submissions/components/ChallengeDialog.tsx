import * as React from "react";
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";

export const MIN_CHALLENGE_REASON = 10; // keep in step with the backend serializer
const DIALOG_RADIUS = 2;

export type ChallengeVerdict = "Safe" | "Dangerous";
export type ChallengeRequest = { id: number; proposed_result: ChallengeVerdict; reason: string };

/**
 * Asks what the verdict should have been, and why. Open while `caseId` is set.
 * The caller owns the request: it passes `pending`/`error` and closes the dialog on success.
 * The form starts empty for each case it is opened on.
 */
export function ChallengeDialog({ caseId, onClose, onSubmit, pending, error }: {
  caseId: number | null;
  onClose: () => void;
  onSubmit: (request: ChallengeRequest) => void;
  pending: boolean;
  error: boolean;
}) {
  const [verdict, setVerdict] = React.useState<ChallengeVerdict | null>(null);
  const [reason, setReason] = React.useState("");

  // Reset while rendering when the case changes; an effect would paint the old text first.
  const [formFor, setFormFor] = React.useState(caseId);
  if (formFor !== caseId) {
    setFormFor(caseId);
    setVerdict(null);
    setReason("");
  }

  const trimmed = reason.trim();
  const canSubmit = caseId !== null && verdict !== null && trimmed.length >= MIN_CHALLENGE_REASON && !pending;

  return (
    <Dialog
      open={caseId !== null}
      onClose={onClose}
      maxWidth="xs"
      fullWidth
      slotProps={{ paper: { sx: { borderRadius: DIALOG_RADIUS } } }}
    >
      <DialogTitle>Challenge submission</DialogTitle>
      <DialogContent>
        <Typography color="text.secondary">
          Tell us what you think the verdict should be for submission #{caseId}.
        </Typography>
        <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
          What should the verdict be?
        </Typography>
        <ToggleButtonGroup value={verdict} exclusive onChange={(_, v) => v && setVerdict(v)} size="small">
          <ToggleButton value="Safe">Safe</ToggleButton>
          <ToggleButton value="Dangerous">Dangerous</ToggleButton>
        </ToggleButtonGroup>
        <TextField
          label="Why is the verdict wrong?"
          helperText={`Required, at least ${MIN_CHALLENGE_REASON} characters.`}
          required
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          multiline
          minRows={2}
          fullWidth
          sx={{ mt: 2 }}
        />
        {error ? <Alert severity="error" sx={{ mt: 2 }}>Failed to challenge.</Alert> : null}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} sx={{ borderRadius: 2 }}>Cancel</Button>
        <Button
          variant="contained"
          disabled={!canSubmit}
          onClick={() => {
            if (caseId !== null && verdict) onSubmit({ id: caseId, proposed_result: verdict, reason: trimmed });
          }}
          sx={{ textTransform: "none", fontWeight: 950, borderRadius: 2 }}
        >
          {pending ? "Sending…" : "Confirm"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
