import * as React from "react";
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, TextField } from "@mui/material";

import type { ReviewKind } from "../api";
import { useReview } from "../hooks";

export const NOTE_MAX = 2000;

export function ReviewDialog({ kind, caseId, onClose }: { kind: ReviewKind; caseId: number | null; onClose(): void }) {
  const id = React.useId();
  const [note, setNote] = React.useState("");
  const review = useReview();
  const valid = note.trim().length > 0 && note.length <= NOTE_MAX;
  const done = () => {
    setNote("");
    onClose();
  };
  return (
    <Dialog open={caseId != null} onClose={done} aria-labelledby={`${id}-t`} aria-describedby={`${id}-b`}>
      <DialogTitle id={`${id}-t`} component="div">
        Review case {caseId}
      </DialogTitle>
      <DialogContent>
        <DialogContentText id={`${id}-b`} component="div" sx={{ mb: 1 }}>
          Record what you checked. The note is kept with the review.
        </DialogContentText>
        <TextField
          label="Review note"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          multiline
          minRows={3}
          fullWidth
          required
          autoFocus
          error={note.length > NOTE_MAX}
          helperText={`${note.length} / ${NOTE_MAX}`}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={done}>Cancel</Button>
        <Button
          variant="contained"
          disabled={!valid || review.isPending}
          onClick={() => review.mutate({ kind, case_id: Number(caseId), note: note.trim() }, { onSuccess: done })}
        >
          Save review
        </Button>
      </DialogActions>
    </Dialog>
  );
}
