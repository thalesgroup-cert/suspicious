import * as React from "react";
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, TextField } from "@mui/material";

import type { ReviewKind } from "../api";
import { useReviewAll } from "../hooks";
import { NOTE_MAX } from "./ReviewDialog";

type Props = { versionId: string; kind: ReviewKind | null; count: number; what: string; onClose(): void };

/** One shared note; the server still writes one review row per case. */
export function BulkReviewDialog({ versionId, kind, count, what, onClose }: Props) {
  const [note, setNote] = React.useState("");
  const reviewAll = useReviewAll();
  const valid = note.trim().length > 0 && note.length <= NOTE_MAX;
  const done = () => {
    setNote("");
    onClose();
  };
  return (
    <Dialog open={kind != null} onClose={done}>
      <DialogTitle>Mark {count} {what} as reviewed</DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ mb: 1 }}>
          Say what you checked. The same note is kept with each of the {count} reviews.
        </DialogContentText>
        <TextField label="Review note" value={note} onChange={(e) => setNote(e.target.value)} multiline minRows={3} fullWidth required autoFocus
          error={note.length > NOTE_MAX} helperText={`${note.length} / ${NOTE_MAX}`} />
      </DialogContent>
      <DialogActions>
        <Button onClick={done}>Cancel</Button>
        <Button variant="contained" disabled={!valid || reviewAll.isPending}
          onClick={() => reviewAll.mutate({ version_id: versionId, kind: kind as ReviewKind, note: note.trim() }, { onSuccess: done })}>
          Mark all reviewed
        </Button>
      </DialogActions>
    </Dialog>
  );
}
