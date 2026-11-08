import * as React from "react";
import { Box, Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from "@mui/material";

import type { FlagRow } from "../api";
import { RESOLVE_NOTE_MAX } from "../constants";
import { useAiModelFlags, useResolveFlag } from "../hooks";
import { flagReasonText, refusalMessage } from "../labels";
import { PAGE, Pager } from "./Pager";

type Pending = { row: FlagRow; keep: boolean };

export function FlagsList() {
  const id = React.useId();
  const [offset, setOffset] = React.useState(0);
  const [pending, setPending] = React.useState<Pending | null>(null);
  const [note, setNote] = React.useState("");
  // The latest outcome only.
  const [outcome, setOutcome] = React.useState<string | null>(null);
  const q = useAiModelFlags({ limit: PAGE, offset });
  const resolve = useResolveFlag();
  // Kept after close so the title does not blank mid-animation.
  const [shown, setShown] = React.useState<Pending | null>(null);
  const ask = (p: Pending) => { setShown(p); setPending(p); };

  if (q.isError) return <Typography role="alert">Could not load the flagged labels.</Typography>;
  if (!q.data) return <Typography>Loading</Typography>;
  const { results, count } = q.data;
  const close = () => { setPending(null); setNote(""); };
  const valid = note.trim().length > 0 && note.length <= RESOLVE_NOTE_MAX;
  const word = shown?.keep ? "Keep label" : "Drop label";

  const submit = () => {
    if (!pending) return;
    const { row, keep } = pending;
    close();
    resolve.mutate({ id: row.id, keep, note: note.trim() }, {
      onSuccess: () => setOutcome(`Case ${row.case_id}: label ${keep ? "kept" : "dropped"}.`),
      onError: (e) => {
        const conflict = (e as { response?: { status?: number } })?.response?.status === 409;
        setOutcome(conflict ? `Case ${row.case_id}: this flag was already closed. The list is refreshed.` : refusalMessage(e));
      },
    });
  };

  return (
    <Box>
      <Typography variant="subtitle2" component="h4" sx={{ mb: 1 }}>Flagged labels</Typography>
      {count === 0 ? (
        <Typography>No flagged labels.</Typography>
      ) : (
        <TableContainer>
          <Table size="small" aria-label="Flagged labels">
            <TableHead>
              <TableRow>
                {["Case", "Class", "Source", "Reason", "Date", "Action"].map((h) => <TableCell key={h} component="th" scope="col">{h}</TableCell>)}
              </TableRow>
            </TableHead>
            <TableBody>
              {results.map((r) => (
                <TableRow key={r.id}>
                  <TableCell component="th" scope="row">{r.case_id ?? "none"}</TableCell>
                  <TableCell>{r.label_class}</TableCell>
                  <TableCell>{r.source}</TableCell>
                  <TableCell>{flagReasonText(r.flag_reason)}</TableCell>
                  <TableCell>{new Date(r.observed_at).toLocaleDateString()}</TableCell>
                  <TableCell>
                    <Button size="small" disabled={resolve.isPending} aria-label={`Keep label for case ${r.case_id}`} onClick={() => ask({ row: r, keep: true })}>Keep label</Button>
                    <Button size="small" color="error" disabled={resolve.isPending} aria-label={`Drop label for case ${r.case_id}`} onClick={() => ask({ row: r, keep: false })}>Drop label</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <Pager count={count} offset={offset} onChange={setOffset} label="flagged labels" />
      <Box role="status">{outcome && <Typography variant="body2">{outcome}</Typography>}</Box>
      <Dialog open={pending !== null} onClose={close} aria-labelledby={`${id}-t`} aria-describedby={`${id}-b`}>
        <DialogTitle id={`${id}-t`} component="div">{word} for case {shown?.row.case_id}?</DialogTitle>
        <DialogContent>
          <DialogContentText id={`${id}-b`} component="div" sx={{ mb: 1 }}>
            {shown?.keep
              ? "The label stays in the training data."
              : "The label is removed from the training data."}{" "}
            The flag closes and this cannot be undone here. Record why.
          </DialogContentText>
          <TextField label="Note" value={note} onChange={(e) => setNote(e.target.value)} multiline minRows={2} fullWidth required autoFocus
            error={note.length > RESOLVE_NOTE_MAX} helperText={`${note.length} / ${RESOLVE_NOTE_MAX}`} />
        </DialogContent>
        <DialogActions>
          <Button onClick={close}>Cancel</Button>
          <Button variant="contained" color={shown?.keep ? "primary" : "error"} disabled={!valid} onClick={submit}>{word}</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
