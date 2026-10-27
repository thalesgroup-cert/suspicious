import * as React from "react";
import {
  Alert, Box, Button, Checkbox, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControl, FormControlLabel, InputLabel, MenuItem, Paper, Select, Stack, TextField, Typography,
} from "@mui/material";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import {
  bulkRedoAnalysis, bulkSetVerdict, type BulkResult,
} from "@/features/investigation/api";
import { classificationOptions } from "@/features/investigation/components/InvestigationOverview";

type Props = { ids: number[]; onClear: () => void };

const inRange = (v: string, max: number) => v.trim() !== "" && Number(v) >= 0 && Number(v) <= max;

function Summary({ results, verb }: { results: BulkResult[]; verb: string }) {
  const count = (o: BulkResult["outcome"]) => results.filter((r) => r.outcome === o).length;
  const problems = results.filter((r) => r.outcome === "skipped" || r.outcome === "failed");
  const done = count("updated") + count("queued");
  return (
    <Alert severity={problems.length ? "warning" : "success"} sx={{ mt: 1 }}>
      {done} {verb}{problems.length ? `, ${count("skipped")} skipped, ${count("failed")} failed` : ""}.
      {problems.map((r) => (
        <Typography key={r.case_id} variant="body2">Case {r.case_id}: {r.detail}</Typography>
      ))}
    </Alert>
  );
}

export function BulkActionBar({ ids, onClear }: Props) {
  const qc = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [classification, setClassification] = React.useState("DANGEROUS");
  const [score, setScore] = React.useState("9");
  const [confidence, setConfidence] = React.useState("90");
  const [notifyReporters, setNotifyReporters] = React.useState(false);
  const [summary, setSummary] = React.useState<{ results: BulkResult[]; verb: string } | null>(null);

  const refresh = () =>
    Promise.all([
      qc.invalidateQueries({ queryKey: ["investigation"] }),
      qc.invalidateQueries({ queryKey: ["investigationDetails"] }),
    ]);

  const verdict = useMutation({
    mutationFn: () => bulkSetVerdict(ids, Number(score), Number(confidence), classification, notifyReporters),
    onSuccess: async (results) => {
      setOpen(false);
      setSummary({ results, verb: "updated" });
      await refresh();
    },
  });
  const redo = useMutation({
    mutationFn: () => bulkRedoAnalysis(ids),
    onSuccess: async (results) => {
      setSummary({ results, verb: "queued for analysis" });
      await refresh();
    },
  });

  if (ids.length === 0 && !summary) return null;
  const valid = inRange(score, 10) && inRange(confidence, 100);
  const busy = verdict.isPending || redo.isPending;

  return (
    <>
      <Paper
        elevation={8}
        role="region"
        aria-label="Bulk actions"
        sx={{
          position: "fixed", bottom: 16, left: "50%", transform: "translateX(-50%)", zIndex: 1200,
          px: 2, py: 1, borderRadius: 3, maxWidth: "calc(100vw - 32px)",
        }}
      >
        <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
          {ids.length > 0 ? <Typography sx={{ fontWeight: 700 }}>{ids.length} selected</Typography> : null}
          <Button variant="contained" disabled={busy || ids.length === 0} onClick={() => setOpen(true)}>
            Set verdict…
          </Button>
          <Button
            variant="outlined" disabled={busy || ids.length === 0}
            startIcon={redo.isPending ? <CircularProgress size={13} color="inherit" /> : undefined}
            onClick={() => redo.mutate()}
          >
            Redo analysis
          </Button>
          <Button onClick={() => { setSummary(null); onClear(); }} disabled={busy}>
            {ids.length > 0 ? "Clear" : "Dismiss"}
          </Button>
        </Stack>
        {redo.isError || (summary === null && verdict.isError) ? (
          <Alert severity="error" sx={{ mt: 1 }}>The request failed. Nothing was changed.</Alert>
        ) : null}
        {summary ? <Summary {...summary} /> : null}
      </Paper>

      <Dialog open={open} onClose={() => !busy && setOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>Set verdict for {ids.length} {ids.length === 1 ? "case" : "cases"}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <FormControl fullWidth size="small">
              <InputLabel id="bulk-classification-label">Classification</InputLabel>
              <Select
                labelId="bulk-classification-label" label="Classification" value={classification}
                onChange={(e) => setClassification(String(e.target.value))}
              >
                {classificationOptions.map((c) => <MenuItem key={c} value={c}>{c}</MenuItem>)}
              </Select>
            </FormControl>
            <Stack direction="row" spacing={1.5}>
              <TextField
                label="Score (0-10)" type="number" size="small" fullWidth value={score}
                onChange={(e) => setScore(e.target.value)}
                error={!inRange(score, 10)} helperText={inRange(score, 10) ? undefined : "Score must be between 0 and 10."}
              />
              <TextField
                label="Confidence (0-100)" type="number" size="small" fullWidth value={confidence}
                onChange={(e) => setConfidence(e.target.value)}
                error={!inRange(confidence, 100)} helperText={inRange(confidence, 100) ? undefined : "Confidence must be between 0 and 100."}
              />
            </Stack>
            <Box>
              <FormControlLabel
                control={<Checkbox size="small" checked={notifyReporters} onChange={(e) => setNotifyReporters(e.target.checked)} />}
                label="Email each reporter about the new verdict"
              />
              <Typography variant="body2" color="text.secondary">
                Replaces the verdict on each selected case and clears its stored explanation, as the single-case edit does. Reporters are only emailed if you tick the box; the search index and SIEM are always updated.
              </Typography>
            </Box>
            {verdict.isError ? <Alert severity="error">The request failed. Nothing was changed.</Alert> : null}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)} disabled={busy}>Cancel</Button>
          <Button variant="contained" disabled={!valid || busy} onClick={() => verdict.mutate()}>
            {verdict.isPending ? "Applying…" : `Apply to ${ids.length} ${ids.length === 1 ? "case" : "cases"}`}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
