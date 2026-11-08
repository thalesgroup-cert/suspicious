import { Alert, Box, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from "@mui/material";

import { useAiModelLedger } from "../hooks";
import { FlagsList } from "./FlagsList";
import { QueueLists } from "./QueueLists";

const CLASSES = ["Dangerous", "Safe", "Unwanted"];
// Floor to one decimal, as the versions table does, so a share never reads above its value.
const pct = (p: number | undefined) => (p === undefined ? "none" : `${Math.floor(p * 1000) / 10}%`);

export function LedgerTab() {
  const q = useAiModelLedger();
  if (q.isError) return <Alert severity="error">Could not load the label ledger.</Alert>;
  if (!q.data) return <Typography>Loading</Typography>;
  const { mix, by_source } = q.data;
  const sources = Object.keys(by_source);
  const classes = [...new Set([...CLASSES, ...sources.flatMap((s) => Object.keys(by_source[s]))])];
  const hasMix = mix.rows.now > 0;

  return (
    <Box sx={{ display: "grid", gap: 3 }}>
      <Box>
        <Typography variant="subtitle2" component="h4" sx={{ mb: 1 }}>Labels by source</Typography>
        <TableContainer>
          <Table size="small" aria-label="Labels by source">
            <TableHead>
              <TableRow>
                <TableCell component="th" scope="col">Source</TableCell>
                {classes.map((c) => <TableCell key={c} component="th" scope="col">{c}</TableCell>)}
              </TableRow>
            </TableHead>
            <TableBody>
              {sources.map((s) => (
                <TableRow key={s}>
                  <TableCell component="th" scope="row">{s}</TableCell>
                  {classes.map((c) => <TableCell key={c}>{by_source[s][c] ?? 0}</TableCell>)}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Box>
      <Box>
        <Typography variant="subtitle2" component="h4" sx={{ mb: 1 }}>Label mix</Typography>
        {mix.jump && (
          <Alert severity="warning" sx={{ mb: 1 }}>
            {mix.jump.class} moved from {pct(mix.jump.from)} to {pct(mix.jump.to)} of folder labels in the last 30 days.
          </Alert>
        )}
        {!hasMix ? (
          <Typography>No folder labels yet.</Typography>
        ) : (
          <Table size="small" aria-label="Label mix">
            <TableHead>
              <TableRow>
                <TableCell component="th" scope="col">Class</TableCell>
                <TableCell component="th" scope="col">Now ({mix.rows.now} labels)</TableCell>
                <TableCell component="th" scope="col">30 days ago ({mix.rows.before} labels)</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {CLASSES.map((c) => (
                <TableRow key={c}>
                  <TableCell component="th" scope="row">{c}</TableCell>
                  <TableCell>{pct(mix.now[c])}</TableCell>
                  <TableCell>{pct(mix.before[c])}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Box>
      <FlagsList />
      <QueueLists />
    </Box>
  );
}
