import * as React from "react";
import { Alert, Box, Link, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";
import { Link as RouterLink } from "react-router";

import { useAiModelQueue } from "../hooks";
import { PAGE, Pager } from "./Pager";

const day = (iso: string) => new Date(iso).toLocaleDateString();

// Ids, classes and dates only: the queue never shows anything about the mail itself.
export function QueueLists() {
  const [dOff, setDOff] = React.useState(0);
  const [cOff, setCOff] = React.useState(0);
  const q = useAiModelQueue({ disagreements_limit: PAGE, disagreements_offset: dOff, conflicts_limit: PAGE, conflicts_offset: cOff });
  if (q.isError) return <Alert severity="error">Could not load the review queue.</Alert>;
  if (!q.data) return <Typography>Loading</Typography>;
  const { disagreements: d, campaign_conflicts: c } = q.data;
  return (
    <Box>
      <Typography variant="subtitle2" component="h4" sx={{ mb: 1 }}>Review queue</Typography>
      {d.count === 0 ? (
        <Typography>No cases where the AI disagrees with the evidence.</Typography>
      ) : (
        <Table size="small" aria-label="AI disagrees with the evidence">
          <TableHead>
            <TableRow>
              {["Case", "Verdict", "AI class", "Date"].map((h) => <TableCell key={h} component="th" scope="col">{h}</TableCell>)}
            </TableRow>
          </TableHead>
          <TableBody>
            {d.results.map((r) => (
              <TableRow key={r.case_id}>
                <TableCell component="th" scope="row">
                  <Link component={RouterLink} to={`/investigation?open=${encodeURIComponent(String(r.case_id))}`}>{r.case_id}</Link>
                </TableCell>
                <TableCell>{r.verdict}</TableCell>
                <TableCell>{r.ai_class}</TableCell>
                <TableCell>{day(r.date)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <Pager count={d.count} offset={dOff} onChange={setDOff} label="AI disagreements" />
      {c.count === 0 ? (
        <Typography>No campaigns with disagreeing members.</Typography>
      ) : (
        // ponytail: no per-campaign route exists (only the /campaigns list), so no link.
        <Table size="small" aria-label="Campaign members disagree">
          <TableHead>
            <TableRow>
              {["Campaign", "Classes", "Date"].map((h) => <TableCell key={h} component="th" scope="col">{h}</TableCell>)}
            </TableRow>
          </TableHead>
          <TableBody>
            {c.results.map((r) => (
              <TableRow key={r.campaign_ref}>
                <TableCell component="th" scope="row">{r.campaign_ref}</TableCell>
                <TableCell>{r.classes.join(", ")}</TableCell>
                <TableCell>{day(r.date)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <Pager count={c.count} offset={cOff} onChange={setCOff} label="campaign conflicts" />
    </Box>
  );
}
