import { Box, Table, TableBody, TableCell, TableHead, TableRow } from "@mui/material";

import type { Agreement } from "../api";

const row = (name: string, a: Agreement) => {
  const pct = a.total ? Math.round((a.agree / a.total) * 100) : 0;
  return (
    <TableRow key={name}>
      <TableCell component="th" scope="row">{name}</TableCell>
      <TableCell align="right">{a.agree}</TableCell>
      <TableCell align="right">{a.total}</TableCell>
      <TableCell>
        {a.total ? `${pct}%` : "no results yet"}
        <Box aria-hidden sx={{ height: 6, mt: 0.5, bgcolor: "action.hover" }}>
          <Box sx={{ height: 6, width: `${pct}%`, bgcolor: "primary.main" }} />
        </Box>
      </TableCell>
    </TableRow>
  );
};

export function AgreementTable({ agreement }: { agreement: { class: Agreement; verdict: Agreement } }) {
  return (
    <Table size="small" aria-label="Agreement with the active model">
      <TableHead>
        <TableRow>
          <TableCell>Comparison</TableCell>
          <TableCell align="right">Agree</TableCell>
          <TableCell align="right">Compared</TableCell>
          <TableCell>Share</TableCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {row("AI class", agreement.class)}
        {row("Verdict", agreement.verdict)}
      </TableBody>
    </Table>
  );
}
