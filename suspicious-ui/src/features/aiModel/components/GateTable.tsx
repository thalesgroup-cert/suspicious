import { Box, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";

import type { Gate } from "../api";

import { NA, show, sortedChecks } from "./gateFormat";

export function GateTable({ gate }: { gate: Gate | null }) {
  const checks = sortedChecks(gate?.checks ?? null);
  const camp = gate?.campaign;
  const tiers = gate?.tier_cutoffs;
  return (
    <Box>
      {checks.length ? (
        <Table size="small" aria-label="Gate checks">
          <TableHead>
            <TableRow>
              <TableCell>Check</TableCell>
              <TableCell>Result</TableCell>
              <TableCell align="right">Value</TableCell>
              <TableCell align="right">Threshold</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {checks.map(([name, c]) => (
              <TableRow key={name}>
                <TableCell component="th" scope="row">
                  {name}
                </TableCell>
                <TableCell>{c.passed === true ? "Passed" : "Failed"}</TableCell>
                <TableCell align="right">{show(c.value)}</TableCell>
                <TableCell align="right">{show(c.threshold)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : (
        <Typography>Gate checks: {NA}</Typography>
      )}
      <Typography sx={{ mt: 1 }}>
        {camp
          ? `Campaign held-out: ${show(camp.dangerous_called_safe)} Dangerous called Safe, baseline ${show(camp.baseline_dangerous_called_safe)}, ${show(camp.groups)} groups`
          : `Campaign held-out: ${NA}`}
      </Typography>
      <Typography>{tiers ? `Tier cutoffs: High ${show(tiers.high)}, Medium ${show(tiers.medium)}` : `Tier cutoffs: ${NA}`}</Typography>
    </Box>
  );
}
