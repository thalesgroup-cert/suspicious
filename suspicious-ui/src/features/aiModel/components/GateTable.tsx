import { Box, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";

import type { Gate, GateCheck } from "../api";

const NA = "not available";
/** Numbers and short strings only; anything else is "not available". */
export const show = (v: unknown): string =>
  typeof v === "number" && Number.isFinite(v) ? String(Math.round(v * 10_000) / 10_000) : typeof v === "string" && v ? v.slice(0, 300) : NA;

/** Failed checks first, then by name. A check without a boolean `passed` counts as failed. */
export function sortedChecks(checks: Gate["checks"]): [string, GateCheck][] {
  if (!checks || typeof checks !== "object") return [];
  return Object.entries(checks)
    .filter(([, c]) => c && typeof c === "object")
    .sort(([an, a], [bn, b]) => Number(a.passed === true) - Number(b.passed === true) || an.localeCompare(bn));
}

export const failedNames = (gate: Gate | null) => sortedChecks(gate?.checks ?? null).filter(([, c]) => c.passed !== true).map(([n]) => n);

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
