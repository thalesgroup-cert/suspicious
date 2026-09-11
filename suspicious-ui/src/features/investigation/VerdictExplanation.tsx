import { useState } from "react";
import { Box, Button, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";
import type { VerdictExplanationDTO } from "./api";

export function VerdictExplanation({ data }: { data: VerdictExplanationDTO | null | undefined }) {
  const [open, setOpen] = useState(false);
  if (!data) return null;
  return (
    <Box>
      <Typography variant="body2" sx={{ mb: 0.5 }}>{data.analyst_paragraph}</Typography>
      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
        {data.confidence_reading}
      </Typography>
      {data.sources.length > 0 && (
        <>
          <Button size="small" onClick={() => setOpen((v) => !v)}>
            {open ? "Hide source breakdown" : "Show source breakdown"}
          </Button>
          {open && (
            <Table size="small" sx={{ mt: 1 }}>
              <TableHead>
                <TableRow>
                  <TableCell>Source</TableCell><TableCell>Tier</TableCell>
                  <TableCell>Verdict</TableCell><TableCell>Counted</TableCell><TableCell>Note</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.sources.map((s) => (
                  <TableRow key={s.name}>
                    <TableCell>{s.name}</TableCell><TableCell>{s.tier}</TableCell>
                    <TableCell>{s.verdict}</TableCell>
                    <TableCell>{s.counted ? "yes" : "—"}</TableCell>
                    <TableCell>{s.note}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </>
      )}
    </Box>
  );
}
