import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { ExpandMoreOutlined } from "@mui/icons-material";

import type { Source } from "./observableGroup";

const VERDICT_COLOR: Record<string, "error" | "warning" | "success" | "default"> = {
  malicious: "error",
  suspicious: "warning",
  clean: "success",
  "no-data": "default",
};

export function SourceTable({ sources }: { sources: Source[] }) {
  return (
    <Table size="small">
      <TableHead>
        <TableRow>
          <TableCell>Source</TableCell>
          <TableCell>Tier</TableCell>
          <TableCell>Verdict</TableCell>
          <TableCell>Evidence</TableCell>
          <TableCell>Details</TableCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {sources.map((source, i) => (
          <TableRow key={`${source.name}-${i}`}>
            <TableCell>{source.name}</TableCell>
            <TableCell>
              <Chip size="small" variant="outlined" label={`T${source.tier}`} />
            </TableCell>
            <TableCell>
              <Chip size="small" color={VERDICT_COLOR[source.verdict] ?? "default"} label={source.verdict} />
            </TableCell>
            <TableCell>{source.evidence}</TableCell>
            <TableCell>
              <Accordion disableGutters sx={{ background: "transparent", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                  <Typography variant="caption">Analyzer detail</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Box
                    component="pre"
                    sx={{ m: 0, p: 1.25, borderRadius: 2, overflow: "auto", maxHeight: 220, fontSize: 12 }}
                  >
                    {JSON.stringify(source.report, null, 2)}
                  </Box>
                </AccordionDetails>
              </Accordion>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
