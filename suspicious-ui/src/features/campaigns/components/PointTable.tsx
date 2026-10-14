import { Link, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from "@mui/material";
import { Link as RouterLink } from "react-router";

import type { PcaPoint } from "@/features/campaigns/api";
import { classLabel, sortRows, useSort } from "@/features/campaigns/utils";
import { SortCell } from "./PanelState";

// Thousands of DOM rows make the page sluggish; the map holds the rest.
const MAX_ROWS = 200;

type Key = "subject" | "case" | "label" | "x" | "y" | "z";
const KEYS: Record<Key, (p: PcaPoint) => string | number | null> = {
  subject: (p) => p.mail_subject,
  case: (p) => p.suspicious_case_id,
  label: (p) => classLabel(p.label),
  x: (p) => p.x,
  y: (p) => p.y,
  z: (p) => p.z,
};

/** The map as text: every sampled message with its coordinates. */
export default function PointTable({ points }: { points: PcaPoint[] }) {
  const { sort, onSort } = useSort<Key>({ key: "label", dir: "asc" }, () => "asc");
  const rows = sortRows(points, KEYS[sort.key], sort.dir).slice(0, MAX_ROWS);
  const cell = (k: Key, label: string, align?: "right") => (
    <SortCell id={k} sort={sort} onSort={onSort} align={align}>
      {label}
    </SortCell>
  );

  return (
    <>
      {points.length > MAX_ROWS ? (
        <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 1 }}>
          Showing {MAX_ROWS} of {points.length.toLocaleString()}
        </Typography>
      ) : null}
      <TableContainer sx={{ maxHeight: 420 }}>
        <Table size="small" stickyHeader>
          <caption>Sampled messages with their position on the first three components</caption>
          <TableHead>
            <TableRow>
              {cell("subject", "Subject")}
              {cell("case", "Case")}
              {cell("label", "Classification")}
              {cell("x", "PC1", "right")}
              {cell("y", "PC2", "right")}
              {cell("z", "PC3", "right")}
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((p, i) => (
              <TableRow key={`${p.suspicious_case_id ?? "none"}-${i}`}>
                <TableCell sx={{ maxWidth: 260, overflowWrap: "anywhere" }}>{p.mail_subject ?? "—"}</TableCell>
                <TableCell>
                  {p.suspicious_case_id ? (
                    <Link component={RouterLink} to={`/investigation?open=${encodeURIComponent(p.suspicious_case_id)}`}>
                      {p.suspicious_case_id}
                    </Link>
                  ) : (
                    "—"
                  )}
                </TableCell>
                <TableCell>{classLabel(p.label)}</TableCell>
                {[p.x, p.y, p.z].map((v, j) => (
                  <TableCell key={j} align="right" sx={{ fontVariantNumeric: "tabular-nums" }}>
                    {v.toFixed(3)}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
}
