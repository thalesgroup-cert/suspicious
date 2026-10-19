import * as React from "react";
import { Box, Button, Link, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { Link as RouterLink } from "react-router";

import { ensureContrast, flatten } from "@/shared/lib/contrast";

import type { PcaPoint } from "@/features/campaigns/api";
import { classLabel, sortRows, useSort } from "@/features/campaigns/utils";
import { SortCell } from "./PanelState";

// Thousands of DOM rows make the page sluggish; the map holds the rest.
const MAX_ROWS = 200;
// In sx a bare 1 is 100%, so the size is spelled in px.
const visuallyHidden = { position: "absolute", width: "1px", height: "1px", overflow: "hidden", clip: "rect(0 0 0 0)", whiteSpace: "nowrap" } as const;
const NO_CASE = "This message has no case id, so it cannot be selected.";

type Key = "subject" | "case" | "label" | "x" | "y" | "z";
const KEYS: Record<Key, (p: PcaPoint) => string | number | null> = {
  subject: (p) => p.mail_subject,
  case: (p) => p.suspicious_case_id,
  label: (p) => classLabel(p.label),
  x: (p) => p.x,
  y: (p) => p.y,
  z: (p) => p.z,
};

function SelectButton({ point: p, selected, onSelectCases }: { point: PcaPoint; selected: string[]; onSelectCases: (caseIds: string[]) => void }) {
  const id = p.suspicious_case_id;
  const pressed = !!id && selected.includes(id);
  const whyId = React.useId();
  const { palette } = useTheme();
  // Muted by colour, not opacity (a faded text colour falls under 4.5:1): the muted text colour, kept at 4.5:1 on the card.
  const inert = ensureContrast(flatten(palette.text.secondary, palette.background.paper), palette.background.paper, 4.5);
  return (
    <>
      {/* aria-disabled instead of disabled: the button stays in the tab order, so a keyboard user can reach the reason. */}
      <Button
        size="small"
        variant={pressed ? "outlined" : "text"}
        aria-pressed={pressed}
        aria-label={`Select ${p.mail_subject ?? (id ? `case ${id}` : "message")}`}
        aria-disabled={id ? undefined : true}
        aria-describedby={id ? undefined : whyId}
        title={id ? undefined : NO_CASE}
        // A second press takes this case out of the selection; selecting replaces it, like a click in the map.
        onClick={() => id && onSelectCases(pressed ? selected.filter((x) => x !== id) : [id])}
        sx={{ minWidth: 0, ...(id ? {} : { color: inert, cursor: "default", "&:hover": { bgcolor: "transparent" } }) }}
      >
        Select
      </Button>
      {id ? null : (
        <Box component="span" id={whyId} sx={visuallyHidden}>
          {NO_CASE}
        </Box>
      )}
    </>
  );
}

/**
 * The map as text: every sampled message with its coordinates. Given `onSelectCases`, each row has a Select button, so the
 * table is also the keyboard way to pick a message (the canvas can only be picked with a pointer).
 */
export default function PointTable({
  points,
  selectedCaseIds = [],
  onSelectCases,
}: {
  points: PcaPoint[];
  selectedCaseIds?: string[];
  onSelectCases?: (caseIds: string[]) => void;
}) {
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
              {onSelectCases ? <TableCell>Select</TableCell> : null}
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((p, i) => (
              // The row shows what aria-pressed says: a state carried only by a button's attribute is invisible to a sighted user.
              <TableRow key={`${p.suspicious_case_id ?? "none"}-${i}`} selected={!!onSelectCases && !!p.suspicious_case_id && selectedCaseIds.includes(p.suspicious_case_id)}>
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
                {onSelectCases ? (
                  <TableCell>
                    <SelectButton point={p} selected={selectedCaseIds} onSelectCases={onSelectCases} />
                  </TableCell>
                ) : null}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
}
