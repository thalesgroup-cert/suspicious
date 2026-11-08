import { Button, Table, TableBody, TableCell, TableHead, TablePagination, TableRow, Typography } from "@mui/material";

import type { ShadowDetail } from "../api";

export const PAGE = 10;

export function Pager({ count, offset, onChange, label }: { count: number; offset: number; onChange(o: number): void; label: string }) {
  return (
    <TablePagination
      component="div"
      count={count}
      page={Math.floor(offset / PAGE)}
      rowsPerPage={PAGE}
      rowsPerPageOptions={[]}
      onPageChange={(_, p) => onChange(p * PAGE)}
      slotProps={{ actions: { previousButton: { "aria-label": `Previous page of ${label}` }, nextButton: { "aria-label": `Next page of ${label}` } } }}
    />
  );
}

type Props = { flips: ShadowDetail["flips"]; offset: number; onPage(o: number): void; onReview(caseId: number): void };

export function FlipsList({ flips, offset, onPage, onReview }: Props) {
  if (!flips.count) return <Typography>No verdict changes so far.</Typography>;
  return (
    <>
      <Table size="small" aria-label="Verdict changes">
        <TableHead>
          <TableRow>
            <TableCell>Case</TableCell>
            <TableCell>Change</TableCell>
            <TableCell>Live</TableCell>
            <TableCell>With candidate</TableCell>
            <TableCell>Review</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {flips.results.map((f) => (
            <TableRow key={f.case_id}>
              <TableCell component="th" scope="row">{f.case_id}</TableCell>
              <TableCell>{f.flip === "critical" ? "Critical" : "Changed"}</TableCell>
              <TableCell>{f.live_result}</TableCell>
              <TableCell>{f.would_be_result}</TableCell>
              <TableCell>
                {!f.reviewable ? null : f.reviewed ? (
                  "Reviewed"
                ) : (
                  <Button size="small" aria-label={`Review case ${f.case_id}`} onClick={() => onReview(f.case_id)}>
                    Review
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Pager count={flips.count} offset={offset} onChange={onPage} label="verdict changes" />
    </>
  );
}
