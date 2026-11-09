import { Button, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";

import type { ShadowDetail } from "../api";
import { Pager } from "./Pager";

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
