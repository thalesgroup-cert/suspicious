import * as React from "react";
import { Button, Link, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";
import { Link as RouterLink } from "react-router";

import type { ReviewKind, ShadowDetail } from "../api";

type Props = {
  toReview: ShadowDetail["to_review"];
  onReview(kind: ReviewKind, caseId: number): void;
  onReviewAll(kind: ReviewKind): void;
};

const SIDE: Record<"candidate" | "active", string> = {
  candidate: "Only the new model would raise a campaign alert",
  active: "Only the current model raises a campaign alert",
};

export const CaseLink = ({ id }: { id: number }) => (
  <Link component={RouterLink} to={`/investigation?open=${id}`}>{id}</Link>
);

const FIRST = 5;

function Group({ title, hint, count, shown, onAll, rows, head }: {
  title: string; hint: string; count: number; shown: number; onAll(): void; rows: React.ReactNode[]; head: string[];
}) {
  const [all, setAll] = React.useState(false);
  return (
    <Stack spacing={1}>
      <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "center" }}>
        <Typography variant="subtitle1" component="h4">{title}: {count}</Typography>
        <Button size="small" variant="outlined" onClick={onAll}>Mark all {count} reviewed</Button>
      </Stack>
      <Typography variant="body2" color="text.secondary">{hint}</Typography>
      <Table size="small" aria-label={title}>
        <TableHead><TableRow>{head.map((h) => <TableCell key={h}>{h}</TableCell>)}<TableCell /></TableRow></TableHead>
        <TableBody>{all ? rows : rows.slice(0, FIRST)}</TableBody>
      </Table>
      {(rows.length > FIRST || count > shown) && (
        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
          {rows.length > FIRST && (
            <Button size="small" onClick={() => setAll((v) => !v)}>{all ? "Show fewer" : `Show ${rows.length} of ${count}`}</Button>
          )}
          {count > shown && <Typography variant="body2">{count - shown} more are not listed; "Mark all" covers them too.</Typography>}
        </Stack>
      )}
    </Stack>
  );
}

export function ReviewQueue({ toReview, onReview, onReviewAll }: Props) {
  const { flips, alerts } = toReview;
  if (!flips.count && !alerts.count) return <Typography>Nothing left to review.</Typography>;
  return (
    <Stack spacing={3}>
      {flips.count > 0 && (
        <Group title="Risky verdict changes" count={flips.count} shown={flips.results.length} onAll={() => onReviewAll("flip")}
          hint="Mails the current model called Safe and the new model calls Dangerous. Open the case, then mark it reviewed."
          head={["Case", "Now", "With the new model"]}
          rows={flips.results.map((f) => (
            <TableRow key={f.case_id}>
              <TableCell component="th" scope="row"><CaseLink id={f.case_id} /></TableCell>
              <TableCell>{f.live_result}</TableCell>
              <TableCell>{f.would_be_result}</TableCell>
              <TableCell align="right">
                <Button size="small" aria-label={`Review case ${f.case_id}`} onClick={() => onReview("flip", f.case_id)}>Review</Button>
              </TableCell>
            </TableRow>
          ))} />
      )}
      {alerts.count > 0 && (
        <Group title="Alert differences" count={alerts.count} shown={alerts.results.length} onAll={() => onReviewAll("campaign")}
          hint="Cases where the two models disagree about raising a campaign alert."
          head={["Case", "Difference"]}
          rows={alerts.results.map((a) => (
            <TableRow key={a.case_id}>
              <TableCell component="th" scope="row"><CaseLink id={a.case_id} /></TableCell>
              <TableCell>{SIDE[a.side]}</TableCell>
              <TableCell align="right">
                <Button size="small" aria-label={`Review alert case ${a.case_id}`} onClick={() => onReview("campaign", a.case_id)}>Review</Button>
              </TableCell>
            </TableRow>
          ))} />
      )}
    </Stack>
  );
}
