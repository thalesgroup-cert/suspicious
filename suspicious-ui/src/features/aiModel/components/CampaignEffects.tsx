import { Button, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";

import type { ShadowDetail } from "../api";
import { Pager } from "./FlipsList";

export type Offsets = { effects: number; candidate_only: number; active_only: number };
type Props = { data: ShadowDetail; offsets: Offsets; onPage(k: keyof Offsets, o: number): void; onReview(caseId: number): void };

export function CampaignEffects({ data, offsets, onPage, onReview }: Props) {
  const fx = data.campaign_effects;
  const alerts = [
    ["candidate_only", "Alerts only the candidate would raise"],
    ["active_only", "Alerts only the active model raises"],
  ] as const;
  return (
    <Stack spacing={2}>
      {fx.count ? (
        <>
          <Table size="small" aria-label="Campaign effects">
            <TableHead>
              <TableRow>
                <TableCell>Case</TableCell>
                <TableCell>Effect</TableCell>
                <TableCell>Live campaign</TableCell>
                <TableCell>Review</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {fx.results.map((e) => (
                <TableRow key={e.case_id}>
                  <TableCell component="th" scope="row">{e.case_id}</TableCell>
                  <TableCell>{e.effect}</TableCell>
                  <TableCell>{e.live_campaign_id ?? "none"}</TableCell>
                  <TableCell>
                    {!e.reviewable ? null : e.reviewed ? (
                      "Reviewed"
                    ) : (
                      <Button size="small" aria-label={`Review campaign case ${e.case_id}`} onClick={() => onReview(e.case_id)}>
                        Review
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Pager count={fx.count} offset={offsets.effects} onChange={(o) => onPage("effects", o)} label="campaign effects" />
        </>
      ) : (
        <Typography>No campaign effects so far.</Typography>
      )}
      {alerts.map(([k, title]) => {
        const list = data.alert_delta[k];
        return (
          <div key={k}>
            <Typography variant="subtitle2">{title}: {list.count}</Typography>
            {list.count > 0 && (
              <>
                <Table size="small" aria-label={title}>
                  <TableHead>
                    <TableRow>
                      <TableCell>Case</TableCell>
                      <TableCell>Review</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {list.results.map((id) => (
                      <TableRow key={id}>
                        <TableCell component="th" scope="row">{id}</TableCell>
                        <TableCell>
                          <Button size="small" aria-label={`Review alert case ${id}`} onClick={() => onReview(id)}>
                            Review
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <Pager count={list.count} offset={offsets[k]} onChange={(o) => onPage(k, o)} label={title} />
              </>
            )}
          </div>
        );
      })}
    </Stack>
  );
}
