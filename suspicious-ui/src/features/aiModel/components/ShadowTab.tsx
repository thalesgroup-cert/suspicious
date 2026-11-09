import * as React from "react";
import { Alert, Box, Button, LinearProgress, Stack, TextField, Typography } from "@mui/material";

import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";

import type { ReviewKind } from "../api";
import { MAX_SHADOW_DAYS, SHADOW_MIN_RESULTS } from "../constants";
import { useAiModelShadow, useAiModelStatus, useDiscard, useExtend, usePromote, useRecheck } from "../hooks";
import { refusalMessage } from "../labels";
import { AgreementTable } from "./AgreementTable";
import { CampaignEffects, type Offsets } from "./CampaignEffects";
import { FlipsList } from "./FlipsList";
import { PAGE } from "./Pager";
import { PromotionConditions } from "./PromotionConditions";
import { ReviewDialog } from "./ReviewDialog";

const DAY = 86_400_000;

export function ShadowTab({ onSeeCandidate }: { onSeeCandidate(): void }) {
  const [off, setOff] = React.useState<Offsets & { flips: number }>({ flips: 0, effects: 0, candidate_only: 0, active_only: 0 });
  const [dialog, setDialog] = React.useState<null | "promote" | "discard">(null);
  const [review, setReview] = React.useState<{ kind: ReviewKind; caseId: number } | null>(null);
  const [now] = React.useState(() => Date.now());
  const [days, setDays] = React.useState("");
  const jobRunning = useAiModelStatus().data?.job_running ?? false;
  const [err, setErr] = React.useState<unknown>(null);
  const q = useAiModelShadow({
    flips_limit: PAGE, flips_offset: off.flips,
    effects_limit: PAGE, effects_offset: off.effects,
    candidate_only_limit: PAGE, candidate_only_offset: off.candidate_only,
    active_only_limit: PAGE, active_only_offset: off.active_only,
  }, jobRunning);
  const promote = usePromote();
  const extend = useExtend();
  const recheck = useRecheck();
  const discard = useDiscard();

  if (q.isError) return <Alert severity="error">Could not load the shadow.</Alert>;
  if (!q.data) return <Typography>Loading</Typography>;
  const d = q.data;
  if (!("version_id" in d)) {
    return (
      <Stack spacing={1} sx={{ alignItems: "flex-start" }}>
        <Typography>No shadow is running. Start one from the Candidate tab.</Typography>
        <Button onClick={onSeeCandidate}>Go to Candidate</Button>
      </Stack>
    );
  }

  const busy = promote.isPending || extend.isPending || recheck.isPending || discard.isPending;
  const age = d.shadow_since ? Math.max(0, Math.floor((now - new Date(d.shadow_since).getTime()) / DAY)) : 0;
  const pct = Math.min(100, Math.round((d.live_results / SHADOW_MIN_RESULTS) * 100));
  const n = Number(days);
  const daysOk = /^\d+$/.test(days) && n > d.shadow_min_days && n <= MAX_SHADOW_DAYS;
  // The latest outcome of any action wins, so an old refusal does not outlive a later success.
  const run = <V,>(m: { mutate(v: V, o: { onSuccess(): void; onError(e: unknown): void }): void }, v: V, then?: () => void) =>
    m.mutate(v, { onSuccess: () => { setErr(null); then?.(); }, onError: setErr });
  const page = (k: keyof typeof off, o: number) => setOff((p) => ({ ...p, [k]: o }));
  const close = () => setDialog(null);

  return (
    <Stack spacing={3}>
      <Box>
        <Typography>
          Shadow {d.version_id}: {age} of {d.shadow_min_days} days
        </Typography>
        <Typography id="shadow-results">
          {d.live_results} of {SHADOW_MIN_RESULTS} live results compared
        </Typography>
        <LinearProgress variant="determinate" value={pct} aria-labelledby="shadow-results" aria-valuetext={`${d.live_results} of ${SHADOW_MIN_RESULTS}`} />
      </Box>

      <AgreementTable agreement={d.agreement} />

      <Box>
        <Typography variant="subtitle1" component="h4">Verdict changes</Typography>
        <FlipsList flips={d.flips} offset={off.flips} onPage={(o) => page("flips", o)} onReview={(c) => setReview({ kind: "flip", caseId: c })} />
      </Box>

      <Box>
        <Typography variant="subtitle1" component="h4">Campaigns and alerts</Typography>
        <CampaignEffects data={d} offsets={off} onPage={page} onReview={(c) => setReview({ kind: "campaign", caseId: c })} />
      </Box>

      <Box>
        <Typography variant="subtitle1" component="h4">Promotion conditions</Typography>
        <PromotionConditions conditions={d.conditions} />
      </Box>

      <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", flexWrap: "wrap" }}>
        <Button variant="contained" disabled={d.conditions.length > 0 || busy} onClick={() => setDialog("promote")}>
          Promote
        </Button>
        <TextField
          size="small"
          label="New total days"
          value={days}
          onChange={(e) => setDays(e.target.value)}
          error={days !== "" && !daysOk}
          helperText={days !== "" && !daysOk ? `Enter a whole number above ${d.shadow_min_days}, at most ${MAX_SHADOW_DAYS}` : `Now ${d.shadow_min_days} days, above ${d.shadow_min_days}, at most ${MAX_SHADOW_DAYS}`}
          slotProps={{ htmlInput: { inputMode: "numeric" } }}
        />
        <Button disabled={!daysOk || busy} onClick={() => run(extend, { version_id: d.version_id, days: n }, () => setDays(""))}>
          Extend
        </Button>
        <Button disabled={busy} onClick={() => run(recheck, { version_id: d.version_id })}>
          Recheck
        </Button>
        <Button color="error" disabled={busy} onClick={() => setDialog("discard")}>
          Discard
        </Button>
      </Stack>

      <Box role="status">
        {d.recheck && (
          <Typography variant="body2">
            Last recheck: {d.recheck.passed === true ? "Passed" : d.recheck.passed === false ? "Failed" : "no result yet"}
            {d.recheck.finished_at ? ` on ${new Date(d.recheck.finished_at).toLocaleDateString()}` : ""}
          </Typography>
        )}
        {recheck.isSuccess && <Typography variant="body2">Recheck started.</Typography>}
        {err != null && <Typography variant="body2">{refusalMessage(err)}</Typography>}
      </Box>

      <ReviewDialog versionId={d.version_id} kind={review?.kind ?? "flip"} caseId={review?.caseId ?? null} onClose={() => setReview(null)} />
      <ConfirmDialog
        open={dialog === "promote"}
        title="Promote this version?"
        body={`${d.version_id} becomes the active model and the current one becomes the previous version.`}
        confirmLabel="Promote"
        onCancel={close}
        onConfirm={() => {
          close();
          run(promote, { version_id: d.version_id });
        }}
      />
      <ConfirmDialog
        open={dialog === "discard"}
        title="Discard the shadow?"
        body={`${d.version_id} stops scoring live mail and cannot be used again.`}
        confirmLabel="Discard"
        destructive
        onCancel={close}
        onConfirm={() => {
          close();
          run(discard, { version_id: d.version_id, expected_status: "shadow" });
        }}
      />
    </Stack>
  );
}
