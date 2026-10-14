import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { CloseOutlined, SaveOutlined } from "@mui/icons-material";
import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";

import type { InvestigationDetails, InvestigationListResponse } from "@/features/investigation/api";
import { VerdictExplanation } from "@/features/investigation/VerdictExplanation";
import { ThreatBadge } from "@/features/investigation/ThreatBadge";
import { AnalysisHealthBanner } from "@/features/investigation/AnalysisHealthBanner";
import { pickClassification, pickConfidence, pickScore } from "@/features/investigation/utils";
import { CopyIconButton } from "@/shared/components/CopyIconButton";
import MailPreview from "@/shared/components/MailPreview";
import { ScreenshotPanel } from "@/shared/components/ScreenshotPanel";
import { Section, Stat } from "@/shared/components/SheetSection";
import { humanStatus, normalizeScore } from "@/shared/lib/scoreUtils";
import { monoStack } from "@/styles/themes";

const classificationOptions = [
  "SAFE", "INCONCLUSIVE", "UNCHALLENGED", "ALLOW_LISTED",
  "FAILURE", "SUSPICIOUS", "DANGEROUS",
];

export type EditPayload = { caseId: number; score: number; confidence: number; classification: string };

export type InvestigationOverviewProps = {
  row: InvestigationListResponse["results"][number] | InvestigationDetails;
  caseId: number;
  detailsQuery: UseQueryResult<InvestigationDetails>;
  /** UNKNOWN case type: an IOC group, several observables behind one summary sentence. */
  multi: boolean;
  observableCount: number;
  noAnalyzersRan: boolean;
  verdictHex?: string;
  editMutation: UseMutationResult<unknown, unknown, EditPayload>;
  editMode: boolean;
  onCancelEdit: () => void;
  editScore: string;
  setEditScore: (v: string) => void;
  editConfidence: string;
  setEditConfidence: (v: string) => void;
  editClassification: string;
  setEditClassification: (v: string) => void;
};

/** A monospace value in a quiet box with a copy button: artifacts are pasted into other tools and compared character by character. */
function CopyBlock({ text, title }: { text: string; title: string }) {
  return (
    <Stack direction="row" spacing={0.5}
      sx={{ alignItems: "flex-start", p: 1.25, borderRadius: 1, bgcolor: "action.hover", border: 1, borderColor: "divider" }}>
      <Typography variant="body2" sx={{ flex: 1, minWidth: 0, fontFamily: monoStack, wordBreak: "break-all" }}>
        {text || "—"}
      </Typography>
      {text ? <CopyIconButton text={text} title={title} /> : null}
    </Stack>
  );
}

export function InvestigationOverview({
  row, caseId, detailsQuery, multi, observableCount, noAnalyzersRan, verdictHex,
  editMutation, editMode, onCancelEdit,
  editScore, setEditScore, editConfidence, setEditConfidence, editClassification, setEditClassification,
}: InvestigationOverviewProps) {
  const d = detailsQuery.data;
  const ci = d?.case_infos;
  // IOC road has no analyst-visible score: the stored band number is not a real 0-10 score.
  const iocRoad = !!d?.observable_group;
  // Nothing ran, so nothing was computed: the API's 0 is a default, not a measurement.
  const score = noAnalyzersRan ? null : pickScore(d);
  const confidence = noAnalyzersRan ? null : pickConfidence(d);
  const scoreAi = ci?.score_ai;
  const confAi = ci?.confidence_ai;
  const classAi = ci?.classification_ai == null ? "" : String(ci.classification_ai);
  const hasAi = !!ci && [classAi, scoreAi, confAi, ci.category_ai].some((v) => v != null && v !== "");
  const aiUnclassified = scoreAi === 0 && confAi === 0;

  const scoreNum = Number(editScore);
  const confNum = Number(editConfidence);
  const scoreValid = Number.isFinite(scoreNum) && scoreNum >= 0 && scoreNum <= 10;
  const confValid = Number.isFinite(confNum) && confNum >= 0 && confNum <= 100;
  const canSave = scoreValid && confValid && !!editClassification && !editMutation.isPending;
  const mailPreview = d?.mail_preview_url ?? row.mail_preview_url ?? null;

  return (
    <Stack>
      {/* Banners qualify the verdict, so they come before it. */}
      {(d?.is_allowlisted || d?.is_denylisted) ? (
        <Box sx={{ px: 2.25, pt: 2 }}>
          <Alert severity={d.is_denylisted ? "error" : "success"}>
            {d.is_denylisted ? "This case matched the deny list." : "This case matched the allow list."}
            {d.list_reason ? ` ${d.list_reason}` : ""}
          </Alert>
        </Box>
      ) : null}
      {d?.analysis_health && (d.analysis_health.failed > 0 || d.analysis_health.pending > 0) ? (
        <Box sx={{ px: 2.25, pt: 2 }}>
          <AnalysisHealthBanner health={d.analysis_health} />
        </Box>
      ) : null}

      <Section title="Verdict">
        {detailsQuery.isLoading ? (
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <CircularProgress size={14} />
            <Typography variant="body2" color="text.secondary">Loading…</Typography>
          </Stack>
        ) : detailsQuery.isError ? (
          <Alert severity="warning" sx={{ py: 0.5 }}>Could not load details.</Alert>
        ) : (
          <Stack spacing={2}>
            {/* Plain text: the header chip already carries the verdict colour; this is the stored classification. */}
            <Stack direction="row" spacing={1} useFlexGap sx={{ alignItems: "center", flexWrap: "wrap" }}>
              <Typography variant="body1" sx={{ fontWeight: 650 }}>{humanStatus(String(pickClassification(d)))}</Typography>
              <ThreatBadge value={d?.threat_classification} />
            </Stack>
            <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2.5 }}>
              {iocRoad ? null : (
                <Stat label="Score" value={score != null ? `${score}/10` : null} pct={normalizeScore(score)} hex={verdictHex} />
              )}
              <Stat label="Confidence" value={confidence != null ? `${confidence}%` : null} pct={Math.min(100, confidence ?? 0)} hex={verdictHex} />
            </Box>
            {noAnalyzersRan ? (
              <Typography variant="body2" color="text.secondary">No analyzers ran for this submission.</Typography>
            ) : null}
          </Stack>
        )}
      </Section>

      {ci?.verdict_explanation ? (
        <Section title="Why this verdict">
          <VerdictExplanation data={ci.verdict_explanation} />
        </Section>
      ) : null}

      {hasAi ? (
        <Section title="AI classifier">
          {aiUnclassified ? (
            <Typography variant="body2" color="text.secondary">Not classified</Typography>
          ) : (
            <Stack direction="row" useFlexGap spacing={0.75} sx={{ flexWrap: "wrap" }}>
              {[
                classAi || null,
                `score ${scoreAi ?? "—"}`,
                `conf ${confAi ?? "—"}%`,
                ci.category_ai ? `cat ${ci.category_ai}` : null,
              ].filter((l): l is string => !!l).map((label) => (
                <Chip key={label} size="small" label={label} variant="outlined" sx={{ typography: "caption" }} />
              ))}
            </Stack>
          )}
        </Section>
      ) : null}

      {d?.challenge_proposed_result ? (
        <Section title="Reporter's challenge">
          <Typography variant="body2">
            Proposed verdict: <strong>{d.challenge_proposed_result}</strong>
          </Typography>
          {d.challenge_reason ? (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              Reason: {d.challenge_reason}
            </Typography>
          ) : null}
        </Section>
      ) : null}

      {(d?.reporter_note || d?.reporter_context) ? (
        <Section title="Reporter's context">
          <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "pre-wrap" }}>
            {d.reporter_note || d.reporter_context}
          </Typography>
        </Section>
      ) : null}

      {/* The override form shows only while editing: the verdict block above already shows the current values. */}
      {editMode ? (
        <Section title="Verdict override">
          {detailsQuery.isError ? (
            <Alert severity="warning" sx={{ py: 0.5 }}>Could not load details.</Alert>
          ) : (
            <Stack spacing={1.5}>
              <Stack direction={{ xs: "column", sm: "row" }} spacing={1.25}>
                <TextField id="investigation-edit-score" label="Score (0-10)" value={editScore} autoFocus
                  onChange={(e) => setEditScore(e.target.value)}
                  error={!scoreValid} helperText={scoreValid ? undefined : "Score must be between 0 and 10."}
                  type="number" slotProps={{ htmlInput: { min: 0, max: 10, step: 0.1 } }} size="small" fullWidth />
                <TextField label="Confidence (0-100)" value={editConfidence}
                  onChange={(e) => setEditConfidence(e.target.value)}
                  error={!confValid} helperText={confValid ? undefined : "Confidence must be between 0 and 100."}
                  type="number" slotProps={{ htmlInput: { min: 0, max: 100, step: 0.1 } }} size="small" fullWidth />
              </Stack>
              <FormControl fullWidth size="small">
                <InputLabel id="classification-label">Classification</InputLabel>
                <Select labelId="classification-label" label="Classification"
                  value={editClassification}
                  onChange={(e) => setEditClassification(String(e.target.value))}>
                  {classificationOptions.map((c) => (
                    <MenuItem key={c} value={c}>{c}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }} useFlexGap>
                <Button variant="contained" startIcon={editMutation.isPending ? <CircularProgress size={13} color="inherit" /> : <SaveOutlined />}
                  disabled={!canSave}
                  onClick={() => editMutation.mutate({ caseId, score: scoreNum, confidence: confNum, classification: editClassification })}>
                  {editMutation.isPending ? "Saving…" : "Save"}
                </Button>
                <Button startIcon={<CloseOutlined />} onClick={onCancelEdit}>Cancel</Button>
                {editMutation.isError ? <Alert severity="error" sx={{ py: 0.3, flex: 1 }}>Save failed.</Alert> : null}
              </Stack>
            </Stack>
          )}
        </Section>
      ) : null}

      {multi ? (
        <Section title="Summary">
          <Typography variant="body2">{row.info || "—"}</Typography>
          {observableCount > 0 ? (
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
              {observableCount} observable{observableCount !== 1 ? "s" : ""}
            </Typography>
          ) : null}
        </Section>
      ) : (
        <Section title="Artifact">
          <CopyBlock text={row.info} title="Copy artifact" />
        </Section>
      )}

      <Section title="Reported by">
        {/* Plain line, not the monospace box: an address is read, not compared character by character. */}
        <Stack direction="row" spacing={0.5} sx={{ alignItems: "center", minWidth: 0 }}>
          <Typography variant="body2" sx={{ minWidth: 0, wordBreak: "break-all" }}>{row.reporter_email || "—"}</Typography>
          {row.reporter_email ? <CopyIconButton text={row.reporter_email} title="Copy email" /> : null}
        </Stack>
      </Section>

      {mailPreview ? (
        <Section title="Email preview">
          <MailPreview url={mailPreview} variant="full" alt={`Preview of email for case ${caseId}`} />
        </Section>
      ) : null}

      {d?.screenshot_url ? (
        <Section title="Page screenshot">
          <ScreenshotPanel src={d.screenshot_url} label="Page screenshot" />
        </Section>
      ) : null}
    </Stack>
  );
}
