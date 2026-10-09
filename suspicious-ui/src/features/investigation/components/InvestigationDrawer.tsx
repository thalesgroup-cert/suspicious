import * as React from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  ButtonGroup,
  Chip,
  CircularProgress,
  Divider,
  Drawer,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import {
  ContentCopyOutlined,
  EditOutlined,
  SaveOutlined,
  CloseOutlined,
  ExpandMoreOutlined,
  ReplayOutlined,
  DescriptionOutlined,
  DownloadOutlined,
  NorthEastOutlined,
} from "@mui/icons-material";
import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { alpha, useTheme } from "@mui/material/styles";

import type { InvestigationDetails, InvestigationListResponse } from "@/features/investigation/api";
import type { CaseComment } from "@/features/comments/api";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import { SheetHeader } from "@/shared/components/SheetHeader";
import { CopyIconButton } from "@/shared/components/CopyIconButton";
import MailPreview from "@/shared/components/MailPreview";
import { ScreenshotPanel } from "@/shared/components/ScreenshotPanel";
import { InvestigationAnalyzerReportCard } from "@/features/investigation/components/InvestigationAnalyzerReportCard";
import { ObservableGroupPanel } from "@/features/investigation/ObservableGroupPanel";
import { VerdictExplanation } from "@/features/investigation/VerdictExplanation";
import { ThreatBadge } from "@/features/investigation/ThreatBadge";
import { AnalysisHealthBanner } from "@/features/investigation/AnalysisHealthBanner";
import { CommentThread } from "@/features/comments/CommentThread";
import {
  fmtDate,
  groupReportsByArtifact,
  kindLabel,
  pickClassification,
  pickConfidence,
  pickScore,
} from "@/features/investigation/utils";

const BADGE_W = 132;
const DRAWER_RADIUS = 2;

const classificationOptions = [
  "SAFE", "INCONCLUSIVE", "UNCHALLENGED", "ALLOW_LISTED",
  "FAILURE", "SUSPICIOUS", "DANGEROUS",
];

export type InvestigationDrawerProps = {
  open: boolean;
  onClose: () => void;
  /** List row if present in the current page, else the loaded details. */
  drawerRow: InvestigationListResponse["results"][number] | InvestigationDetails | undefined;
  selectedIdNum: number;
  hasNumericSelectedId: boolean;
  detailsQuery: UseQueryResult<InvestigationDetails>;
  detailsReady: boolean;
  theHiveEnabled: boolean;
  pushMutation: UseMutationResult<unknown, unknown, number>;
  editMutation: UseMutationResult<unknown, unknown, { caseId: number; score: number; confidence: number; classification: string }>;
  editMode: boolean;
  setEditMode: React.Dispatch<React.SetStateAction<boolean>>;
  editScore: string;
  setEditScore: (v: string) => void;
  editConfidence: string;
  setEditConfidence: (v: string) => void;
  editClassification: string;
  setEditClassification: (v: string) => void;
  onRedo: () => void;
  commentsQuery: UseQueryResult<CaseComment[]>;
  addCommentMutation: UseMutationResult<unknown, unknown, string>;
  expandedGroups: Record<string, boolean>;
  setExpandedGroups: React.Dispatch<React.SetStateAction<Record<string, boolean>>>;
  expandedAnalyzerIds: Record<number, boolean>;
  setExpandedAnalyzerIds: React.Dispatch<React.SetStateAction<Record<number, boolean>>>;
  copyEmail: (email?: string) => Promise<void>;
};

export function InvestigationDrawer({
  open, onClose, drawerRow, selectedIdNum, hasNumericSelectedId, detailsQuery, detailsReady,
  theHiveEnabled, pushMutation, editMutation, editMode, setEditMode,
  editScore, setEditScore, editConfidence, setEditConfidence, editClassification, setEditClassification,
  onRedo, commentsQuery, addCommentMutation,
  expandedGroups, setExpandedGroups, expandedAnalyzerIds, setExpandedAnalyzerIds, copyEmail,
}: InvestigationDrawerProps) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const currentScore = pickScore(detailsQuery.data);
  const currentConfidence = pickConfidence(detailsQuery.data);
  const currentClassification = pickClassification(detailsQuery.data);

  const analyzerReports = React.useMemo(
    () => detailsQuery.data?.analyzer_reports ?? [],
    [detailsQuery.data]
  );
  const observableGroup = detailsQuery.data?.observable_group;
  const reportGroups = React.useMemo(
    () => groupReportsByArtifact(analyzerReports),
    [analyzerReports]
  );

  const scoreNum = Number(editScore);
  const confNum = Number(editConfidence);
  const scoreValid = Number.isFinite(scoreNum) && scoreNum >= 0 && scoreNum <= 10;
  const confValid = Number.isFinite(confNum) && confNum >= 0 && confNum <= 100;
  const canSave = scoreValid && confValid && !!editClassification && !editMutation.isPending;

  return (
      <Drawer
        anchor="right"
        open={open}
        onClose={onClose}
        slotProps={{
          paper: {
            sx: (theme) => ({
              width: { xs: "100%", sm: 620 },
              p: 0,
              borderLeft: `1px solid ${theme.palette.divider}`,
              background: `linear-gradient(
                180deg,
                ${theme.palette.background.paper} 0%,
                ${alpha(theme.palette.background.default, 0.98)} 100%
              )`,
              color: theme.palette.text.primary,
              overflow: "hidden",
              borderRadius: DRAWER_RADIUS,
            }),
          },
        }}
      >
        {!drawerRow ? (
          <Box sx={{ p: 2 }}><Alert severity="info">Select a row.</Alert></Box>
        ) : (
          <Stack sx={{ height: "100%" }}>
            <SheetHeader>
              <Stack direction="row" spacing={2} sx={{ alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", rowGap: 1 }} >
                <Box>
                  <Typography variant="overline" color="text.secondary">Investigation</Typography>
                  <Stack direction="row" spacing={1} sx={{ mt: 0.25, alignItems: "center" }}>
                    <Typography variant="h5" sx={{ fontWeight: 950, lineHeight: 1.1 }} >
                      #{drawerRow.id}
                    </Typography>
                    <CopyIconButton text={String(drawerRow.id)} title="Copy ID" />
                  </Stack>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.75 }}>
                    Created {fmtDate(drawerRow.created_at)}
                  </Typography>
                </Box>

                <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap", rowGap: 1, ml: "auto" }} >
                  {hasNumericSelectedId ? (
                    <ButtonGroup variant="outlined" sx={{ borderRadius: 2 }}>
                      <Button
                        startIcon={<DescriptionOutlined />}
                        onClick={() =>
                          window.open(
                            `/api/cases/${selectedIdNum}/report/`,
                            "_blank",
                          )
                        }
                        sx={{ textTransform: "none", fontWeight: 800 }}
                      >
                        Full report
                      </Button>
                      <Button
                        startIcon={<DownloadOutlined />}
                        onClick={() =>
                          window.open(
                            `/api/cases/${selectedIdNum}/report.md`,
                            "_blank",
                          )
                        }
                        sx={{ textTransform: "none", fontWeight: 800 }}
                      >
                        Markdown
                      </Button>
                      {theHiveEnabled ? (
                        <Button
                          startIcon={
                            pushMutation.isPending ? (
                              <CircularProgress size={13} color="inherit" />
                            ) : (
                              <NorthEastOutlined />
                            )
                          }
                          disabled={!detailsReady || pushMutation.isPending}
                          onClick={() => pushMutation.mutate(selectedIdNum)}
                          sx={{ textTransform: "none", fontWeight: 800 }}
                        >
                          {pushMutation.isPending ? "Pushing…" : "Push to TheHive"}
                        </Button>
                      ) : null}
                    </ButtonGroup>
                  ) : null}
                  <Tooltip
                    title={detailsReady ? "" : "Load details to edit global override"}
                    arrow
                    placement="bottom"
                    disableHoverListener={detailsReady}
                  >
                    <span>
                      <Button
                        variant={editMode ? "outlined" : "contained"}
                        startIcon={editMode ? <CloseOutlined /> : <EditOutlined />}
                        onClick={() => {
                          if (!detailsReady) return;
                          const score = pickScore(detailsQuery.data);
                          const confidence = pickConfidence(detailsQuery.data);
                          const classification = pickClassification(detailsQuery.data);
                          setEditScore(score == null ? "" : String(score));
                          setEditConfidence(confidence == null ? "" : String(confidence));
                          setEditClassification(String(classification).toUpperCase());
                          editMutation.reset();
                          setEditMode((prev) => !prev);
                        }}
                        sx={{ textTransform: "none", borderRadius: 2, fontWeight: 950 }}
                        disabled={!detailsReady}
                      >
                        {editMode ? "Cancel" : "Edit"}
                      </Button>
                    </span>
                  </Tooltip>

                  <Button
                    onClick={onClose}
                    sx={{ textTransform: "none", borderRadius: 2, alignSelf: "flex-start" }}
                  >
                    Close
                  </Button>
                </Stack>
              </Stack>

              <Stack direction="row" spacing={1} sx={{ mt: 1.75, flexWrap: "wrap" }}>
                <StatusChip status={drawerRow.status as any} minWidth={BADGE_W} />
                <Chip
                  size="small"
                  label={drawerRow.type}
                  variant="outlined"
                  sx={{
                    fontWeight: 900,
                    minWidth: BADGE_W,
                    justifyContent: "center",
                    "& .MuiChip-label": { width: "100%", textAlign: "center" },
                  }}
                />
                <ResultChip result={drawerRow.result} minWidth={BADGE_W} />
                <Chip
                  size="small"
                  label={`${drawerRow.tests_done} tests`}
                  variant="outlined"
                  sx={{ fontWeight: 900 }}
                />
              </Stack>
            </SheetHeader>

            <Box sx={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
            <Skeleton
              name="investigation-drawer-details"
              loading={detailsQuery.isFetching && detailsQuery.isPlaceholderData}
              animate="shimmer"
            >
            <Box>

              {/* ── Allow/deny-list banner ────────────────────────────────────── */}
              {(detailsQuery.data?.is_allowlisted || detailsQuery.data?.is_denylisted) ? (
                <Box sx={{ px: 2.25, pt: 2 }}>
                  <Alert severity={detailsQuery.data?.is_denylisted ? "error" : "success"}>
                    {detailsQuery.data?.is_denylisted ? "This case matched the deny list." : "This case matched the allow list."}
                    {detailsQuery.data?.list_reason ? ` ${detailsQuery.data.list_reason}` : ""}
                  </Alert>
                </Box>
              ) : null}

              {/* ── Summary strip ──────────────────────────────────────────────── */}
              <Box
                sx={{
                  px: 2.25,
                  py: 1.5,
                  display: "grid",
                  gridTemplateColumns: "repeat(3, 1fr)",
                  gap: 1,
                  borderBottom: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.55)}`,
                  background: isDark ? alpha("#fff", 0.015) : alpha(theme.palette.grey[50], 0.6),
                }}
              >
                {[
                  { label: "Submission", value: `#${drawerRow.id}` },
                  { label: "Tests run", value: drawerRow.tests_done ?? "—" },
                  { label: "Submitted", value: fmtDate(drawerRow.created_at) },
                ].map(({ label, value }) => (
                  <Box key={label}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.07em", color: "text.disabled", mb: 0.2 }}>
                      {label}
                    </Typography>
                    <Typography sx={{ fontWeight: 900, fontSize: 13 }}>{String(value)}</Typography>
                  </Box>
                ))}
              </Box>

              <Stack spacing={0} divider={<Divider sx={{ opacity: isDark ? 0.12 : 0.35 }} />}>

                {/* ── Artifact ──────────────────────────────────────────────────── */}
                <Box sx={{ px: 2.25, py: 2 }}>
                  <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                    Artifact
                  </Typography>
                  <Typography sx={{ wordBreak: "break-all", fontWeight: 700, fontSize: 13.5 }}>
                    {drawerRow.info || "—"}
                  </Typography>
                </Box>

                {/* ── Reporter ──────────────────────────────────────────────────── */}
                <Box sx={{ px: 2.25, py: 2 }}>
                  <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                    Reported by
                  </Typography>
                  <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                    <Typography sx={{ fontWeight: 700, fontSize: 13.5 }}>
                      {drawerRow.reporter_email || "—"}
                    </Typography>
                    {drawerRow.reporter_email ? (
                      <Tooltip title="Copy email">
                        <IconButton size="small" onClick={() => copyEmail(drawerRow.reporter_email)}
                          sx={{ opacity: 0.5, "&:hover": { opacity: 1 } }}>
                          <ContentCopyOutlined sx={{ fontSize: 13 }} />
                        </IconButton>
                      </Tooltip>
                    ) : null}
                  </Stack>
                </Box>

                {/* ── Reporter's challenge (proposed verdict) ───────────────────── */}
                {detailsQuery.data?.challenge_proposed_result ? (
                  <Box sx={{ px: 2.25, py: 2 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                      Reporter's challenge
                    </Typography>
                    <Typography sx={{ fontWeight: 700, fontSize: 13.5 }}>
                      Proposed verdict: <strong>{detailsQuery.data.challenge_proposed_result}</strong>
                    </Typography>
                    {detailsQuery.data.challenge_reason ? (
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                        Reason: {detailsQuery.data.challenge_reason}
                      </Typography>
                    ) : null}
                  </Box>
                ) : null}

                {/* ── Reporter's context / note ─────────────────────────────────── */}
                {(detailsQuery.data?.reporter_note || detailsQuery.data?.reporter_context) ? (
                  <Box sx={{ px: 2.25, py: 2 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                      Reporter's context
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "pre-wrap" }}>
                      {detailsQuery.data.reporter_note || detailsQuery.data.reporter_context}
                    </Typography>
                  </Box>
                ) : null}

                {/* ── Comments (reporter's own + analyst notes) ─────────────────── */}
                <CommentThread
                  title="Comments"
                  comments={commentsQuery.data ?? []}
                  isLoading={commentsQuery.isLoading}
                  onAdd={(body) => addCommentMutation.mutateAsync(body)}
                  isAdding={addCommentMutation.isPending}
                />

                {/* ── Global verdict override ───────────────────────────────────── */}
                <Box sx={{ px: 2.25, py: 2 }}>
                  <Stack direction="row" sx={{ mb: 1, alignItems: "center", justifyContent: "space-between" }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled" }}>
                      Verdict override
                    </Typography>
                    {detailsReady && !editMode ? (
                      <Button
                        size="small"
                        startIcon={<EditOutlined sx={{ fontSize: "13px !important" }} />}
                        onClick={() => {
                          const score = pickScore(detailsQuery.data);
                          const confidence = pickConfidence(detailsQuery.data);
                          const classification = pickClassification(detailsQuery.data);
                          setEditScore(score == null ? "" : String(score));
                          setEditConfidence(confidence == null ? "" : String(confidence));
                          setEditClassification(String(classification).toUpperCase());
                          editMutation.reset();
                          setEditMode(true);
                        }}
                        sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2, fontSize: 12, py: 0.3 }}
                      >
                        Edit
                      </Button>
                    ) : editMode ? (
                      <Button
                        size="small"
                        startIcon={<CloseOutlined sx={{ fontSize: "13px !important" }} />}
                        onClick={() => { setEditMode(false); editMutation.reset(); }}
                        sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2, fontSize: 12, py: 0.3 }}
                      >
                        Cancel
                      </Button>
                    ) : null}
                    {detailsReady ? (
                      <Tooltip
                        title={
                          detailsQuery.data?.status === "DONE" || detailsQuery.data?.status === "CHALLENGED"
                            ? ""
                            : "Case is still being analyzed."
                        }
                      >
                        <span>
                          <Button
                            size="small"
                            startIcon={<ReplayOutlined sx={{ fontSize: "13px !important" }} />}
                            disabled={
                              !(detailsQuery.data?.status === "DONE" || detailsQuery.data?.status === "CHALLENGED")
                            }
                            onClick={() => onRedo()}
                            sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2, fontSize: 12, py: 0.3 }}
                          >
                            Redo analysis
                          </Button>
                        </span>
                      </Tooltip>
                    ) : null}
                  </Stack>

                  {detailsQuery.isLoading ? (
                    <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                      <CircularProgress size={14} />
                      <Typography variant="caption" color="text.secondary">Loading…</Typography>
                    </Stack>
                  ) : detailsQuery.isError ? (
                    <Alert severity="warning" sx={{ py: 0.5 }}>Could not load details.</Alert>
                  ) : !editMode ? (
                    <Stack spacing={1.25}>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }} >
                        <ResultChip result={String(currentClassification ?? "UNKNOWN")} minWidth={BADGE_W} />
                        {/* IOC road has no analyst-visible score: the stored band number is not a real 0-10 score. */}
                        {!observableGroup && (
                          <Chip size="small" label={`Score ${currentScore ?? "—"}/10`} variant="outlined" sx={{ fontWeight: 800 }} />
                        )}
                        <Chip size="small" label={`Confidence ${currentConfidence ?? "—"}%`} variant="outlined" sx={{ fontWeight: 800 }} />
                        <ThreatBadge value={detailsQuery.data?.threat_classification} />
                      </Stack>
                      <Stack direction="row" spacing={0.75} sx={{ opacity: 0.65, flexWrap: "wrap" }}>
                        <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, mr: 0.25 }}>AI:</Typography>
                        {[
                          `${detailsQuery.data?.case_infos?.classification_ai ?? "—"}`,
                          `score ${detailsQuery.data?.case_infos?.score_ai ?? "—"}`,
                          `conf ${detailsQuery.data?.case_infos?.confidence_ai ?? "—"}%`,
                          detailsQuery.data?.case_infos?.category_ai ? `cat ${detailsQuery.data.case_infos.category_ai}` : null,
                        ].filter(Boolean).map((label) => (
                          <Chip key={label as string} size="small" label={label as string} variant="outlined"
                            sx={{ height: 18, fontSize: 10, "& .MuiChip-label": { px: 0.75 } }} />
                        ))}
                      </Stack>
                    </Stack>
                  ) : (
                    <Stack spacing={1.25}>
                      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.25}>
                        <TextField label="Score (0-10)" value={editScore}
                          onChange={(e) => setEditScore(e.target.value)}
                          type="number" slotProps={{ htmlInput: { min: 0, max: 10, step: 0.1 } }} size="small" fullWidth />
                        <TextField label="Confidence (0-100)" value={editConfidence}
                          onChange={(e) => setEditConfidence(e.target.value)}
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
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                        <Button variant="contained" startIcon={editMutation.isPending ? <CircularProgress size={13} color="inherit" /> : <SaveOutlined />}
                          disabled={!canSave || !hasNumericSelectedId}
                          onClick={() => {
                            if (!hasNumericSelectedId) return;
                            editMutation.mutate({ caseId: selectedIdNum, score: scoreNum, confidence: confNum, classification: editClassification });
                          }}
                          sx={{ textTransform: "none", fontWeight: 950, borderRadius: 2 }}>
                          {editMutation.isPending ? "Saving…" : "Save"}
                        </Button>
                        {editMutation.isError ? <Alert severity="error" sx={{ py: 0.3, flex: 1 }}>Save failed.</Alert> : null}
                      </Stack>
                    </Stack>
                  )}
                </Box>

                {/* ── Email preview (only when the case is a mail) ──────────────── */}
                {(detailsQuery.data?.mail_preview_url || drawerRow?.mail_preview_url) ? (
                  <Box sx={{ px: 2.25, py: 2 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                      Email preview
                    </Typography>
                    <MailPreview
                      url={detailsQuery.data?.mail_preview_url ?? drawerRow?.mail_preview_url ?? null}
                      variant="full"
                      alt={`Preview of email for case ${selectedIdNum}`}
                    />
                  </Box>
                ) : null}

                {/* ── Page screenshot captured by the analyzer ─────────────────── */}
                {detailsQuery.data?.screenshot_url ? (
                  <Box sx={{ px: 2.25, py: 2 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                      Page screenshot
                    </Typography>
                    <ScreenshotPanel src={detailsQuery.data.screenshot_url} label="Page screenshot" />
                  </Box>
                ) : null}

                {detailsQuery.data?.analysis_health ? (
                  <Box sx={{ px: 2.25, pt: 1.5 }}>
                    <AnalysisHealthBanner health={detailsQuery.data.analysis_health} />
                  </Box>
                ) : null}

                {detailsQuery.data?.case_infos?.verdict_explanation ? (
                  <Box sx={{ px: 2.25, py: 2 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                      Why this verdict
                    </Typography>
                    <VerdictExplanation data={detailsQuery.data.case_infos.verdict_explanation} />
                  </Box>
                ) : null}

                {/* Analysis results: IOC-group cases get the VT-style panel */}
                {observableGroup ? (
                  <ObservableGroupPanel group={observableGroup} />
                ) : (
                <Box sx={{ px: 2.25, pt: 2, pb: 1 }}>
                  <Stack direction="row" sx={{ mb: 1.25, alignItems: "center", justifyContent: "space-between" }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled" }}>
                      Analysis · {analyzerReports.length} report{analyzerReports.length !== 1 ? "s" : ""}
                    </Typography>
                    {reportGroups.length > 0 ? (
                      <Stack direction="row" spacing={0.5}>
                        <Button size="small" onClick={() => setExpandedGroups(Object.fromEntries(reportGroups.map((g) => [g.key, true])))}
                          sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2, fontSize: 11, py: 0.2, minWidth: 0 }}>
                          Expand all
                        </Button>
                        <Button size="small" onClick={() => setExpandedGroups({})}
                          sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2, fontSize: 11, py: 0.2, minWidth: 0 }}>
                          Collapse
                        </Button>
                      </Stack>
                    ) : null}
                  </Stack>

                  {detailsQuery.isLoading ? (
                    <Stack direction="row" spacing={1} sx={{ py: 2, alignItems: "center" }}>
                      <CircularProgress size={16} />
                      <Typography variant="caption" color="text.secondary">Loading analysis…</Typography>
                    </Stack>
                  ) : detailsQuery.isError ? (
                    <Alert severity="warning" sx={{ mb: 1.5 }}>Could not load analysis details.</Alert>
                  ) : !reportGroups.length ? (
                    <Alert severity="info" sx={{ mb: 1.5 }}>No analysis reports yet.</Alert>
                  ) : (
                    <Stack spacing={1} sx={{ mb: 1.5 }}>
                      {reportGroups.map((group) => {
                        const isGroupOpen = !!expandedGroups[group.key];
                        return (
                          <Box key={group.key}
                            sx={{
                              borderRadius: 2.5,
                              border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.55)}`,
                              background: isDark ? alpha("#fff", 0.02) : alpha(theme.palette.background.paper, 0.5),
                              overflow: "hidden",
                            }}
                          >
                            <Box
                              role="button" tabIndex={0}
                              onClick={() => setExpandedGroups((prev) => ({ ...prev, [group.key]: !prev[group.key] }))}
                              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setExpandedGroups((prev) => ({ ...prev, [group.key]: !prev[group.key] })); } }}
                              sx={{
                                px: 1.75, py: 1.1,
                                display: "flex", alignItems: "center", gap: 1.25,
                                cursor: "pointer", userSelect: "none",
                                background: isDark ? alpha("#fff", 0.03) : alpha(theme.palette.background.paper, 0.7),
                                "&:hover": { background: isDark ? alpha("#fff", 0.05) : alpha(theme.palette.primary.main, 0.04) },
                                transition: "background .15s ease",
                              }}
                            >
                              <Box sx={{
                                px: 0.9, py: 0.2, borderRadius: 1.25,
                                fontSize: 10, fontWeight: 800, letterSpacing: "0.05em", textTransform: "uppercase",
                                bgcolor: isDark ? alpha(theme.palette.primary.main, 0.15) : alpha(theme.palette.primary.main, 0.08),
                                color: isDark ? alpha(theme.palette.primary.light, 0.9) : theme.palette.primary.main,
                                border: `1px solid ${alpha(theme.palette.primary.main, isDark ? 0.25 : 0.18)}`,
                                flexShrink: 0,
                              }}>
                                {kindLabel(group.kind)}
                              </Box>
                              <Typography variant="body2" sx={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: 700 }} title={group.value}>
                                {group.value}
                              </Typography>
                              <Typography variant="caption" color="text.disabled" sx={{ flexShrink: 0, fontSize: 11 }}>
                                {group.reports.length} analyzer{group.reports.length !== 1 ? "s" : ""}
                              </Typography>
                              <ExpandMoreOutlined sx={{
                                fontSize: 18, flexShrink: 0, opacity: 0.6,
                                transform: isGroupOpen ? "rotate(180deg)" : "rotate(0deg)",
                                transition: "transform .2s ease",
                              }} />
                            </Box>

                            {isGroupOpen ? (
                              <Box sx={{ p: 1.25 }}>
                                <Stack spacing={0.9}>
                                  {group.reports.map((report) => (
                                    <InvestigationAnalyzerReportCard
                                      key={report.id}
                                      report={report}
                                      expanded={!!expandedAnalyzerIds[report.id]}
                                      onToggle={() => setExpandedAnalyzerIds((prev) => ({ ...prev, [report.id]: !prev[report.id] }))}
                                    />
                                  ))}
                                </Stack>
                              </Box>
                            ) : null}
                          </Box>
                        );
                      })}
                    </Stack>
                  )}
                </Box>
                )}

                {/* ── Raw details ───────────────────────────────────────────────── */}
                <Accordion disableGutters sx={{ background: "transparent", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreOutlined />} sx={{ px: 2.25, py: 1 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled" }}>
                      Raw API payload
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ px: 2.25, pt: 0, pb: 2 }}>
                    {detailsQuery.isLoading ? <CircularProgress size={16} /> : detailsQuery.isError ? (
                      <Alert severity="warning">Could not load.</Alert>
                    ) : (
                      <Box component="pre" sx={(t) => ({
                        m: 0, p: 1.25, borderRadius: 2,
                        border: `1px solid ${t.palette.divider}`,
                        backgroundColor: alpha(t.palette.action.hover, 0.55),
                        color: t.palette.text.primary,
                        overflow: "auto", maxHeight: 280, fontSize: 11.5, lineHeight: 1.45,
                      })}>
                        {JSON.stringify(detailsQuery.data?.raw ?? detailsQuery.data, null, 2)}
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>

              </Stack>
            </Box>
            </Skeleton>
            </Box>
          </Stack>
        )}
      </Drawer>
  );
}
