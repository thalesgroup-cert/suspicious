import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
  Drawer,
  Stack,
  Typography,
} from "@mui/material";
import { DescriptionOutlined, ExpandMoreOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import type { UseQueryResult } from "@tanstack/react-query";
import type { SubmissionDetails, SubmissionRow } from "@/features/submissions/api";
import type { CaseComment } from "@/features/comments/api";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import { SheetHeader } from "@/shared/components/SheetHeader";
import { CopyIconButton } from "@/shared/components/CopyIconButton";
import MailPreview from "@/shared/components/MailPreview";
import { AnalyzerReportCard } from "@/features/submissions/components/AnalyzerReportCard";
import { UrlGroupList } from "@/features/submissions/components/UrlGroupList";
import { CommentThread } from "@/features/comments/CommentThread";
import { fmtDate, groupReportsByArtifact, kindLabel } from "@/features/submissions/utils";

const BADGE_W = 132;

export type SubmissionDrawerProps = {
  open: boolean;
  onClose: () => void;
  row: SubmissionRow | undefined;
  submissionId: number;
  details: UseQueryResult<SubmissionDetails>;
  comments: UseQueryResult<CaseComment[]>;
  onAddComment: (body: string) => Promise<unknown>;
  isAddingComment: boolean;
  expandedGroups: Record<string, boolean>;
  setExpandedGroups: React.Dispatch<React.SetStateAction<Record<string, boolean>>>;
  expandedAnalyzerIds: Record<number, boolean>;
  setExpandedAnalyzerIds: React.Dispatch<React.SetStateAction<Record<number, boolean>>>;
};

export function SubmissionDrawer({
  open,
  onClose,
  row: selectedRow,
  submissionId: selectedIdNum,
  details: detailsQuery,
  comments: commentsQuery,
  onAddComment,
  isAddingComment,
  expandedGroups,
  setExpandedGroups,
  expandedAnalyzerIds,
  setExpandedAnalyzerIds,
}: SubmissionDrawerProps) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const analyzerReports = React.useMemo(
    () => detailsQuery.data?.analyzer_reports ?? [],
    [detailsQuery.data]
  );
  const ci = detailsQuery.data?.case_infos;
  // Only claim "nothing ran" for a finished case; NEW/IN_PROGRESS also have 0 tests while analyzers run.
  const noAnalyzersRan =
    !!selectedRow && String(selectedRow.status).toUpperCase() === "DONE" && selectedRow.tests_done === 0 && analyzerReports.length === 0;
  const urlArtifacts = detailsQuery.data?.url_artifacts ?? [];
  const reportGroups = React.useMemo(
    () => groupReportsByArtifact(analyzerReports),
    [analyzerReports]
  );

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
            }),
          },
        }}
      >
        {!selectedRow ? (
          <Box sx={{ p: 2 }}>
            <Alert severity="info">Select a row.</Alert>
          </Box>
        ) : (
          <Stack sx={{ height: "100%" }}>
            <SheetHeader>
              <Stack direction="row" spacing={2} sx={{ alignItems: "flex-start", justifyContent: "space-between" }} >
                <Box>
                  <Typography variant="overline" color="text.secondary">Submission</Typography>
                  <Stack direction="row" spacing={1} sx={{ mt: 0.25, alignItems: "center" }}>
                    <Typography variant="h5" sx={{ fontWeight: 950, lineHeight: 1.1 }} >
                      #{selectedRow.id}
                    </Typography>
                    <CopyIconButton text={String(selectedRow.id)} title="Copy ID" />
                  </Stack>
                </Box>
                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                  <Button
                    variant="outlined"
                    startIcon={<DescriptionOutlined />}
                    onClick={() =>
                      window.open(`/api/cases/${selectedRow.id}/report/`, "_blank")
                    }
                    sx={{ textTransform: "none", borderRadius: 2, fontWeight: 800 }}
                  >
                    Full report
                  </Button>
                  <Button onClick={onClose}
                    sx={{ textTransform: "none", borderRadius: 2, alignSelf: "flex-start" }}>
                    Close
                  </Button>
                </Stack>
              </Stack>

              <Stack direction="row" spacing={1} sx={{ mt: 1.5, flexWrap: "wrap" }}>
                <ResultChip result={selectedRow.result} minWidth={BADGE_W} />
                <StatusChip status={selectedRow.status} minWidth={96} />
                <Chip size="small" label={selectedRow.type} variant="outlined"
                  sx={{ fontWeight: 900, justifyContent: "center" }} />
                <Chip size="small" label={`${selectedRow.tests_done} tests`} variant="outlined"
                  sx={{ fontWeight: 900 }} />
              </Stack>
            </SheetHeader>

            <Box sx={{ flex: 1, overflowY: "auto" }}>

              {/* ── Summary strip ──────────────────────────────────────────────── */}
              <Box
                sx={{
                  px: 2.25, py: 1.5,
                  display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 1,
                  borderBottom: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.55)}`,
                  background: isDark ? alpha("#fff", 0.015) : alpha(theme.palette.grey[50], 0.6),
                }}
              >
                {[
                  { label: "Tests run", value: selectedRow.tests_done ?? "—" },
                  { label: "Submitted", value: fmtDate(selectedRow.created_at) },
                ].map(({ label, value }) => (
                  <Box key={label}>
                    <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mb: 0.2 }}>
                      {label}
                    </Typography>
                    <Typography sx={{ fontWeight: 700, fontSize: 13 }}>{String(value)}</Typography>
                  </Box>
                ))}
              </Box>

              <Stack spacing={0} divider={<Divider sx={{ opacity: isDark ? 0.12 : 0.35 }} />}>

                {/* ── Verdict (read-only) ───────────────────────────────────────── */}
                {ci ? (
                  <Box sx={{ px: 2.25, py: 2 }}>
                    <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mb: 0.75 }}>
                      Verdict
                    </Typography>
                    <Stack spacing={1.25}>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
                        <ResultChip result={String(ci.classification ?? "UNKNOWN")} minWidth={BADGE_W} />
                        <Chip size="small" label={`Score ${ci.score ?? "—"}/10`} variant="outlined" />
                        <Chip size="small" label={`Confidence ${ci.confidence ?? "—"}%`} variant="outlined" />
                      </Stack>
                      {[ci.classification_ai, ci.score_ai, ci.confidence_ai, ci.category_ai].some((v) => v != null && v !== "") ? (
                        <Box>
                          <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mb: 0.5 }}>
                            AI classifier
                          </Typography>
                          <Stack direction="row" spacing={0.75} sx={{ flexWrap: "wrap", rowGap: 0.75 }}>
                            {[
                              ci.classification_ai ? String(ci.classification_ai) : null,
                              `score ${ci.score_ai ?? "—"}`,
                              `conf ${ci.confidence_ai ?? "—"}%`,
                              ci.category_ai ? `cat ${ci.category_ai}` : null,
                            ].filter(Boolean).map((label) => (
                              <Chip key={label as string} size="small" label={label as string} variant="outlined"
                                sx={{ fontSize: theme.typography.caption.fontSize }} />
                            ))}
                          </Stack>
                        </Box>
                      ) : null}
                    </Stack>
                  </Box>
                ) : null}

                {noAnalyzersRan ? (
                  <Box sx={{ px: 2.25, py: 1.5 }}>
                    <Typography variant="body2" color="text.secondary">
                      No analyzers ran for this submission.
                    </Typography>
                  </Box>
                ) : null}

                {/* ── Artifact ──────────────────────────────────────────────────── */}
                <Box sx={{ px: 2.25, py: 2 }}>
                  <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                    Artifact
                  </Typography>
                  <Typography sx={{ wordBreak: "break-all", fontWeight: 700, fontSize: 13.5 }}>
                    {selectedRow.artifact || "—"}
                  </Typography>
                </Box>

                {/* ── Your comments ───────────────────────────────────────────── */}
                <CommentThread
                  title="Your comments"
                  comments={commentsQuery.data ?? []}
                  isLoading={commentsQuery.isLoading}
                  onAdd={onAddComment}
                  isAdding={isAddingComment}
                />

                {/* ── Email preview (only when the case is a mail) ─────────────── */}
                {selectedRow.mail_preview_url ? (
                  <Box sx={{ px: 2.25, py: 2 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                      Email preview
                    </Typography>
                    <MailPreview
                      url={selectedRow.mail_preview_url}
                      variant="full"
                      alt={`Preview of email for case ${selectedRow.id}`}
                    />
                  </Box>
                ) : null}

                {/* Analysis results: grouped by artifact (omitted when nothing ran and nothing reported) */}
                {noAnalyzersRan && analyzerReports.length === 0 && !detailsQuery.isLoading && !detailsQuery.isError ? null : (
                <Box sx={{ px: 2.25, pt: 2, pb: 1 }}>
                  <Stack direction="row" sx={{ mb: 1.25, alignItems: "center", justifyContent: "space-between" }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled" }}>
                      Analysis · {analyzerReports.length} report{analyzerReports.length !== 1 ? "s" : ""}
                    </Typography>
                    {reportGroups.length > 0 ? (
                      <Stack direction="row" spacing={0.5}>
                        <Button size="small"
                          onClick={() => setExpandedGroups(Object.fromEntries(reportGroups.map((g) => [g.key, true])))}
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
                              <Typography variant="body2"
                                sx={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: 700 }}
                                title={group.value}>
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
                                    <AnalyzerReportCard
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

                {/* URL artifacts: grouped by domain */}
                {urlArtifacts.length > 0 && (
                  <Box sx={{ px: 2.25, pt: 2, pb: 1 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 1.25 }}>
                      URLs · {urlArtifacts.length} artifact{urlArtifacts.length !== 1 ? "s" : ""}
                    </Typography>
                    <UrlGroupList submissionId={selectedIdNum} urls={urlArtifacts} />
                  </Box>
                )}
              </Stack>
            </Box>
          </Stack>
        )}
      </Drawer>
  );
}
