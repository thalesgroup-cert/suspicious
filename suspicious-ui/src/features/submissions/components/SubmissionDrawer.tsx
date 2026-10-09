import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Drawer,
  Stack,
  Tab,
  Tabs,
  Typography,
} from "@mui/material";
import { DescriptionOutlined } from "@mui/icons-material";
import type { UseQueryResult } from "@tanstack/react-query";
import type { SubmissionDetails, SubmissionRow } from "@/features/submissions/api";
import type { CaseComment } from "@/features/comments/api";
import { ResultChip, useResultHex } from "@/shared/components/ResultChip";
import { SheetHeader } from "@/shared/components/SheetHeader";
import { CopyIconButton } from "@/shared/components/CopyIconButton";
import { AnalysisTab } from "@/features/submissions/components/AnalysisTab";
import { OverviewTab } from "@/features/submissions/components/OverviewTab";
import { CommentThread } from "@/features/comments/CommentThread";
import { fmtDate, groupReportsByArtifact } from "@/features/submissions/utils";

const BADGE_W = 132;

const TABS = ["overview", "analysis", "comments"] as const;
type TabKey = (typeof TABS)[number];

// Case types, not report target kinds: kindLabel maps targets (there MAIL means "Email address").
const TYPE_LABELS: Record<string, string> = { FILE: "File", MAIL: "Email", URL: "URL", IP: "IP", HASH: "Hash" };

/** "IN_PROGRESS" -> "In progress". */
const humanStatus = (s: string) => {
  const t = String(s ?? "").replace(/_/g, " ").toLowerCase();
  return t ? t[0].toUpperCase() + t.slice(1) : "Unknown";
};

function Panel({ value, tab, children }: { value: TabKey; tab: TabKey; children: React.ReactNode }) {
  return (
    <div role="tabpanel" hidden={tab !== value} id={`submission-tabpanel-${value}`} aria-labelledby={`submission-tab-${value}`}>
      {tab === value ? children : null}
    </div>
  );
}

export type SubmissionDrawerProps = {
  open: boolean;
  onClose: () => void;
  row: SubmissionRow | undefined;
  submissionId: number;
  details: UseQueryResult<SubmissionDetails>;
  comments: UseQueryResult<CaseComment[]>;
  onAddComment: (body: string) => Promise<unknown>;
  isAddingComment: boolean;
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
}: SubmissionDrawerProps) {
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
  const verdictHex = useResultHex(selectedRow?.result ?? "UNKNOWN");
  const type = String(selectedRow?.type ?? "").toUpperCase();
  // The backend types FILE/MAIL/URL/IP/HASH from one primary observable; only IOC-group cases come back UNKNOWN.
  const multi = type === "UNKNOWN";
  const typeLabel = multi ? "Indicators" : TYPE_LABELS[type] ?? type;

  // The tab belongs to the submission it was picked on: another submission opens on Overview.
  const [tabState, setTabState] = React.useState<{ id?: number; tab: TabKey }>({ tab: "overview" });
  const tab: TabKey = tabState.id === selectedRow?.id ? tabState.tab : "overview";
  const tabLabel = (t: TabKey) =>
    t === "overview" ? "Overview"
    : t === "analysis" ? (detailsQuery.data ? `Analysis (${analyzerReports.length})` : "Analysis")
    : commentsQuery.data ? `Comments (${commentsQuery.data.length})` : "Comments";

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
              // Solid paper: the old translucent gradient let the list behind show through on light themes.
              background: theme.palette.background.paper,
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
            <SheetHeader sx={{ pb: 0 }}>
              {/* Verdict accent: the one colour cue for the case, in the user's own result colour. */}
              <Box aria-hidden data-testid="verdict-accent" sx={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, bgcolor: verdictHex ?? "divider" }} />
              <Stack direction="row" spacing={1} sx={{ alignItems: "center", justifyContent: "space-between" }}>
                <Stack direction="row" spacing={0.5} sx={{ alignItems: "center", minWidth: 0 }}>
                  <Typography variant="h2" component="h2">#{selectedRow.id}</Typography>
                  <CopyIconButton text={String(selectedRow.id)} title="Copy ID" />
                </Stack>
                <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexShrink: 0 }}>
                  <Button
                    variant="outlined"
                    startIcon={<DescriptionOutlined />}
                    onClick={() => window.open(`/api/cases/${selectedRow.id}/report/`, "_blank")}
                  >
                    Full report
                  </Button>
                  <Button onClick={onClose}>Close</Button>
                </Stack>
              </Stack>

              <Box sx={{ mt: 1.25 }}>
                <ResultChip result={selectedRow.result} minWidth={BADGE_W} size="medium" />
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                {[
                  humanStatus(selectedRow.status),
                  typeLabel,
                  selectedRow.tests_done == null ? null : `${selectedRow.tests_done} test${selectedRow.tests_done === 1 ? "" : "s"}`,
                  fmtDate(selectedRow.created_at),
                ].filter(Boolean).join(" · ")}
              </Typography>

              <Tabs
                value={tab}
                onChange={(_, v: TabKey) => setTabState({ id: selectedRow.id, tab: v })}
                variant="scrollable"
                scrollButtons="auto"
                allowScrollButtonsMobile
                aria-label="Submission sections"
                // The header's bottom border is the tab rule; some themes add their own, which would double it.
                sx={{ mt: 1, minHeight: 40, borderBottom: 0, "& .MuiTab-root": { minHeight: 40, px: 1.5 } }}
              >
                {TABS.map((t) => (
                  <Tab key={t} value={t} id={`submission-tab-${t}`} aria-controls={`submission-tabpanel-${t}`}
                    label={tabLabel(t)} />
                ))}
              </Tabs>
            </SheetHeader>

            <Box sx={{ flex: 1, overflowY: "auto" }}>
              <Panel value="overview" tab={tab}>
                <OverviewTab
                  row={selectedRow}
                  reports={analyzerReports}
                  ci={ci}
                  multi={multi}
                  observableCount={detailsQuery.isLoading ? 0 : reportGroups.length}
                  noAnalyzersRan={noAnalyzersRan}
                  verdictHex={verdictHex}
                  onSeeAll={() => setTabState({ id: selectedRow.id, tab: "analysis" })}
                />
              </Panel>

              <Panel value="analysis" tab={tab}>
                <AnalysisTab
                  key={selectedRow.id}
                  submissionId={selectedIdNum}
                  reports={analyzerReports}
                  urlArtifacts={urlArtifacts}
                  isLoading={detailsQuery.isLoading}
                  isError={detailsQuery.isError}
                  hideReports={noAnalyzersRan && !detailsQuery.isLoading && !detailsQuery.isError}
                />
              </Panel>

              <Panel value="comments" tab={tab}>
                <CommentThread
                  title="Your comments"
                  comments={commentsQuery.data ?? []}
                  isLoading={commentsQuery.isLoading}
                  onAdd={onAddComment}
                  isAdding={isAddingComment}
                />
              </Panel>
            </Box>
          </Stack>
        )}
      </Drawer>
  );
}
