import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Drawer,
  IconButton,
  Stack,
  Tab,
  Tabs,
  Tooltip,
  Typography,
  useMediaQuery,
  useTheme,
} from "@mui/material";
import { ChevronLeft, ChevronRight, DescriptionOutlined } from "@mui/icons-material";
import { tabLabelColors } from "@/features/submissions/tabColors";
import type { UseQueryResult } from "@tanstack/react-query";
import type { SubmissionDetails, SubmissionRow } from "@/features/submissions/api";
import type { CaseComment } from "@/features/comments/api";
import { ResultChip, useResultHex } from "@/shared/components/ResultChip";
import { SheetHeader } from "@/shared/components/SheetHeader";
import { CopyIconButton } from "@/shared/components/CopyIconButton";
import { AnalysisTab } from "@/features/submissions/components/AnalysisTab";
import { DrawerActions } from "@/features/submissions/components/DrawerActions";
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

function StepButton({ label, target, onNavigate, onStep, btnRef, children }: {
  label: string; onStep: () => void; btnRef: React.Ref<HTMLButtonElement>; target: number | string | null; onNavigate?: (id: number | string) => void; children: React.ReactNode;
}) {
  return (
    <Tooltip title={label}>
      {/* span: a disabled button can't host the tooltip's listeners */}
      <span>
        <IconButton ref={btnRef} size="small" aria-label={label} disabled={target == null} onClick={() => { if (target == null) return; onStep(); onNavigate?.(target); }}>
          {children}
        </IconButton>
      </span>
    </Tooltip>
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
  elevated?: boolean;
  /** Set only when the row can be challenged. */
  onChallenge?: () => void;
  /** Adjacent rows of the current page; null at the ends. */
  prevId?: number | string | null;
  nextId?: number | string | null;
  onNavigate?: (id: number | string) => void;
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
  elevated,
  onChallenge,
  prevId = null,
  nextId = null,
  onNavigate,
}: SubmissionDrawerProps) {
  const isPhone = useMediaQuery(useTheme().breakpoints.down("sm"));
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
  // After Previous/Next the pressed button may become disabled (end of the page) and drop focus: hand it to the other one.
  const stepped = React.useRef<"prev" | "next" | null>(null);
  const prevBtn = React.useRef<HTMLButtonElement>(null);
  const nextBtn = React.useRef<HTMLButtonElement>(null);
  React.useEffect(() => {
    const s = stepped.current;
    if (!s) return;
    stepped.current = null;
    if (s === "prev" && prevId == null) nextBtn.current?.focus();
    if (s === "next" && nextId == null) prevBtn.current?.focus();
  }, [selectedRow?.id, prevId, nextId]);
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
            // MUI's temporary Drawer already sets role="dialog", aria-modal and focuses the paper; only the name is ours.
            "aria-labelledby": "submission-drawer-title",
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
                  <Typography id="submission-drawer-title" variant="h2" component="h2">#{selectedRow.id}</Typography>
                  <CopyIconButton text={String(selectedRow.id)} title="Copy ID" />
                  <StepButton label="Previous submission" target={prevId} onNavigate={onNavigate} btnRef={prevBtn} onStep={() => { stepped.current = "prev"; }}><ChevronLeft fontSize="small" /></StepButton>
                  <StepButton label="Next submission" target={nextId} onNavigate={onNavigate} btnRef={nextBtn} onStep={() => { stepped.current = "next"; }}><ChevronRight fontSize="small" /></StepButton>
                </Stack>
                <Stack direction="row" spacing={isPhone ? 0.5 : 1} sx={{ alignItems: "center", flexShrink: 0 }}>
                  {isPhone ? null : (
                    <Button
                      variant="outlined"
                      startIcon={<DescriptionOutlined />}
                      onClick={() => window.open(`/api/cases/${selectedRow.id}/report/`, "_blank")}
                    >
                      Full report
                    </Button>
                  )}
                  <DrawerActions id={selectedRow.id} elevated={elevated} onChallenge={onChallenge} includeFullReport={isPhone} />
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
                sx={(theme) => {
                  const c = tabLabelColors(theme);
                  return {
                    mt: 1, minHeight: 40, borderBottom: 0,
                    "& .MuiTab-root": { minHeight: 40, px: 1.5, color: c.unselected, textShadow: "none" },
                    "& .MuiTab-root.Mui-selected": { color: c.selected },
                  };
                }}
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
                  onSeeAll={() => {
                    setTabState({ id: selectedRow.id, tab: "analysis" });
                    // The button that was focused unmounts with the Overview panel; keep focus in the tablist.
                    requestAnimationFrame(() => document.getElementById("submission-tab-analysis")?.focus());
                  }}
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
