import * as React from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Drawer,
  Stack,
  Tab,
  Tabs,
  Typography,
  useMediaQuery,
} from "@mui/material";
import { ChevronLeft, ChevronRight } from "@mui/icons-material";
import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { useTheme } from "@mui/material/styles";
import { monoStack } from "@/styles/themes";

import type { InvestigationDetails, InvestigationListResponse } from "@/features/investigation/api";
import type { CaseComment } from "@/features/comments/api";
import { ResultChip, useResultHex } from "@/shared/components/ResultChip";
import { SheetAccent, SheetHeader, StepButton, headerTint } from "@/shared/components/SheetHeader";
import { CopyIconButton } from "@/shared/components/CopyIconButton";
import { flatten } from "@/shared/lib/contrast";
import { humanStatus } from "@/shared/lib/scoreUtils";
import { InvestigationAnalysisTab } from "@/features/investigation/components/InvestigationAnalysisTab";
import { MoreActions, PrimaryActions } from "@/features/investigation/components/InvestigationActions";
import { InvestigationOverview, type EditPayload } from "@/features/investigation/components/InvestigationOverview";
import { CommentThread } from "@/features/comments/CommentThread";
import { tabLabelColors } from "@/features/submissions/tabColors";
import {
  fmtDate,
  groupReportsByArtifact,
  pickClassification,
  pickConfidence,
  pickScore,
} from "@/features/investigation/utils";

const BADGE_W = 132;

const TABS = ["overview", "analysis", "discussion", "raw"] as const;
type TabKey = (typeof TABS)[number];

function Panel({ value, tab, children }: { value: TabKey; tab: TabKey; children: React.ReactNode }) {
  return (
    <div role="tabpanel" hidden={tab !== value} id={`investigation-tabpanel-${value}`} aria-labelledby={`investigation-tab-${value}`}>
      {tab === value ? children : null}
    </div>
  );
}

export type InvestigationDrawerProps = {
  open: boolean;
  onClose: () => void;
  /** List row if present in the current page, else the loaded details. */
  drawerRow: InvestigationListResponse["results"][number] | InvestigationDetails | undefined;
  /** The selected case: the target of edit, push and redo. */
  caseId: number;
  detailsQuery: UseQueryResult<InvestigationDetails>;
  editMutation: UseMutationResult<unknown, unknown, EditPayload>;
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
  /** IDs of the current page's rows, in order: previous/next step through them. */
  siblings?: number[];
  onNavigate?: (id: number) => void;
};

export function InvestigationDrawer({
  open, onClose, drawerRow, caseId, detailsQuery, editMutation, editMode, setEditMode,
  editScore, setEditScore, editConfidence, setEditConfidence, editClassification, setEditClassification,
  onRedo, commentsQuery, addCommentMutation,
  siblings = [], onNavigate,
}: InvestigationDrawerProps) {
  const theme = useTheme();
  const isPhone = useMediaQuery(theme.breakpoints.down("sm"));

  const detailsReady = !!detailsQuery.data && !detailsQuery.isLoading && !detailsQuery.isError;
  const analyzerReports = React.useMemo(
    () => detailsQuery.data?.analyzer_reports ?? [],
    [detailsQuery.data]
  );
  const observableGroup = detailsQuery.data?.observable_group;
  const reportGroups = React.useMemo(
    () => groupReportsByArtifact(analyzerReports),
    [analyzerReports]
  );
  const verdictHex = useResultHex(drawerRow?.result ?? "UNKNOWN");
  // This endpoint (serializers/investigations.py get_case_type) types FILE/MAIL/URL/IP/HASH from one primary observable,
  // observable-group cases "IOC", and a case with no observable "UNKNOWN" (the Submissions endpoint uses UNKNOWN for IOC groups).
  const caseType = String(drawerRow?.type ?? "").toUpperCase();
  const multi = caseType === "IOC" || caseType === "UNKNOWN";
  // Only claim "nothing ran" for a finished case; NEW/IN_PROGRESS also have 0 tests while analyzers run.
  const noAnalyzersRan =
    !!drawerRow && detailsReady && String(drawerRow.status).toUpperCase() === "DONE" && drawerRow.tests_done === 0 && analyzerReports.length === 0;
  const status = String(detailsQuery.data?.status ?? "");
  const terminal = status === "DONE" || status === "CHALLENGED";

  // A case not on the current page (deep link, filtered out) has no neighbours.
  const at = drawerRow ? siblings.indexOf(drawerRow.id) : -1;
  const prevId = at < 0 ? null : siblings[at - 1] ?? null;
  const nextId = at < 0 ? null : siblings[at + 1] ?? null;
  const navigate = onNavigate ? (id: number | string) => onNavigate(Number(id)) : undefined;

  // The tab belongs to the case it was picked on: another case opens on Overview.
  const [tabState, setTabState] = React.useState<{ id?: number; tab: TabKey }>({ tab: "overview" });
  const tab: TabKey = tabState.id === drawerRow?.id ? tabState.tab : "overview";
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
  }, [drawerRow?.id, prevId, nextId]);

  const tabLabel = (t: TabKey) =>
    t === "overview" ? "Overview"
    : t === "analysis" ? (detailsQuery.data ? `Analysis (${analyzerReports.length})` : "Analysis")
    : t === "discussion" ? (commentsQuery.data ? `Discussion (${commentsQuery.data.length})` : "Discussion")
    : "Raw";

  // Edit verdict: back to Overview, seed the form from the saved values (as the old Edit button did); the Score field autofocuses.
  const startEdit = () => {
    if (!detailsReady || !drawerRow) return;
    setTabState({ id: drawerRow.id, tab: "overview" });
    // Already editing: the form stays as typed; just bring the user back to it.
    if (editMode) { requestAnimationFrame(() => document.getElementById("investigation-edit-score")?.focus()); return; }
    const score = pickScore(detailsQuery.data);
    const confidence = pickConfidence(detailsQuery.data);
    const classification = pickClassification(detailsQuery.data);
    setEditScore(score == null ? "" : String(score));
    setEditConfidence(confidence == null ? "" : String(confidence));
    setEditClassification(String(classification).toUpperCase());
    editMutation.reset();
    setEditMode(true);
  };

  return (
      <Drawer
        anchor="right"
        open={open}
        onClose={onClose}
        slotProps={{
          paper: {
            "aria-labelledby": "investigation-drawer-title",
            sx: (theme) => ({
              width: { xs: "100%", sm: 620 },
              p: 0,
              borderLeft: `1px solid ${theme.palette.divider}`,
              // Solid paper, as in the Submissions sheet: a translucent gradient lets the list show through on light themes.
              background: theme.palette.background.paper,
              color: theme.palette.text.primary,
              overflow: "hidden",
            }),
          },
        }}
      >
        {!drawerRow ? (
          <Box sx={{ p: 2 }}><Alert severity="info">Select a row.</Alert></Box>
        ) : (
          <Stack sx={{ height: "100%" }}>
            <SheetHeader sx={{ pb: 0 }}>
              <SheetAccent hex={verdictHex} />
              {/* Row 1: identity on the left; More and Close are utilities and always fit beside it, even at 390px. */}
              <Stack direction="row" spacing={1} sx={{ alignItems: "center", justifyContent: "space-between" }}>
                <Stack direction="row" spacing={0.25} sx={{ alignItems: "center", minWidth: 0 }}>
                  <Typography id="investigation-drawer-title" variant="h2" component="h2" sx={{ mr: 0.25 }}>#{drawerRow.id}</Typography>
                  <CopyIconButton text={String(drawerRow.id)} title="Copy ID" />
                  <StepButton label="Previous case" target={prevId} onNavigate={navigate} btnRef={prevBtn} onStep={() => { stepped.current = "prev"; }}><ChevronLeft fontSize="small" /></StepButton>
                  <StepButton label="Next case" target={nextId} onNavigate={navigate} btnRef={nextBtn} onStep={() => { stepped.current = "next"; }}><ChevronRight fontSize="small" /></StepButton>
                </Stack>
                <Stack direction="row" spacing={0.5} sx={{ alignItems: "center", flexShrink: 0 }}>
                  <MoreActions id={caseId} detailsReady={detailsReady} terminal={terminal} onRedo={onRedo} />
                  <Button onClick={onClose}>Close</Button>
                </Stack>
              </Stack>

              {/* Row 2: Edit verdict sits beside the verdict it changes. Phones: when the buttons drop below the chip they start at the content edge. */}
              <Stack direction="row" useFlexGap sx={{ mt: 1.25, alignItems: "center", flexWrap: "wrap", gap: 1 }}>
                <ResultChip result={drawerRow.result} minWidth={BADGE_W} size="medium" behind={[flatten(headerTint(theme), theme.palette.background.paper)]} />
                <Stack direction="row" spacing={1} sx={{ alignItems: "center", ml: isPhone ? 0 : "auto" }}>
                  <PrimaryActions id={caseId} detailsReady={detailsReady} onEdit={startEdit} compact={isPhone} />
                </Stack>
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                {[
                  humanStatus(drawerRow.status),
                  // Analysts read the raw type ("IOC", "MAIL"); only the typeless UNKNOWN gets a word.
                  caseType === "UNKNOWN" ? "Indicators" : drawerRow.type,
                  drawerRow.tests_done == null ? null : `${drawerRow.tests_done} test${drawerRow.tests_done === 1 ? "" : "s"}`,
                  fmtDate(drawerRow.created_at),
                ].filter(Boolean).join(" · ")}
              </Typography>

              <Tabs
                value={tab}
                onChange={(_, v: TabKey) => setTabState({ id: drawerRow.id, tab: v })}
                variant="scrollable"
                scrollButtons="auto"
                allowScrollButtonsMobile
                aria-label="Investigation sections"
                // The header's bottom border is the tab rule; some themes add their own, which would double it.
                sx={(theme) => {
                  const c = tabLabelColors(theme);
                  return {
                    mt: 1, minHeight: 40, borderBottom: 0,
                    // Phones: no 90px tab minimum and narrower padding, so all four tabs fit without a scroll arrow in most themes.
                    "& .MuiTab-root": { minHeight: 40, minWidth: { xs: 0, sm: 90 }, px: { xs: 1, sm: 1.5 }, color: c.unselected, textShadow: "none" },
                    "& .MuiTab-root.Mui-selected": { color: c.selected },
                  };
                }}
              >
                {TABS.map((t) => (
                  <Tab key={t} value={t} id={`investigation-tab-${t}`} aria-controls={`investigation-tabpanel-${t}`} label={tabLabel(t)} />
                ))}
              </Tabs>
            </SheetHeader>

            <Box sx={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
            <Skeleton
              name="investigation-drawer-details"
              loading={detailsQuery.isFetching && detailsQuery.isPlaceholderData}
              animate="shimmer"
            >
            <Box>
              <Panel value="overview" tab={tab}>
                <InvestigationOverview
                  row={drawerRow}
                  caseId={caseId}
                  detailsQuery={detailsQuery}
                  multi={multi}
                  // The group's own list is the real count; report targets are the fallback for cases without one.
                  observableCount={detailsQuery.isLoading ? 0 : observableGroup?.observables.length ?? reportGroups.length}
                  noAnalyzersRan={noAnalyzersRan}
                  verdictHex={verdictHex}
                  editMutation={editMutation}
                  editMode={editMode}
                  onCancelEdit={() => { setEditMode(false); editMutation.reset(); }}
                  editScore={editScore}
                  setEditScore={setEditScore}
                  editConfidence={editConfidence}
                  setEditConfidence={setEditConfidence}
                  editClassification={editClassification}
                  setEditClassification={setEditClassification}
                />
              </Panel>

              <Panel value="analysis" tab={tab}>
                {/* Keyed by case: another case starts from the default expansion (the drawer unmounts on close). */}
                <InvestigationAnalysisTab
                  key={drawerRow.id}
                  reports={analyzerReports}
                  observableGroup={observableGroup}
                  isLoading={detailsQuery.isLoading}
                  isError={detailsQuery.isError}
                />
              </Panel>

              <Panel value="discussion" tab={tab}>
                <CommentThread
                  title="Comments"
                  comments={commentsQuery.data ?? []}
                  isLoading={commentsQuery.isLoading}
                  onAdd={(body) => addCommentMutation.mutateAsync(body)}
                  isAdding={addCommentMutation.isPending}
                />
              </Panel>

              <Panel value="raw" tab={tab}>
                {/* The tab isolates the payload, so no accordion and no inner scroll box: the panel scrolls. */}
                <Box component="section" sx={{ px: 2.25, pt: 2, pb: 2 }}>
                  <Typography variant="subtitle2" component="h3" color="text.secondary" sx={{ mb: 1 }}>Raw API payload</Typography>
                  {detailsQuery.isLoading ? <CircularProgress size={16} /> : detailsQuery.isError ? (
                    <Alert severity="warning">Could not load.</Alert>
                  ) : (
                    <Box component="pre" sx={(t) => ({
                      m: 0, p: 1.25, borderRadius: 2, border: 1, borderColor: "divider",
                      bgcolor: "action.hover", color: "text.primary",
                      // Wrapped, not side-scrolled: a long payload would otherwise hide its scrollbar at the bottom.
                      whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontFamily: monoStack, fontSize: t.typography.caption.fontSize, lineHeight: 1.45,
                    })}>
                      {JSON.stringify(detailsQuery.data?.raw ?? detailsQuery.data, null, 2)}
                    </Box>
                  )}
                </Box>
              </Panel>
            </Box>
            </Skeleton>
            </Box>
          </Stack>
        )}
      </Drawer>
  );
}
