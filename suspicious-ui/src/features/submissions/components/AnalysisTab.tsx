import * as React from "react";
import { Alert, Box, Chip, CircularProgress, Collapse, IconButton, Stack, Tooltip, Typography } from "@mui/material";
import { ExpandMoreOutlined, UnfoldLess, UnfoldMore } from "@mui/icons-material";
import type { SubmissionAnalyzerReport, UrlArtifact } from "@/features/submissions/api";
import { AnalyzerReportCard } from "@/features/submissions/components/AnalyzerReportCard";
import { UrlGroupList } from "@/features/submissions/components/UrlGroupList";
import {
  getRiskTone,
  groupReportsByArtifact,
  kindLabel,
  normalizeScore,
  reportSucceeded,
  riskPalette,
  unfinishedLabel,
} from "@/features/submissions/utils";
import { monoStack } from "@/styles/themes";

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

function Heading({ title, count }: { title: string; count: string }) {
  return (
    <Stack direction="row" spacing={1} sx={{ alignItems: "baseline", minWidth: 0 }}>
      <Typography variant="subtitle2" component="h3" color="text.secondary">{title}</Typography>
      <Typography variant="caption" color="text.secondary">{count}</Typography>
    </Stack>
  );
}

export type AnalysisTabProps = {
  submissionId: number;
  reports: SubmissionAnalyzerReport[];
  urlArtifacts: UrlArtifact[];
  isLoading: boolean;
  isError: boolean;
  /** Nothing ran and nothing reported: the report block is omitted (Task-6 rule). */
  hideReports: boolean;
};

/** Expansion state lives here: the drawer keys this by submission and unmounts it on close, which resets it. */
export function AnalysisTab({ submissionId, reports, urlArtifacts, isLoading, isError, hideReports }: AnalysisTabProps) {
  // Worst risk first: the reporter lands on the dangerous finding. A run with no result has no risk (-1).
  const groups = React.useMemo(
    () =>
      groupReportsByArtifact(reports)
        .map((g) => {
          const scored = g.reports.filter(reportSucceeded);
          const worst = scored.reduce<SubmissionAnalyzerReport | null>(
            (w, r) => (!w || normalizeScore(r.score) > normalizeScore(w.score) ? r : w), null);
          return {
            ...g,
            // Riskiest result first inside the group too; runs with no result go last.
            reports: [...scored].sort((a, b) => normalizeScore(b.score) - normalizeScore(a.score))
              .concat(g.reports.filter((r) => !reportSucceeded(r))),
            label: `${kindLabel(g.kind)} ${g.value}`,
            worst,
            rank: worst ? normalizeScore(worst.score) : -1,
            failed: g.reports.filter((r) => !reportSucceeded(r) && unfinishedLabel(r.status) === "Failed").length,
          };
        })
        .sort((a, b) => b.rank - a.rank || a.label.localeCompare(b.label)),
    [reports]
  );
  const [openGroups, setOpenGroups] = React.useState<Record<string, boolean>>({});
  const [openRows, setOpenRows] = React.useState<Record<number, boolean>>({});
  const isOpen = (key: string) => openGroups[key] ?? key === groups[0]?.key;
  const setAll = (open: boolean) => setOpenGroups(Object.fromEntries(groups.map((g) => [g.key, open])));

  return (
    <>
      {hideReports ? null : (
        <Box component="section" sx={{ px: 2.25, pt: 2, pb: 1 }}>
          <Stack direction="row" sx={{ mb: 1, alignItems: "center", justifyContent: "space-between", minHeight: 40 }}>
            <Heading title="Analysis" count={plural(reports.length, "report")} />
            {groups.length > 0 ? (
              <Stack direction="row">
                <Tooltip title="Expand all groups">
                  <IconButton aria-label="Expand all groups" onClick={() => setAll(true)}><UnfoldMore /></IconButton>
                </Tooltip>
                <Tooltip title="Collapse all groups">
                  <IconButton aria-label="Collapse all groups" onClick={() => setAll(false)}><UnfoldLess /></IconButton>
                </Tooltip>
              </Stack>
            ) : null}
          </Stack>

          {isLoading ? (
            <Stack direction="row" spacing={1} sx={{ py: 2, alignItems: "center" }}>
              <CircularProgress size={16} />
              <Typography variant="caption" color="text.secondary">Loading analysis…</Typography>
            </Stack>
          ) : isError ? (
            <Alert severity="warning" sx={{ mb: 1.5 }}>Could not load analysis details.</Alert>
          ) : !groups.length ? (
            <Alert severity="info" sx={{ mb: 1.5 }}>No analysis reports yet.</Alert>
          ) : (
            <Stack spacing={1} sx={{ mb: 1.5 }}>
              {groups.map((group) => {
                const open = isOpen(group.key);
                const toggle = () => setOpenGroups((prev) => ({ ...prev, [group.key]: !open }));
                const worstLabel = group.worst ? getRiskTone(group.worst.score).label : "No result";
                return (
                  <Box key={group.key} component="section" aria-label={group.label}
                    sx={{ borderRadius: 2, border: 1, borderColor: "divider", overflow: "hidden" }}>
                    <Box
                      role="button" tabIndex={0} aria-expanded={open}
                      onClick={toggle}
                      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } }}
                      sx={{
                        px: 1.5, py: 1, minHeight: 44,
                        display: "flex", alignItems: "center", gap: 1,
                        cursor: "pointer", userSelect: "none",
                        bgcolor: "action.hover",
                        "&:hover": { bgcolor: "action.selected" },
                      }}
                    >
                      {/* Worst-risk dot: the group's answer before it is opened; the label carries it for screen readers. */}
                      <Box role="img" aria-label={`Worst result: ${worstLabel}`} title={worstLabel}
                        sx={{
                          width: 10, height: 10, borderRadius: "50%", flexShrink: 0,
                          ...(group.worst
                            ? { bgcolor: `${riskPalette(group.worst.score)}.main` }
                            : { border: 1.5, borderStyle: "dashed", borderColor: "text.disabled" }),
                        }} />
                      <Chip size="small" variant="outlined" label={kindLabel(group.kind)} sx={{ flexShrink: 0 }} />
                      <Typography variant="body2" noWrap title={group.value}
                        sx={{ flex: 1, minWidth: 0, fontFamily: monoStack, fontWeight: 600 }}>
                        {group.value}
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ flexShrink: 0, textAlign: "right" }}>
                        {plural(group.reports.length, "analyzer")}
                        {group.failed ? <Box component="span" sx={{ display: "block" }}>{group.failed} failed</Box> : null}
                      </Typography>
                      <ExpandMoreOutlined aria-hidden sx={{
                        flexShrink: 0, color: "text.secondary",
                        transform: open ? "rotate(180deg)" : "rotate(0deg)", transition: "transform .2s ease",
                      }} />
                    </Box>

                    <Collapse in={open} unmountOnExit>
                      <Stack spacing={0.75} sx={{ p: 1 }}>
                        {group.reports.map((report) => (
                          <AnalyzerReportCard
                            key={report.id}
                            report={report}
                            expanded={!!openRows[report.id]}
                            onToggle={() => setOpenRows((prev) => ({ ...prev, [report.id]: !prev[report.id] }))}
                          />
                        ))}
                      </Stack>
                    </Collapse>
                  </Box>
                );
              })}
            </Stack>
          )}
        </Box>
      )}

      {urlArtifacts.length > 0 ? (
        <Box component="section" sx={{ px: 2.25, pt: 2, pb: 1 }}>
          <Box sx={{ mb: 1 }}><Heading title="URLs" count={plural(urlArtifacts.length, "artifact")} /></Box>
          <UrlGroupList submissionId={submissionId} urls={urlArtifacts} />
        </Box>
      ) : null}
    </>
  );
}
