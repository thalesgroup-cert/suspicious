import * as React from "react";
import { Alert, Box, Chip, CircularProgress, Collapse, IconButton, Stack, Tooltip, Typography } from "@mui/material";
import { ExpandMoreOutlined, UnfoldLess, UnfoldMore } from "@mui/icons-material";
import { AnalyzerReportCard, type AnalyzerReportRow } from "@/features/submissions/components/AnalyzerReportCard";
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

export function Heading({ title, count }: { title: string; count?: string }) {
  return (
    <Stack direction="row" spacing={1} sx={{ alignItems: "baseline", minWidth: 0 }}>
      <Typography variant="subtitle2" component="h3" color="text.secondary">{title}</Typography>
      {count ? <Typography variant="caption" color="text.secondary">{count}</Typography> : null}
    </Stack>
  );
}

/**
 * The analyzer groups (heading, states, groups, rows). Shared by the Submissions and Investigation drawers.
 * Expansion state lives here: each drawer keys its tab by case and unmounts it on close, which resets it.
 */
export function AnalyzerGroups<R extends AnalyzerReportRow>({ reports, isLoading, isError, extraDetails, listLabel = "Observables" }: {
  reports: R[];
  isLoading: boolean;
  isError: boolean;
  /** Built only for an expanded row: it may parse the report (Investigation enrichment). */
  extraDetails?: (report: R) => React.ReactNode;
  /** Accessible name of the group list; Investigation renames it so it does not repeat its "Observables" heading. */
  listLabel?: string;
}) {
  // Worst risk first: the reporter lands on the dangerous finding. A run with no result has no risk (-1).
  const groups = React.useMemo(
    () =>
      groupReportsByArtifact(reports)
        .map((g) => {
          const scored = g.reports.filter(reportSucceeded);
          const worst = scored.reduce<R | null>(
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
  const idBase = React.useId();
  const [openRows, setOpenRows] = React.useState<Record<number, boolean>>({});
  const isOpen = (key: string) => openGroups[key] ?? key === groups[0]?.key;
  const setAll = (open: boolean) => setOpenGroups(Object.fromEntries(groups.map((g) => [g.key, open])));

  return (
    <Box component="section" sx={{ px: 2.25, pt: 2, pb: 1 }}>
      <Stack direction="row" sx={{ mb: 1, alignItems: "center", justifyContent: "space-between", minHeight: 40 }}>
        <Heading title="Analysis" count={isLoading || isError ? undefined : plural(reports.length, "report")} />
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
        <Stack component="ul" aria-label={listLabel} spacing={1} sx={{ mt: 0, mb: 1.5, p: 0, listStyle: "none" }}>
          {groups.map((group, i) => {
            const panelId = `${idBase}-group-${i}`;
            const open = isOpen(group.key);
            const toggle = () => setOpenGroups((prev) => ({ ...prev, [group.key]: !open }));
            const worstLabel = group.worst ? getRiskTone(group.worst.score).label : "No result";
            return (
              <Box key={group.key} component="li"
                sx={{ borderRadius: 2, border: 1, borderColor: "divider", overflow: "hidden" }}>
                <Box
                  role="button" tabIndex={0} aria-expanded={open} aria-controls={panelId}
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

                <div id={panelId}>
                <Collapse in={open} unmountOnExit>
                  <Stack spacing={0.75} sx={{ p: 1 }}>
                    {group.reports.map((report) => (
                      <AnalyzerReportCard
                        key={report.id}
                        report={report}
                        expanded={!!openRows[report.id]}
                        onToggle={() => setOpenRows((prev) => ({ ...prev, [report.id]: !prev[report.id] }))}
                        extraDetails={openRows[report.id] ? extraDetails?.(report) : undefined}
                      />
                    ))}
                  </Stack>
                </Collapse>
                </div>
              </Box>
            );
          })}
        </Stack>
      )}
    </Box>
  );
}
