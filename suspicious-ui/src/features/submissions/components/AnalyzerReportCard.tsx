import * as React from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Chip,
  Collapse,
  LinearProgress,
  Stack,
  Typography,
} from "@mui/material";
import { ExpandMoreOutlined } from "@mui/icons-material";
import { alpha } from "@mui/material/styles";

import type { SubmissionAnalyzerReport, SubmissionResult } from "@/features/submissions/api";
import {
  fmtDate,
  getConfidenceTone,
  getRiskTone,
  normalizeConfidence,
  normalizeScore,
  prettyResult,
  prettySummary,
  readStatus,
  readType,
  riskPalette,
  reportSucceeded,
  summarizeForReading,
  unfinishedLabel,
} from "@/features/submissions/utils";

/** Risk label in the theme's own error/warning/success palette (themes restyle Chip colours, so set them explicitly). */
export function RiskChip({ label, tone }: { label: string; tone: "error" | "warning" | "success" }) {
  return (
    <Chip
      size="small"
      variant="outlined"
      label={label}
      sx={(theme) => {
        const c = theme.palette[tone];
        return {
          flexShrink: 0,
          color: theme.palette.mode === "dark" ? c.light : c.dark,
          borderColor: alpha(c.main, 0.5),
          bgcolor: alpha(c.main, 0.1),
        };
      }}
    />
  );
}

/** A run with no result: neutral and dashed, so it never reads as a risk level. */
function NoResultChip({ label }: { label: string }) {
  return (
    <Chip size="small" variant="outlined" label={label}
      sx={{ flexShrink: 0, color: "text.secondary", borderColor: "text.disabled", borderStyle: "dashed", bgcolor: "transparent" }} />
  );
}

export function AnalyzerReportCard({
  report,
  expanded,
  onToggle,
}: {
  report: SubmissionAnalyzerReport;
  expanded: boolean;
  onToggle: () => void;
}) {
  const ok = reportSucceeded(report);
  const risk = getRiskTone(report.score);
  const tone = riskPalette(report.score);
  const confidence = getConfidenceTone(report.confidence);

  const scorePct = normalizeScore(report.score);
  const confidencePct = normalizeConfidence(report.confidence);

  const readableSummary = prettySummary(report.report_summary);
  const name = report.analyzer_name || "This analyzer";
  const unfinished = unfinishedLabel(report.status);
  const why = {
    Running: `${name} has not finished yet`,
    Queued: `${name} has not finished yet`,
    Expired: `The result of ${name} is no longer available in Cortex`,
    Unknown: `${name} has no status reported`,
    Failed: `${name} did not return a result (status: ${report.status})`,
  }[unfinished];
  const plainSummary = ok ? summarizeForReading(report) : `${why}, so it has no risk score or confidence.`;
  const detailsId = React.useId();

  const detailBg = "action.hover";
  const detailBorder = "divider";
  const codeBg = "action.selected";
  const sectionSx = { borderRadius: 2, border: 1, borderColor: detailBorder, bgcolor: detailBg } as const;

  return (
    <Box
      sx={{
        borderRadius: 1.5,
        border: 1,
        borderColor: "divider",
        // The one risk cue on a collapsed row; a run with no result gets a neutral edge.
        borderLeft: 3,
        borderLeftColor: ok ? `${tone}.main` : "divider",
        bgcolor: "background.paper",
        overflow: "hidden",
      }}
    >
      <Box
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        aria-controls={detailsId}
        onClick={onToggle}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggle();
          }
        }}
        sx={{
          px: 1.5,
          py: 0.75,
          minHeight: 44,
          display: "flex",
          alignItems: "center",
          gap: 1,
          cursor: "pointer",
          userSelect: "none",
          "&:hover": { bgcolor: "action.hover" },
        }}
      >
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography variant="body2" noWrap title={report.analyzer_name || undefined} sx={{ fontWeight: 600 }}>
            {report.analyzer_name || "Unknown analyzer"}
          </Typography>
          <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>
            {/* The chip already states a non-success status; the caption only repeats it for successes. */}
            {ok ? `${readType(report.type)} · ${readStatus(report.status)}` : readType(report.type)}
          </Typography>
        </Box>
        {ok ? <RiskChip label={risk.label} tone={tone} /> : <NoResultChip label={unfinished} />}
        <ExpandMoreOutlined
          aria-hidden
          sx={{
            flexShrink: 0,
            color: "text.secondary",
            transition: "transform .2s ease",
            transform: expanded ? "rotate(180deg)" : "rotate(0deg)",
          }}
        />
      </Box>

      {/* Stable target for aria-controls: Collapse unmounts its content when closed. */}
      <div id={detailsId}>
      <Collapse in={expanded} unmountOnExit>
        <Box sx={{ p: 2, borderTop: 1, borderColor: detailBorder }}>
          <Stack spacing={2}>
            <Box sx={{ p: 1.5, ...sectionSx }}>
              <Typography variant="body2" sx={{ mb: 0.75, fontWeight: 600 }}>
                What this means
              </Typography>
              {/* Summaries quote hashes and URLs: let them wrap instead of running past the box on phones. */}
              <Typography variant="body2" sx={{ lineHeight: 1.6, overflowWrap: "anywhere" }}>
                {readableSummary || plainSummary}
              </Typography>
            </Box>

            {ok ? (
            <Stack spacing={1.25}>
              <Box>
                <Stack direction="row" sx={{ mb: 0.5, justifyContent: "space-between" }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>Risk score</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 700 }}>
                    {typeof report.score === "number"
                      ? report.score.toFixed(report.score <= 10 ? 1 : 0)
                      : "—"}
                  </Typography>
                </Stack>
                <LinearProgress
                  variant="determinate"
                  value={scorePct}
                  // Theme palette, not the theme's accent gradient: the bar shows the same risk colour as the chip.
                  sx={(theme) => ({
                    height: 10, borderRadius: 999, bgcolor: alpha(theme.palette[tone].main, 0.18),
                    "& .MuiLinearProgress-bar": { bgcolor: theme.palette[tone].main, backgroundImage: "none", boxShadow: "none" },
                  })}
                />
                <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                  Higher means the analyzer sees more signs of risk.
                </Typography>
              </Box>

              <Box>
                <Stack direction="row" sx={{ mb: 0.5, justifyContent: "space-between" }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>Confidence</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 700 }}>
                    {Math.round(confidencePct)}%
                  </Typography>
                </Stack>
                <LinearProgress
                  variant="determinate"
                  value={confidencePct}
                  sx={{ height: 10, borderRadius: 999, ...confidence.barSx }}
                />
                <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                  {confidence.label}. Higher means the analyzer is more sure about its result.
                </Typography>
              </Box>
            </Stack>
            ) : null}

            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: { xs: "1fr", sm: "140px 1fr" },
                gap: 1,
                p: 1.5,
                ...sectionSx,
              }}
            >
              <Typography color="text.secondary" variant="body2">Checked item</Typography>
              <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
                {report.target?.value || "—"}
              </Typography>

              <Typography color="text.secondary" variant="body2">Item type</Typography>
              <Typography variant="body2">{report.target?.kind || "—"}</Typography>

              <Typography color="text.secondary" variant="body2">Categories</Typography>
              <Typography variant="body2">
                {report.categories?.length ? report.categories.join(", ") : "None listed"}
              </Typography>

              <Typography color="text.secondary" variant="body2">Result</Typography>
              <Typography variant="body2">
                {prettyResult((report.category as SubmissionResult | null) ?? undefined)}
              </Typography>

              <Typography color="text.secondary" variant="body2">Finished</Typography>
              <Typography variant="body2">{fmtDate(report.created_at)}</Typography>
            </Box>

            <Accordion
              disableGutters
              sx={{
                ...sectionSx,
                "&:before": { display: "none" },
              }}
            >
              <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>Technical details</Typography>
              </AccordionSummary>
              <AccordionDetails onClick={(e) => e.stopPropagation()}>
                <Stack spacing={1.5}>
                  <Box
                    sx={{
                      display: "grid",
                      gridTemplateColumns: { xs: "1fr", sm: "140px 1fr" },
                      gap: 1,
                    }}
                  >
                    <Typography color="text.secondary" variant="body2">Analyzer ID</Typography>
                    <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
                      {report.analyzer_id || "—"}
                    </Typography>

                    <Typography color="text.secondary" variant="body2">Job ID</Typography>
                    <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
                      {report.cortex_job_id || "—"}
                    </Typography>

                    <Typography color="text.secondary" variant="body2">Level</Typography>
                    <Typography variant="body2">{report.level || "—"}</Typography>

                    <Typography color="text.secondary" variant="body2">Status</Typography>
                    <Typography variant="body2">{report.status || "—"}</Typography>
                  </Box>

                  {report.report_taxonomy ? (
                    <Accordion
                      disableGutters
                      sx={{
                        ...sectionSx,
                        "&:before": { display: "none" },
                      }}
                    >
                      <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>Taxonomy JSON</Typography>
                      </AccordionSummary>
                      <AccordionDetails onClick={(e) => e.stopPropagation()}>
                        <Box
                          component="pre"
                          sx={{
                            m: 0,
                            p: 1.25,
                            borderRadius: 2,
                            border: 1,
                            borderColor: detailBorder,
                            bgcolor: codeBg,
                            overflow: "auto",
                            maxHeight: 220,
                            fontSize: "0.75rem",
                            lineHeight: 1.45,
                          }}
                        >
                          {JSON.stringify(report.report_taxonomy, null, 2)}
                        </Box>
                      </AccordionDetails>
                    </Accordion>
                  ) : null}

                  {report.report_summary ? (
                    <Accordion
                      disableGutters
                      sx={{
                        ...sectionSx,
                        "&:before": { display: "none" },
                      }}
                    >
                      <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>Summary JSON</Typography>
                      </AccordionSummary>
                      <AccordionDetails onClick={(e) => e.stopPropagation()}>
                        <Box
                          component="pre"
                          sx={{
                            m: 0,
                            p: 1.25,
                            borderRadius: 2,
                            border: 1,
                            borderColor: detailBorder,
                            bgcolor: codeBg,
                            overflow: "auto",
                            maxHeight: 220,
                            fontSize: "0.75rem",
                            lineHeight: 1.45,
                          }}
                        >
                          {JSON.stringify(report.report_summary, null, 2)}
                        </Box>
                      </AccordionDetails>
                    </Accordion>
                  ) : null}
                </Stack>
              </AccordionDetails>
            </Accordion>
          </Stack>
        </Box>
      </Collapse>
      </div>
    </Box>
  );
}
