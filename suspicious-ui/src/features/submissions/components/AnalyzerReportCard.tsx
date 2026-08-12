import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Card,
  CardContent,
  Chip,
  LinearProgress,
  Stack,
  Typography,
} from "@mui/material";
import { ExpandMoreOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";

import { SubCategoryBarChart } from "@/shared/components/SubCategoryBarChart";
import type { SubmissionAnalyzerReport, SubmissionResult } from "@/features/submissions/api";
import {
  fmtDate,
  getConfidenceTone,
  getRiskTone,
  getSubCategoryProbabilities,
  normalizeConfidence,
  normalizeScore,
  prettyResult,
  prettySummary,
  readStatus,
  readType,
  summarizeForReading,
} from "@/features/submissions/utils";

export function AnalyzerReportCard({
  report,
  expanded,
  onToggle,
}: {
  report: SubmissionAnalyzerReport;
  expanded: boolean;
  onToggle: () => void;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const risk = getRiskTone(report.score);
  const confidence = getConfidenceTone(report.confidence);

  const scorePct = normalizeScore(report.score);
  const confidencePct = normalizeConfidence(report.confidence);

  const readableSummary = prettySummary(report.report_summary);
  const plainSummary = summarizeForReading(report);
  const subCategoryProbabilities = getSubCategoryProbabilities(report.report_full);

  const cardBg = isDark
    ? `linear-gradient(180deg, ${risk.softBg} 0%, rgba(255,255,255,.03) 100%)`
    : `linear-gradient(180deg, ${risk.softBg} 0%, ${alpha("#fff", 0.9)} 100%)`;

  const headerBg = isDark ? "rgba(255,255,255,.03)" : alpha(theme.palette.background.paper, 0.6);
  const detailBg = isDark ? "rgba(255,255,255,.03)" : alpha(theme.palette.background.paper, 0.5);
  const detailBorder = isDark ? "rgba(255,255,255,.08)" : alpha(theme.palette.divider, 0.6);
  const codeBg = isDark ? "rgba(0,0,0,.22)" : alpha(theme.palette.grey[100], 0.9);

  return (
    <Card
      sx={{
        borderRadius: 3,
        border: `1px solid ${risk.softBorder}`,
        background: cardBg,
        overflow: "hidden",
      }}
    >
      <Box
        role="button"
        tabIndex={0}
        onClick={onToggle}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggle();
          }
        }}
        sx={{
          px: 2,
          py: 1.5,
          borderBottom: expanded ? `1px solid ${detailBorder}` : "none",
          background: headerBg,
          cursor: "pointer",
          userSelect: "none",
        }}
      >
        <Stack
          direction={{ xs: "column", sm: "row" }}
          spacing={1.25}
          sx={{ justifyContent: "space-between", alignItems: { xs: "flex-start", sm: "center" } }}
>
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 900 }} >
              {report.analyzer_name || "Unknown analyzer"}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {readType(report.type)} • {readStatus(report.status)}
            </Typography>
          </Box>

          <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap", alignItems: "center" }}>
            <Chip
              size="small"
              label={risk.label}
              sx={{
                fontWeight: 800,
                color: risk.color,
                border: `1px solid ${risk.softBorder}`,
                backgroundColor: risk.softBg,
              }}
            />
            <Chip
              size="small"
              label={confidence.label}
              sx={{
                fontWeight: 800,
                border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.6)}`,
                backgroundColor: isDark ? "rgba(255,255,255,.04)" : alpha(theme.palette.grey[100], 0.7),
              }}
            />
            <ExpandMoreOutlined
              sx={{
                transition: "transform .2s ease",
                transform: expanded ? "rotate(180deg)" : "rotate(0deg)",
                opacity: 0.85,
              }}
            />
          </Stack>
        </Stack>
      </Box>

      {expanded ? (
        <CardContent sx={{ p: 2 }}>
          <Stack spacing={2}>
            <Box
              sx={{
                p: 1.5,
                borderRadius: 2,
                border: `1px solid ${detailBorder}`,
                background: detailBg,
              }}
            >
              <Typography variant="body2" sx={{ mb: 0.75, fontWeight: 800 }}>
                What this means
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                {readableSummary || plainSummary}
              </Typography>
            </Box>

            <Stack spacing={1.25}>
              <Box>
                <Stack direction="row" sx={{ mb: 0.5, justifyContent: "space-between" }}>
                  <Typography variant="body2" sx={{ fontWeight: 700 }} >Risk score</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 900 }} >
                    {typeof report.score === "number"
                      ? report.score.toFixed(report.score <= 10 ? 1 : 0)
                      : "—"}
                  </Typography>
                </Stack>
                <LinearProgress
                  variant="determinate"
                  value={scorePct}
                  sx={{ height: 10, borderRadius: 999, ...risk.barSx }}
                />
                <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                  Higher means the analyzer sees more signs of risk.
                </Typography>
              </Box>

              <Box>
                <Stack direction="row" sx={{ mb: 0.5, justifyContent: "space-between" }}>
                  <Typography variant="body2" sx={{ fontWeight: 700 }} >Confidence</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 900 }} >
                    {Math.round(confidencePct)}%
                  </Typography>
                </Stack>
                <LinearProgress
                  variant="determinate"
                  value={confidencePct}
                  sx={{ height: 10, borderRadius: 999, ...confidence.barSx }}
                />
                <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                  Higher means the analyzer is more sure about its result.
                </Typography>
              </Box>
            </Stack>

            {subCategoryProbabilities ? (
              <Box
                sx={{
                  p: 1.5,
                  borderRadius: 2,
                  border: `1px solid ${detailBorder}`,
                  background: detailBg,
                }}
              >
                <Typography variant="body2" sx={{ mb: 1.25, fontWeight: 800 }}>
                  Répartition par sous-catégorie
                </Typography>
                <SubCategoryBarChart data={subCategoryProbabilities} />
              </Box>
            ) : null}

            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: { xs: "1fr", sm: "140px 1fr" },
                gap: 1,
                p: 1.5,
                borderRadius: 2,
                border: `1px solid ${detailBorder}`,
                background: isDark ? "rgba(255,255,255,.02)" : alpha(theme.palette.background.paper, 0.4),
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
                borderRadius: 2,
                border: `1px solid ${detailBorder}`,
                background: isDark ? "rgba(255,255,255,.02)" : alpha(theme.palette.background.paper, 0.4),
                "&:before": { display: "none" },
              }}
            >
              <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
                <Typography variant="body2" sx={{ fontWeight: 800 }} >Technical details</Typography>
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
                        borderRadius: 2,
                        border: `1px solid ${detailBorder}`,
                        background: isDark ? "rgba(255,255,255,.02)" : alpha(theme.palette.background.paper, 0.4),
                        "&:before": { display: "none" },
                      }}
                    >
                      <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
                        <Typography variant="body2" sx={{ fontWeight: 800 }} >Taxonomy JSON</Typography>
                      </AccordionSummary>
                      <AccordionDetails onClick={(e) => e.stopPropagation()}>
                        <Box
                          component="pre"
                          sx={{
                            m: 0,
                            p: 1.25,
                            borderRadius: 2,
                            border: `1px solid ${detailBorder}`,
                            background: codeBg,
                            overflow: "auto",
                            maxHeight: 220,
                            fontSize: 12,
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
                        borderRadius: 2,
                        border: `1px solid ${detailBorder}`,
                        background: isDark ? "rgba(255,255,255,.02)" : alpha(theme.palette.background.paper, 0.4),
                        "&:before": { display: "none" },
                      }}
                    >
                      <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
                        <Typography variant="body2" sx={{ fontWeight: 800 }} >Summary JSON</Typography>
                      </AccordionSummary>
                      <AccordionDetails onClick={(e) => e.stopPropagation()}>
                        <Box
                          component="pre"
                          sx={{
                            m: 0,
                            p: 1.25,
                            borderRadius: 2,
                            border: `1px solid ${detailBorder}`,
                            background: codeBg,
                            overflow: "auto",
                            maxHeight: 220,
                            fontSize: 12,
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
        </CardContent>
      ) : null}
    </Card>
  );
}
