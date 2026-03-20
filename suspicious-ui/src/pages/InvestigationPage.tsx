// src/pages/InvestigationPage.tsx
import * as React from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Avatar,
  LinearProgress,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Drawer,
  FormControl,
  IconButton,
  InputAdornment,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import {
  AssignmentTurnedInOutlined,
  SearchOutlined,
  RefreshOutlined,
  OpenInNewOutlined,
  FilterAltOutlined,
  ContentCopyOutlined,
  EditOutlined,
  SaveOutlined,
  CloseOutlined,
  ExpandMoreOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { alpha } from "@mui/material/styles";
import { useTheme } from "@mui/material/styles";

import { getMe, type Me } from "@/api/auth";
import {
  getAllInvestigations,
  getInvestigationDetails,
  editGlobalCase,
  type InvestigationDetails,
  type InvestigationListResponse,
  type InvestigationRow,
  type InvestigationStatus,
  type InvestigationType,
} from "@/features/investigation/api";
import { useDebounced } from "@/shared/hooks/useDebounced";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import { CopyIconButton } from "@/shared/components/CopyIconButton";

// ---------------------------------------------------------------------------
// Score / confidence helpers  (identical to SubmissionsPage)
// ---------------------------------------------------------------------------

function clamp(n: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, n));
}

function normalizeScore(score?: number | null) {
  if (typeof score !== "number" || Number.isNaN(score)) return 0;
  if (score <= 10) return clamp(score * 10);
  return clamp(score);
}

function normalizeConfidence(confidence?: number | null) {
  if (typeof confidence !== "number" || Number.isNaN(confidence)) return 0;
  if (confidence <= 1) return clamp(confidence * 100);
  if (confidence <= 10) return clamp(confidence * 10);
  return clamp(confidence);
}

function getRiskTone(score?: number | null) {
  const v = normalizeScore(score);
  if (v >= 80) {
    return {
      label: "High risk",
      color: "#ef4444",
      softBg: "rgba(239,68,68,.12)",
      softBorder: "rgba(239,68,68,.32)",
      barSx: {
        "& .MuiLinearProgress-bar": { backgroundColor: "#ef4444" },
        backgroundColor: "rgba(239,68,68,.18)",
      },
    };
  }
  if (v >= 55) {
    return {
      label: "Needs attention",
      color: "#f59e0b",
      softBg: "rgba(245,158,11,.12)",
      softBorder: "rgba(245,158,11,.32)",
      barSx: {
        "& .MuiLinearProgress-bar": { backgroundColor: "#f59e0b" },
        backgroundColor: "rgba(245,158,11,.18)",
      },
    };
  }
  return {
    label: "Low risk",
    color: "#22c55e",
    softBg: "rgba(34,197,94,.12)",
    softBorder: "rgba(34,197,94,.32)",
    barSx: {
      "& .MuiLinearProgress-bar": { backgroundColor: "#22c55e" },
      backgroundColor: "rgba(34,197,94,.18)",
    },
  };
}

function getConfidenceTone(confidence?: number | null) {
  const v = normalizeConfidence(confidence);
  if (v >= 75) {
    return {
      label: "High confidence",
      color: "#22c55e",
      barSx: {
        "& .MuiLinearProgress-bar": { backgroundColor: "#22c55e" },
        backgroundColor: "rgba(34,197,94,.18)",
      },
    };
  }
  if (v >= 45) {
    return {
      label: "Medium confidence",
      color: "#f59e0b",
      barSx: {
        "& .MuiLinearProgress-bar": { backgroundColor: "#f59e0b" },
        backgroundColor: "rgba(245,158,11,.18)",
      },
    };
  }
  return {
    label: "Low confidence",
    color: "#94a3b8",
    barSx: {
      "& .MuiLinearProgress-bar": { backgroundColor: "#94a3b8" },
      backgroundColor: "rgba(148,163,184,.18)",
    },
  };
}

// ---------------------------------------------------------------------------
// Label helpers
// ---------------------------------------------------------------------------

function readStatus(status?: string) {
  const s = (status ?? "").toUpperCase();
  if (s === "DONE") return "Finished";
  if (s === "FAILED") return "Failed";
  if (s === "IN_PROGRESS") return "Running";
  if (s === "NEW") return "Queued";
  if (s === "CHALLENGED") return "Challenged";
  return status || "Unknown";
}

function readType(type?: string) {
  const t = (type ?? "").toLowerCase();
  if (t === "file") return "File check";
  if (t === "hash") return "Hash check";
  if (t === "mail") return "Email check";
  if (t === "url") return "Link check";
  if (t === "ip") return "IP check";
  return type || "Analyzer";
}

function summarizeForReading(report: any) {
  const risk = getRiskTone(report.score);
  const confidence = getConfidenceTone(report.confidence);
  const targetValue = report.target?.value;
  const categories = report.categories?.filter(Boolean) ?? [];
  const parts: string[] = [];
  parts.push(`${report.analyzer_name || "This analyzer"} marked this item as ${risk.label.toLowerCase()}.`);
  parts.push(`The result confidence is ${confidence.label.toLowerCase()}.`);
  if (targetValue) parts.push(`Checked item: ${targetValue}.`);
  if (categories.length) parts.push(`Detected type: ${categories.join(", ")}.`);
  return parts.join(" ");
}

function prettySummary(summary: any) {
  if (!summary) return null;
  if (typeof summary === "string") return summary;
  if (Array.isArray(summary)) {
    return summary.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join("\n");
  }
  if (typeof summary === "object") {
    if (typeof summary.summary === "string") return summary.summary;
    if (typeof summary.message === "string") return summary.message;
    if (typeof summary.verdict === "string") return summary.verdict;
  }
  return null;
}

function fmtDate(iso: string) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit" });
}

function short(s: string, n = 42) {
  const t = (s ?? "").trim();
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
}

function pickScore(d?: InvestigationDetails) {
  return d?.case_infos?.score ?? null;
}
function pickConfidence(d?: InvestigationDetails) {
  return d?.case_infos?.confidence ?? null;
}
function pickClassification(d?: InvestigationDetails) {
  return d?.case_infos?.classification ?? "UNKNOWN";
}

// ---------------------------------------------------------------------------
// SoftCard — theme-aware, identical to SubmitPage / HomePage / SubmissionsPage
// ---------------------------------------------------------------------------

function SoftCard(props: React.PropsWithChildren<{ sx?: object }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Card
      sx={{
        borderRadius: 4,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.9)}`,
        background: isDark
          ? `linear-gradient(180deg, ${alpha("#fff", 0.03)}, ${alpha("#fff", 0.02)})`
          : `linear-gradient(180deg, ${alpha("#fff", 0.88)}, ${alpha(
              theme.palette.grey[50],
              0.96
            )})`,
        boxShadow: isDark
          ? "0 12px 32px rgba(0,0,0,.28)"
          : "0 10px 28px rgba(15,23,42,.06)",
        ...props.sx,
      }}
    >
      {props.children}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// InvestigationAnalyzerReportCard — fully theme-aware
// ---------------------------------------------------------------------------

function InvestigationAnalyzerReportCard({
  report,
  expanded,
  onToggle,
}: {
  report: any;
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
          justifyContent="space-between"
          alignItems={{ xs: "flex-start", sm: "center" }}
        >
          <Box>
            <Typography variant="subtitle1" fontWeight={900}>
              {report.analyzer_name || "Unknown analyzer"}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {readType(report.type)} • {readStatus(report.status)}
            </Typography>
          </Box>

          <Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: "wrap" }}>
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
                backgroundColor: isDark
                  ? "rgba(255,255,255,.04)"
                  : alpha(theme.palette.grey[100], 0.7),
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
            {/* What this means */}
            <Box
              sx={{
                p: 1.5,
                borderRadius: 2,
                border: `1px solid ${detailBorder}`,
                background: detailBg,
              }}
            >
              <Typography variant="body2" fontWeight={800} sx={{ mb: 0.75 }}>
                What this means
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                {readableSummary || plainSummary}
              </Typography>
            </Box>

            {/* Score + confidence bars */}
            <Stack spacing={1.25}>
              <Box>
                <Stack direction="row" justifyContent="space-between" sx={{ mb: 0.5 }}>
                  <Typography variant="body2" fontWeight={700}>Risk score</Typography>
                  <Typography variant="body2" fontWeight={900}>
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
              </Box>

              <Box>
                <Stack direction="row" justifyContent="space-between" sx={{ mb: 0.5 }}>
                  <Typography variant="body2" fontWeight={700}>Confidence</Typography>
                  <Typography variant="body2" fontWeight={900}>
                    {Math.round(confidencePct)}%
                  </Typography>
                </Stack>
                <LinearProgress
                  variant="determinate"
                  value={confidencePct}
                  sx={{ height: 10, borderRadius: 999, ...confidence.barSx }}
                />
              </Box>
            </Stack>

            {/* Details grid */}
            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: { xs: "1fr", sm: "140px 1fr" },
                gap: 1,
                p: 1.5,
                borderRadius: 2,
                border: `1px solid ${detailBorder}`,
                background: isDark
                  ? "rgba(255,255,255,.02)"
                  : alpha(theme.palette.background.paper, 0.4),
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

              <Typography color="text.secondary" variant="body2">Finished</Typography>
              <Typography variant="body2">
                {report.created_at ? fmtDate(report.created_at) : "—"}
              </Typography>
            </Box>

            {/* Technical details accordion */}
            <Accordion
              disableGutters
              sx={{
                borderRadius: 2,
                border: `1px solid ${detailBorder}`,
                background: isDark
                  ? "rgba(255,255,255,.02)"
                  : alpha(theme.palette.background.paper, 0.4),
                "&:before": { display: "none" },
              }}
            >
              <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
                <Typography variant="body2" fontWeight={800}>Technical details</Typography>
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
                        background: isDark
                          ? "rgba(255,255,255,.02)"
                          : alpha(theme.palette.background.paper, 0.4),
                        "&:before": { display: "none" },
                      }}
                    >
                      <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
                        <Typography variant="body2" fontWeight={800}>Taxonomy JSON</Typography>
                      </AccordionSummary>
                      <AccordionDetails onClick={(e) => e.stopPropagation()}>
                        <Box
                          component="pre"
                          sx={{
                            m: 0, p: 1.25, borderRadius: 2,
                            border: `1px solid ${detailBorder}`,
                            background: codeBg,
                            overflow: "auto", maxHeight: 220, fontSize: 12, lineHeight: 1.45,
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
                        background: isDark
                          ? "rgba(255,255,255,.02)"
                          : alpha(theme.palette.background.paper, 0.4),
                        "&:before": { display: "none" },
                      }}
                    >
                      <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
                        <Typography variant="body2" fontWeight={800}>Summary JSON</Typography>
                      </AccordionSummary>
                      <AccordionDetails onClick={(e) => e.stopPropagation()}>
                        <Box
                          component="pre"
                          sx={{
                            m: 0, p: 1.25, borderRadius: 2,
                            border: `1px solid ${detailBorder}`,
                            background: codeBg,
                            overflow: "auto", maxHeight: 220, fontSize: 12, lineHeight: 1.45,
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

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function InvestigationPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const qc = useQueryClient();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const [q, setQ] = React.useState("");
  const qDebounced = useDebounced(q, 250);

  const [status, setStatus] = React.useState<InvestigationStatus | "ALL">("ALL");
  const [type, setType] = React.useState<InvestigationType | "ALL">("ALL");
  const [from, setFrom] = React.useState("");
  const [to, setTo] = React.useState("");
  const [sort, setSort] = React.useState<"date_desc" | "date_asc" | "id_desc" | "id_asc">("date_desc");
  const [page, setPage] = React.useState(0);
  const [pageSize, setPageSize] = React.useState(10);

  const [openDrawer, setOpenDrawer] = React.useState(false);
  const [selectedId, setSelectedId] = React.useState<number | null>(null);

  const [editMode, setEditMode] = React.useState(false);
  const [editScore, setEditScore] = React.useState<string>("");
  const [editConfidence, setEditConfidence] = React.useState<string>("");
  const [editClassification, setEditClassification] = React.useState<string>("UNKNOWN");

  const [expandedAnalyzerIds, setExpandedAnalyzerIds] = React.useState<Record<number, boolean>>({});

  const meQuery = useQuery<Me>({ queryKey: ["me"], queryFn: getMe, retry: false });
  const me = meQuery.data;

  const groups = React.useMemo(() => me?.groups ?? [], [me]);
  const isElevated = React.useMemo(
    () => groups.includes("CISO") || groups.includes("CERT") || groups.includes("Admin"),
    [groups]
  );

  const investigationListParams = React.useMemo(
    () => ({ page, pageSize, search: qDebounced, status, type, from, to, sort }),
    [page, pageSize, qDebounced, status, type, from, to, sort]
  );

  const investigationsQuery = useQuery<InvestigationListResponse>({
    queryKey: ["investigation", investigationListParams],
    queryFn: () => getAllInvestigations(investigationListParams),
    enabled: !!me && isElevated,
    retry: false,
    placeholderData: (prev) => prev,
    refetchInterval: (query) => {
      const rows = (query.state.data as InvestigationListResponse | undefined)?.results ?? [];
      const shouldPoll = rows.some((r) => {
        const s = String(r.status ?? "UNKNOWN").toUpperCase();
        return s === "NEW" || s === "IN_PROGRESS";
      });
      return shouldPoll ? 10_000 : false;
    },
    refetchIntervalInBackground: true,
  });

  const selectedIdNum =
    typeof selectedId === "number" && Number.isFinite(selectedId) ? selectedId : NaN;
  const hasNumericSelectedId = Number.isFinite(selectedIdNum);

  const detailsQuery = useQuery<InvestigationDetails>({
    queryKey: ["investigationDetails", selectedIdNum],
    queryFn: () => getInvestigationDetails(selectedIdNum),
    enabled: !!me && isElevated && hasNumericSelectedId && openDrawer,
    retry: false,
    staleTime: 30_000,
    gcTime: 10 * 60_000,
    placeholderData: (prev) => prev,
  });

  const editMutation = useMutation({
    mutationFn: async (payload: {
      caseId: number;
      score: number;
      confidence: number;
      classification: string;
    }) => editGlobalCase(payload.caseId, payload.score, payload.confidence, payload.classification),
    onSuccess: async () => {
      setEditMode(false);
      await Promise.all([
        detailsQuery.refetch(),
        investigationsQuery.refetch(),
        qc.invalidateQueries({ queryKey: ["investigationDetails"] }),
        qc.invalidateQueries({ queryKey: ["investigation"] }),
      ]);
    },
  });

  React.useEffect(() => {
    const urlQ = searchParams.get("q") ?? "";
    const open = searchParams.get("open");
    if (urlQ) setQ(urlQ);
    if (open) {
      const idNum = Number(open);
      if (Number.isFinite(idNum)) { setSelectedId(idNum); setOpenDrawer(true); }
    }
  }, [searchParams]);

  React.useEffect(() => { setPage(0); }, [qDebounced, status, type, from, to, sort, pageSize]);
  React.useEffect(() => { if (!openDrawer) setExpandedAnalyzerIds({}); }, [openDrawer]);
  React.useEffect(() => { setExpandedAnalyzerIds({}); }, [selectedId]);
  React.useEffect(() => { setExpandedAnalyzerIds({}); }, [detailsQuery.data?.analyzer_reports]);
  React.useEffect(() => { setEditMode(false); editMutation.reset(); }, [selectedIdNum]); // eslint-disable-line react-hooks/exhaustive-deps

  React.useEffect(() => {
    if (!openDrawer || !detailsQuery.data || editMode) return;
    const score = pickScore(detailsQuery.data);
    const confidence = pickConfidence(detailsQuery.data);
    const classification = pickClassification(detailsQuery.data);
    setEditScore(score == null ? "" : String(score));
    setEditConfidence(confidence == null ? "" : String(confidence));
    setEditClassification(String(classification).toUpperCase());
  }, [openDrawer, detailsQuery.data, editMode]);

  const rows = investigationsQuery.data?.results ?? [];
  const total = investigationsQuery.data?.count ?? 0;
  const start = total === 0 ? 0 : page * pageSize;
  const end = Math.min(total, start + rows.length);

  const selectedRow = selectedId != null
    ? rows.find((r) => String(r.id) === String(selectedId))
    : undefined;
  const drawerRow = selectedRow || detailsQuery.data;
  const detailsReady = !!detailsQuery.data && !detailsQuery.isLoading && !detailsQuery.isError;

  const currentScore = pickScore(detailsQuery.data);
  const currentConfidence = pickConfidence(detailsQuery.data);
  const currentClassification = pickClassification(detailsQuery.data);

  const analyzerReports = detailsQuery.data?.analyzer_reports ?? [];

  const expandAllAnalyzers = React.useCallback(() => {
    setExpandedAnalyzerIds(Object.fromEntries(analyzerReports.map((r) => [r.id, true])));
  }, [analyzerReports]);

  const collapseAllAnalyzers = React.useCallback(() => { setExpandedAnalyzerIds({}); }, []);

  const invertAnalyzers = React.useCallback(() => {
    setExpandedAnalyzerIds((prev) =>
      Object.fromEntries(analyzerReports.map((r) => [r.id, !prev[r.id]]))
    );
  }, [analyzerReports]);

  function closeDrawer() { setOpenDrawer(false); setEditMode(false); editMutation.reset(); }

  async function copyEmail(email?: string) {
    if (!email) return;
    try { await navigator.clipboard.writeText(email); } catch { /* ignore */ }
  }

  // Auth / access guards
  if (meQuery.isLoading) {
    return <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}><CircularProgress /></Box>;
  }
  if (!me) {
    return <Box sx={{ p: 3 }}><Alert severity="error">Not authenticated.</Alert></Box>;
  }
  if (!isElevated) {
    return <Box sx={{ p: 3 }}><Alert severity="error">Access denied.</Alert></Box>;
  }
  if (investigationsQuery.isLoading && !investigationsQuery.data) {
    return <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}><CircularProgress /></Box>;
  }
  if (investigationsQuery.isError) {
    return <Box sx={{ p: 3 }}><Alert severity="error">Failed to load investigations.</Alert></Box>;
  }

  const BADGE_W = 132;
  const DRAWER_RADIUS = 2;

  const classificationOptions = [
    "SAFE", "INCONCLUSIVE", "UNCHALLENGED", "ALLOW_LISTED",
    "FAILURE", "SUSPICIOUS", "DANGEROUS",
  ];

  const scoreNum = Number(editScore);
  const confNum = Number(editConfidence);
  const scoreValid = Number.isFinite(scoreNum) && scoreNum >= 0 && scoreNum <= 10;
  const confValid = Number.isFinite(confNum) && confNum >= 0 && confNum <= 100;
  const canSave = scoreValid && confValid && !!editClassification && !editMutation.isPending;

  // Theme-aware values for drawer inline cards
  const drawerCardBorder = isDark ? "rgba(255,255,255,.08)" : alpha(theme.palette.divider, 0.6);
  const drawerCardBg = isDark ? "rgba(255,255,255,.025)" : alpha(theme.palette.background.paper, 0.7);
  const refreshBtnBorder = isDark
    ? "1px solid rgba(255,255,255,.10)"
    : `1px solid ${alpha(theme.palette.divider, 0.6)}`;

  return (
    <Box sx={{ p: { xs: 2, md: 3 } }}>
      {/* ------------------------------------------------------------------ */}
      {/* Page header                                                         */}
      {/* ------------------------------------------------------------------ */}
      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={2}
        justifyContent="space-between"
        sx={{ mb: 2 }}
      >
        <Stack spacing={0.4}>
          <Stack direction="row" spacing={1.25} alignItems="center">
            <Avatar sx={{ width: 46, height: 46, fontWeight: 950 }}>
              {(me.username?.[0] ?? "A").toUpperCase()}
            </Avatar>
            <Box>
              <Typography variant="h4" fontWeight={950} letterSpacing={-0.5}>
                Investigation
              </Typography>
              <Typography color="text.secondary">
                All submissions — open an ID to see details.
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
            <Chip icon={<AssignmentTurnedInOutlined />} label={`${total} total`} variant="outlined" />
            <Chip icon={<FilterAltOutlined />} label="Server filters" variant="outlined" />
            {qDebounced ? <Chip label={`Search: ${qDebounced}`} variant="outlined" /> : null}
          </Stack>
        </Stack>

        <Stack direction="row" spacing={1} alignItems="center">
          <Button
            variant="contained"
            onClick={() => navigate("/submit")}
            sx={{ borderRadius: 2, textTransform: "none", fontWeight: 900 }}
          >
            New submission
          </Button>

          <IconButton
            aria-label="Refresh"
            onClick={() => investigationsQuery.refetch()}
            sx={{ border: refreshBtnBorder, borderRadius: 2 }}
          >
            <RefreshOutlined />
          </IconButton>
        </Stack>
      </Stack>

      {/* ------------------------------------------------------------------ */}
      {/* Filter bar                                                          */}
      {/* ------------------------------------------------------------------ */}
      <SoftCard sx={{ mb: 2 }}>
        <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
          <Stack spacing={1.5}>
            <Stack direction={{ xs: "column", md: "row" }} spacing={1.25} alignItems="stretch">
              <TextField
                value={q}
                onChange={(e) => setQ(e.target.value)}
                label="Search"
                placeholder="id, user mail, status, artifact, type, result"
                fullWidth
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchOutlined fontSize="small" />
                    </InputAdornment>
                  ),
                }}
              />

              <FormControl sx={{ minWidth: 180 }} fullWidth>
                <InputLabel id="status-label">Status</InputLabel>
                <Select
                  labelId="status-label"
                  label="Status"
                  value={status}
                  onChange={(e) => setStatus(e.target.value as InvestigationStatus | "ALL")}
                >
                  <MenuItem value="ALL">All</MenuItem>
                  {(["NEW", "IN_PROGRESS", "DONE", "CHALLENGED", "UNKNOWN"] as const).map((s) => (
                    <MenuItem key={s} value={s}>{s}</MenuItem>
                  ))}
                </Select>
              </FormControl>

              <FormControl sx={{ minWidth: 160 }} fullWidth>
                <InputLabel id="type-label">Type</InputLabel>
                <Select
                  labelId="type-label"
                  label="Type"
                  value={type}
                  onChange={(e) => setType(e.target.value as InvestigationType | "ALL")}
                >
                  <MenuItem value="ALL">All</MenuItem>
                  {(["FILE", "MAIL", "URL", "IP", "HASH", "UNKNOWN"] as const).map((t) => (
                    <MenuItem key={t} value={t}>{t}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Stack>

            <Stack direction={{ xs: "column", md: "row" }} spacing={1.25} alignItems="stretch">
              <TextField
                label="From"
                type="date"
                value={from}
                onChange={(e) => setFrom(e.target.value)}
                InputLabelProps={{ shrink: true }}
                fullWidth
              />
              <TextField
                label="To"
                type="date"
                value={to}
                onChange={(e) => setTo(e.target.value)}
                InputLabelProps={{ shrink: true }}
                fullWidth
              />

              <FormControl sx={{ minWidth: 220 }} fullWidth>
                <InputLabel id="sort-label">Sort</InputLabel>
                <Select
                  labelId="sort-label"
                  label="Sort"
                  value={sort}
                  onChange={(e) =>
                    setSort(e.target.value as "date_desc" | "date_asc" | "id_desc" | "id_asc")
                  }
                >
                  <MenuItem value="date_desc">Date (new → old)</MenuItem>
                  <MenuItem value="date_asc">Date (old → new)</MenuItem>
                  <MenuItem value="id_desc">ID (high → low)</MenuItem>
                  <MenuItem value="id_asc">ID (low → high)</MenuItem>
                </Select>
              </FormControl>
            </Stack>

            <Divider sx={{ opacity: 0.25 }} />

            <Stack
              direction={{ xs: "column", md: "row" }}
              spacing={1}
              justifyContent="space-between"
              alignItems={{ md: "center" }}
            >
              <Typography variant="body2" color="text.secondary">
                {total === 0 ? "No results" : `Showing ${start + 1}-${end} of ${total}`}
              </Typography>

              <Stack direction="row" spacing={1} alignItems="center">
                <FormControl sx={{ width: 140 }}>
                  <InputLabel id="pagesize-label">Rows</InputLabel>
                  <Select
                    labelId="pagesize-label"
                    label="Rows"
                    value={pageSize}
                    onChange={(e) => setPageSize(Number(e.target.value))}
                  >
                    {[10, 20, 50].map((n) => (
                      <MenuItem key={n} value={n}>{n}</MenuItem>
                    ))}
                  </Select>
                </FormControl>

                <Button
                  variant="outlined"
                  disabled={page === 0 || investigationsQuery.isFetching}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  sx={{ borderRadius: 2, textTransform: "none", fontWeight: 900 }}
                >
                  Prev
                </Button>
                <Button
                  variant="outlined"
                  disabled={!investigationsQuery.data?.next || investigationsQuery.isFetching}
                  onClick={() => setPage((p) => p + 1)}
                  sx={{ borderRadius: 2, textTransform: "none", fontWeight: 900 }}
                >
                  Next
                </Button>
              </Stack>
            </Stack>
          </Stack>
        </CardContent>
      </SoftCard>

      {/* ------------------------------------------------------------------ */}
      {/* Results table                                                       */}
      {/* ------------------------------------------------------------------ */}
      <SoftCard>
        <CardContent sx={{ p: 0 }}>
          {investigationsQuery.isFetching ? <LinearProgress /> : null}

          {total === 0 ? (
            <Box sx={{ p: 3 }}>
              <Alert severity="info">No investigations match your filters.</Alert>
            </Box>
          ) : (
            <Box sx={{ overflowX: "auto" }}>
              <Table sx={{ minWidth: 1120 }}>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 950 }}>ID</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>User mail</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Status</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Artifact</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Date</TableCell>
                    <TableCell sx={{ fontWeight: 950, textAlign: "right" }}>Tests</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Result</TableCell>
                  </TableRow>
                </TableHead>

                <TableBody>
                  {rows.map((r) => (
                    <TableRow
                      key={r.id}
                      hover
                      tabIndex={0}
                      sx={{ cursor: "pointer" }}
                      onClick={() => { setSelectedId(r.id); setOpenDrawer(true); }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setSelectedId(r.id);
                          setOpenDrawer(true);
                        }
                      }}
                    >
                      <TableCell>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Button
                            size="small"
                            variant="contained"
                            onClick={(e) => { e.stopPropagation(); setSelectedId(r.id); setOpenDrawer(true); }}
                            sx={{ borderRadius: 2, textTransform: "none", fontWeight: 950 }}
                          >
                            {r.id}
                          </Button>
                          <CopyIconButton text={String(r.id)} title="Copy ID" />
                          <Tooltip title="Open details">
                            <IconButton
                              size="small"
                              onClick={(e) => { e.stopPropagation(); setSelectedId(r.id); setOpenDrawer(true); }}
                            >
                              <OpenInNewOutlined fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </TableCell>

                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Typography sx={{ fontWeight: 900 }}>
                            {r.reporter_email ?? "—"}
                          </Typography>
                          {r.reporter_email ? (
                            <Tooltip title="Copy email">
                              <IconButton size="small" onClick={() => copyEmail(r.reporter_email)}>
                                <ContentCopyOutlined fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          ) : null}
                        </Stack>
                      </TableCell>

                      <TableCell>
                        <StatusChip status={r.status as any} minWidth={BADGE_W} />
                      </TableCell>

                      <TableCell title={r.info}>
                        <Tooltip title={r.info || ""} arrow placement="top">
                          <Typography
                            sx={{
                              maxWidth: 360,
                              whiteSpace: "nowrap",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              cursor: "help",
                            }}
                          >
                            {short(r.info, 72)}
                          </Typography>
                        </Tooltip>
                      </TableCell>

                      <TableCell>{fmtDate(r.created_at)}</TableCell>

                      <TableCell sx={{ textAlign: "right", fontWeight: 900 }}>
                        {r.tests_done}
                      </TableCell>

                      <TableCell>
                        <Chip
                          label={r.type}
                          size="small"
                          variant="outlined"
                          sx={{
                            fontWeight: 900,
                            minWidth: BADGE_W,
                            justifyContent: "center",
                            "& .MuiChip-label": { width: "100%", textAlign: "center" },
                          }}
                        />
                      </TableCell>

                      <TableCell>
                        <ResultChip result={r.result} minWidth={BADGE_W} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Box>
          )}
        </CardContent>
      </SoftCard>

      {/* ------------------------------------------------------------------ */}
      {/* Detail drawer                                                       */}
      {/* ------------------------------------------------------------------ */}
      <Drawer
        anchor="right"
        open={openDrawer}
        onClose={closeDrawer}
        PaperProps={{
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
        }}
      >
        {!drawerRow ? (
          <Box sx={{ p: 2 }}><Alert severity="info">Select a row.</Alert></Box>
        ) : (
          <Stack sx={{ height: "100%" }}>
            {/* Drawer header */}
            <Box
              sx={(theme) => ({
                px: 2.25,
                py: 1.75,
                borderBottom: `1px solid ${theme.palette.divider}`,
                background: `linear-gradient(
                  180deg,
                  ${alpha(theme.palette.action.hover, 0.22)} 0%,
                  ${alpha(theme.palette.background.paper, 0)} 100%
                )`,
              })}
            >
              <Stack direction="row" alignItems="flex-start" justifyContent="space-between" spacing={2}>
                <Box>
                  <Typography variant="overline" color="text.secondary">Investigation</Typography>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 0.25 }}>
                    <Typography variant="h5" fontWeight={950} lineHeight={1.1}>
                      #{drawerRow.id}
                    </Typography>
                    <CopyIconButton text={String(drawerRow.id)} title="Copy ID" />
                  </Stack>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.75 }}>
                    Created {fmtDate(drawerRow.created_at)}
                  </Typography>
                </Box>

                <Stack direction="row" spacing={1} alignItems="center">
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
                    onClick={closeDrawer}
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
            </Box>

            {/* Drawer body */}
            <Box sx={{ flex: 1, overflowY: "auto", p: 2 }}>
              <Stack spacing={2}>
                {/* Overview */}
                <Card sx={{ borderRadius: 2, border: `1px solid ${drawerCardBorder}`, background: drawerCardBg }}>
                  <CardContent sx={{ p: 2 }}>
                    <Typography variant="subtitle2" fontWeight={900} sx={{ mb: 1.25 }}>
                      Overview
                    </Typography>
                    <Box
                      sx={{
                        display: "grid",
                        gridTemplateColumns: { xs: "1fr", sm: "120px 1fr" },
                        gap: 1.25,
                      }}
                    >
                      <Typography color="text.secondary">Artifact</Typography>
                      <Typography sx={{ wordBreak: "break-word" }}>{drawerRow.info || "—"}</Typography>

                      <Typography color="text.secondary">User mail</Typography>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography sx={{ wordBreak: "break-word" }}>
                          {drawerRow.reporter_email || "—"}
                        </Typography>
                        {drawerRow.reporter_email ? (
                          <IconButton size="small" onClick={() => copyEmail(drawerRow.reporter_email)}>
                            <ContentCopyOutlined fontSize="small" />
                          </IconButton>
                        ) : null}
                      </Stack>

                      <Typography color="text.secondary">Created</Typography>
                      <Typography>{fmtDate(drawerRow.created_at)}</Typography>

                      <Typography color="text.secondary">Investigation ID</Typography>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography>{drawerRow.id}</Typography>
                        <CopyIconButton text={String(drawerRow.id)} title="Copy ID" />
                      </Stack>
                    </Box>
                  </CardContent>
                </Card>

                {/* Global override */}
                <Card sx={{ borderRadius: 2, border: `1px solid ${drawerCardBorder}`, background: drawerCardBg }}>
                  <CardContent sx={{ p: 2 }}>
                    <Typography variant="subtitle2" fontWeight={900} sx={{ mb: 1.25 }}>
                      Global override
                    </Typography>

                    {detailsQuery.isLoading ? (
                      <Stack direction="row" spacing={1} alignItems="center">
                        <CircularProgress size={18} />
                        <Typography variant="body2" color="text.secondary">Loading details…</Typography>
                      </Stack>
                    ) : detailsQuery.isError ? (
                      <Alert severity="warning">Could not load details.</Alert>
                    ) : (
                      <Stack spacing={1.25}>
                        <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                          <Chip size="small" label={`AI score: ${detailsQuery.data?.case_infos?.score_ai ?? "—"}`} variant="outlined" />
                          <Chip size="small" label={`AI confidence: ${detailsQuery.data?.case_infos?.confidence_ai ?? "—"}`} variant="outlined" />
                          <Chip size="small" label={`AI result: ${detailsQuery.data?.case_infos?.classification_ai ?? "—"}`} variant="outlined" />
                          <Chip size="small" label={`AI category: ${detailsQuery.data?.case_infos?.category_ai ?? "—"}`} variant="outlined" />
                        </Stack>

                        {!editMode ? (
                          <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                            <Chip size="small" label={`Score: ${currentScore ?? "—"} / 10`} variant="outlined" sx={{ fontWeight: 900 }} />
                            <Chip size="small" label={`Confidence: ${currentConfidence ?? "—"} %`} variant="outlined" sx={{ fontWeight: 900 }} />
                            <Chip size="small" label="Classification" variant="outlined" />
                            <ResultChip result={String(currentClassification ?? "UNKNOWN")} minWidth={BADGE_W} />
                          </Stack>
                        ) : (
                          <Stack spacing={1.25}>
                            <Stack direction={{ xs: "column", sm: "row" }} spacing={1.25}>
                              <TextField
                                label="Score (0-10)"
                                value={editScore}
                                onChange={(e) => setEditScore(e.target.value)}
                                type="number"
                                inputProps={{ min: 0, max: 10, step: 0.1 }}
                                fullWidth
                              />
                              <TextField
                                label="Confidence (0-100)"
                                value={editConfidence}
                                onChange={(e) => setEditConfidence(e.target.value)}
                                type="number"
                                inputProps={{ min: 0, max: 100, step: 0.1 }}
                                fullWidth
                              />
                            </Stack>

                            <FormControl fullWidth>
                              <InputLabel id="classification-label">Classification</InputLabel>
                              <Select
                                labelId="classification-label"
                                label="Classification"
                                value={editClassification}
                                onChange={(e) => setEditClassification(String(e.target.value))}
                              >
                                {classificationOptions.map((c) => (
                                  <MenuItem key={c} value={c}>{c}</MenuItem>
                                ))}
                              </Select>
                            </FormControl>

                            <Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: "wrap" }}>
                              <Button
                                variant="contained"
                                startIcon={<SaveOutlined />}
                                disabled={!canSave || !hasNumericSelectedId}
                                onClick={() => {
                                  if (!hasNumericSelectedId) return;
                                  editMutation.mutate({
                                    caseId: selectedIdNum,
                                    score: scoreNum,
                                    confidence: confNum,
                                    classification: editClassification,
                                  });
                                }}
                                sx={{ textTransform: "none", fontWeight: 950, borderRadius: 2 }}
                              >
                                {editMutation.isPending ? "Saving…" : "Save"}
                              </Button>
                              {editMutation.isError ? (
                                <Alert severity="error" sx={{ py: 0.5 }}>Save failed.</Alert>
                              ) : null}
                            </Stack>
                          </Stack>
                        )}
                      </Stack>
                    )}
                  </CardContent>
                </Card>

                {/* Analysis results */}
                <Card sx={{ borderRadius: 2, border: `1px solid ${drawerCardBorder}`, background: drawerCardBg }}>
                  <CardContent sx={{ p: 2 }}>
                    <Stack
                      direction={{ xs: "column", sm: "row" }}
                      justifyContent="space-between"
                      alignItems={{ xs: "flex-start", sm: "center" }}
                      spacing={1}
                      sx={{ mb: 1.25 }}
                    >
                      <Typography variant="subtitle2" fontWeight={900}>Analysis results</Typography>

                      {!detailsQuery.isLoading && !detailsQuery.isError ? (
                        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                          <Typography variant="caption" color="text.secondary">
                            {analyzerReports.length} report{analyzerReports.length === 1 ? "" : "s"}
                          </Typography>
                          {!!analyzerReports.length ? (
                            <>
                              <Button size="small" variant="outlined" onClick={expandAllAnalyzers} sx={{ textTransform: "none", borderRadius: 2, fontWeight: 800 }}>
                                Expand all
                              </Button>
                              <Button size="small" variant="outlined" onClick={collapseAllAnalyzers} sx={{ textTransform: "none", borderRadius: 2, fontWeight: 800 }}>
                                Collapse all
                              </Button>
                              <Button size="small" variant="outlined" onClick={invertAnalyzers} sx={{ textTransform: "none", borderRadius: 2, fontWeight: 800 }}>
                                Invert
                              </Button>
                            </>
                          ) : null}
                        </Stack>
                      ) : null}
                    </Stack>

                    {detailsQuery.isLoading ? (
                      <Stack direction="row" spacing={1} alignItems="center">
                        <CircularProgress size={18} />
                        <Typography variant="body2" color="text.secondary">Loading details…</Typography>
                      </Stack>
                    ) : detailsQuery.isError ? (
                      <Alert severity="warning">Could not load details.</Alert>
                    ) : !analyzerReports.length ? (
                      <Alert severity="info">No analysis details are available for this investigation yet.</Alert>
                    ) : (
                      <Stack spacing={1.25}>
                        {analyzerReports.map((report) => (
                          <InvestigationAnalyzerReportCard
                            key={report.id}
                            report={report}
                            expanded={!!expandedAnalyzerIds[report.id]}
                            onToggle={() =>
                              setExpandedAnalyzerIds((prev) => ({
                                ...prev,
                                [report.id]: !prev[report.id],
                              }))
                            }
                          />
                        ))}
                      </Stack>
                    )}
                  </CardContent>
                </Card>

                {/* Raw details */}
                <Card
                  sx={{
                    borderRadius: 2,
                    border: `1px solid ${drawerCardBorder}`,
                    background: isDark ? "rgba(255,255,255,.02)" : alpha(theme.palette.background.paper, 0.5),
                  }}
                >
                  <Accordion
                    disableGutters
                    sx={{
                      borderRadius: 2,
                      border: "none",
                      background: "transparent",
                      "&:before": { display: "none" },
                    }}
                  >
                    <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                      <Typography variant="subtitle2" fontWeight={900}>Raw details (API)</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      {detailsQuery.isLoading ? (
                        <CircularProgress size={18} />
                      ) : detailsQuery.isError ? (
                        <Alert severity="warning">Could not load details.</Alert>
                      ) : (
                        <Box
                          component="pre"
                          sx={(theme) => ({
                            m: 0, p: 1.5, borderRadius: 2,
                            border: `1px solid ${theme.palette.divider}`,
                            backgroundColor: alpha(theme.palette.action.hover, 0.55),
                            color: theme.palette.text.primary,
                            overflow: "auto", maxHeight: 320, fontSize: 12, lineHeight: 1.45,
                          })}
                        >
                          {JSON.stringify(detailsQuery.data?.raw ?? detailsQuery.data, null, 2)}
                        </Box>
                      )}
                    </AccordionDetails>
                  </Accordion>
                </Card>
              </Stack>
            </Box>
          </Stack>
        )}
      </Drawer>
    </Box>
  );
}