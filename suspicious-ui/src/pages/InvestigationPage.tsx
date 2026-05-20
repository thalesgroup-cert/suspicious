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
  TableSortLabel,
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
  RestartAltOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { alpha } from "@mui/material/styles";
import { useTheme } from "@mui/material/styles";

import { getMe, type Me } from "@/api/auth";
import {
  getAllInvestigations,
  getInvestigationDetails,
  editGlobalCase,
  buildSortOrdering,
  type InvestigationDetails,
  type InvestigationListResponse,
  type InvestigationResult,
  type InvestigationStatus,
  type InvestigationType,
} from "@/features/investigation/api";
import { useDebounced } from "@/shared/hooks/useDebounced";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import { CopyIconButton } from "@/shared/components/CopyIconButton";
import MailPreview from "@/shared/components/MailPreview";

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
// Group analyzer reports by artifact — shared with SubmissionsPage
// ---------------------------------------------------------------------------

type ReportGroup = {
  key: string;
  kind: string;
  value: string;
  reports: any[];
};

function groupReportsByArtifact(reports: any[]): ReportGroup[] {
  const order: string[] = [];
  const map: Record<string, ReportGroup> = {};
  for (const report of reports) {
    const kind  = report.target?.kind  ?? "UNKNOWN";
    const value = report.target?.value ?? "—";
    const key   = `${kind}::${value}`;
    if (!map[key]) { order.push(key); map[key] = { key, kind, value, reports: [] }; }
    map[key].reports.push(report);
  }
  return order.map((k) => map[k]);
}

function kindLabel(kind: string) {
  const labels: Record<string, string> = {
    FILE: "File", URL: "URL", IP: "IP address", HASH: "Hash",
    DOMAIN: "Domain", MAIL: "Email address",
    MAIL_BODY: "Mail body", MAIL_HEADER: "Mail header", UNKNOWN: "Unknown",
  };
  return labels[kind.toUpperCase()] ?? kind;
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
              <Typography variant="body2" sx={{ mb: 0.75, fontWeight: 800 }}>
                What this means
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                {readableSummary || plainSummary}
              </Typography>
            </Box>

            {/* Score + confidence bars */}
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
                        background: isDark
                          ? "rgba(255,255,255,.02)"
                          : alpha(theme.palette.background.paper, 0.4),
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
                        <Typography variant="body2" sx={{ fontWeight: 800 }} >Summary JSON</Typography>
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
  const [result, setResult] = React.useState<InvestigationResult | "ALL">("ALL");
  const [from, setFrom] = React.useState("");
  const [to, setTo] = React.useState("");
  const [sortField, setSortField] = React.useState<"creation_date" | "id" | "status" | "result">("creation_date");
  const [sortDir,   setSortDir]   = React.useState<"asc" | "desc">("desc");

  // Derived sort value for backwards-compat with the sort dropdown and API
  const sort = React.useMemo((): "date_desc" | "date_asc" | "id_desc" | "id_asc" => {
    if (sortField === "creation_date") return sortDir === "desc" ? "date_desc" : "date_asc";
    if (sortField === "id") return sortDir === "desc" ? "id_desc" : "id_asc";
    return sortDir === "desc" ? "date_desc" : "date_asc";
  }, [sortField, sortDir]);

  function handleColumnSort(field: "creation_date" | "id" | "status" | "result") {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("desc");
    }
    setPage(0);
  }
  const [page, setPage] = React.useState(0);
  const [pageSize, setPageSize] = React.useState(10);

  const filtersActive =
    q !== "" ||
    status !== "ALL" ||
    type !== "ALL" ||
    result !== "ALL" ||
    from !== "" ||
    to !== "" ||
    sortField !== "creation_date" ||
    sortDir !== "desc";

  const resetFilters = React.useCallback(() => {
    setQ("");
    setStatus("ALL");
    setType("ALL");
    setResult("ALL");
    setFrom("");
    setTo("");
    setSortField("creation_date");
    setSortDir("desc");
    setPage(0);
  }, []);

  const [openDrawer, setOpenDrawer] = React.useState(false);
  const [selectedId, setSelectedId] = React.useState<number | null>(null);

  const [editMode, setEditMode] = React.useState(false);
  const [editScore, setEditScore] = React.useState<string>("");
  const [editConfidence, setEditConfidence] = React.useState<string>("");
  const [editClassification, setEditClassification] = React.useState<string>("UNKNOWN");

  const [expandedAnalyzerIds, setExpandedAnalyzerIds] = React.useState<Record<number, boolean>>({});
  const [expandedGroups, setExpandedGroups] = React.useState<Record<string, boolean>>({});

  const meQuery = useQuery<Me>({ queryKey: ["me"], queryFn: getMe, retry: false });
  const me = meQuery.data;

  const groups = React.useMemo(() => me?.groups ?? [], [me]);
  const isElevated = React.useMemo(
    () => groups.includes("CISO") || groups.includes("CERT") || groups.includes("Admin"),
    [groups]
  );

  // For status/result sort fields (not covered by the dropdown "sort" presets),
  // pass the raw ordering string so the backend gets e.g. "-result".
  const investigationListParams = React.useMemo(() => {
    const needsRawOrdering = sortField === "status" || sortField === "result";
    return {
      page,
      pageSize,
      search: qDebounced,
      status,
      type,
      result,
      from,
      to,
      sort: needsRawOrdering ? "date_desc" : sort, // fallback for mapSort
      ordering: needsRawOrdering
        ? buildSortOrdering(sortField, sortDir)
        : undefined,
    };
  }, [page, pageSize, qDebounced, status, type, result, from, to, sort, sortField, sortDir]);

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

  // Deep-link URL sync (?q, ?open) — adjusted during render, runs on mount
  // and whenever the params change.
  const urlSyncKey = `${searchParams.get("q") ?? ""}|${searchParams.get("open") ?? ""}`;
  const [prevUrlSyncKey, setPrevUrlSyncKey] = React.useState<string | null>(null);
  if (urlSyncKey !== prevUrlSyncKey) {
    setPrevUrlSyncKey(urlSyncKey);
    const urlQ = searchParams.get("q") ?? "";
    if (urlQ) setQ(urlQ);
    const open = searchParams.get("open");
    if (open) {
      const idNum = Number(open);
      if (Number.isFinite(idNum)) { setSelectedId(idNum); setOpenDrawer(true); }
    }
  }

  // Reset to first page when any filter/sort changes.
  const filterKey = [qDebounced, status, type, result, from, to, sort, pageSize].join("|");
  const [prevFilterKey, setPrevFilterKey] = React.useState(filterKey);
  if (filterKey !== prevFilterKey) { setPrevFilterKey(filterKey); setPage(0); }

  // Collapse expansion when the drawer closes.
  const [prevOpenDrawer, setPrevOpenDrawer] = React.useState(openDrawer);
  if (openDrawer !== prevOpenDrawer) {
    setPrevOpenDrawer(openDrawer);
    if (!openDrawer) { setExpandedAnalyzerIds({}); setExpandedGroups({}); }
  }

  // Collapse expansion when the selected item changes.
  const [prevSelectedId, setPrevSelectedId] = React.useState(selectedId);
  if (selectedId !== prevSelectedId) {
    setPrevSelectedId(selectedId);
    setExpandedAnalyzerIds({});
    setExpandedGroups({});
  }

  // Collapse analyzer rows when a fresh set of reports arrives.
  const reportsRef = detailsQuery.data?.analyzer_reports;
  const [prevReportsRef, setPrevReportsRef] = React.useState(reportsRef);
  if (reportsRef !== prevReportsRef) { setPrevReportsRef(reportsRef); setExpandedAnalyzerIds({}); }

  // Leave edit mode + clear the mutation when switching to another case.
  const [prevSelectedIdNum, setPrevSelectedIdNum] = React.useState(selectedIdNum);
  if (selectedIdNum !== prevSelectedIdNum) {
    setPrevSelectedIdNum(selectedIdNum);
    setEditMode(false);
    editMutation.reset();
  }

  // Seed the edit form from fetched details (unless actively editing).
  const editSeedKey = `${openDrawer}|${detailsQuery.dataUpdatedAt}|${editMode}`;
  const [prevEditSeedKey, setPrevEditSeedKey] = React.useState<string | null>(null);
  if (editSeedKey !== prevEditSeedKey) {
    setPrevEditSeedKey(editSeedKey);
    if (openDrawer && detailsQuery.data && !editMode) {
      const score = pickScore(detailsQuery.data);
      const confidence = pickConfidence(detailsQuery.data);
      const classification = pickClassification(detailsQuery.data);
      setEditScore(score == null ? "" : String(score));
      setEditConfidence(confidence == null ? "" : String(confidence));
      setEditClassification(String(classification).toUpperCase());
    }
  }

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

  const analyzerReports = React.useMemo(
    () => detailsQuery.data?.analyzer_reports ?? [],
    [detailsQuery.data]
  );
  const reportGroups = React.useMemo(
    () => groupReportsByArtifact(analyzerReports),
    [analyzerReports]
  );

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
    <Skeleton
      name="investigation-page"
      loading={investigationsQuery.isPending || meQuery.isPending}
      animate="shimmer"
    >
    <Box sx={{ p: { xs: 2, md: 3 } }}>
      {/* ------------------------------------------------------------------ */}
      {/* Page header                                                         */}
      {/* ------------------------------------------------------------------ */}
      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={2}
        sx={{ mb: 2, justifyContent: "space-between" }}
      >
        <Stack spacing={0.4}>
          <Stack direction="row" spacing={1.25} sx={{ alignItems: "center" }} >
            <Avatar sx={{ width: 46, height: 46, fontWeight: 950 }}>
              {(me.username?.[0] ?? "A").toUpperCase()}
            </Avatar>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 950, letterSpacing: -0.5 }} >
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

        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
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
            <Stack direction={{ xs: "column", md: "row" }} spacing={1.25} sx={{ alignItems: "stretch" }} >
              <TextField
                value={q}
                onChange={(e) => setQ(e.target.value)}
                label="Search"
                placeholder="id, user mail, status, artifact, type, result"
                fullWidth
                slotProps={{
                  input: {
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchOutlined fontSize="small" />
                      </InputAdornment>
                    ),
                  },
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

              <FormControl sx={{ minWidth: 180 }} fullWidth>
                <InputLabel id="result-label">Result</InputLabel>
                <Select
                  labelId="result-label"
                  label="Result"
                  value={result}
                  onChange={(e) => setResult(e.target.value as InvestigationResult | "ALL")}
                >
                  <MenuItem value="ALL">All results</MenuItem>
                  {(["DANGEROUS", "SUSPICIOUS", "INCONCLUSIVE", "SAFE", "FAILURE", "UNCHALLENGED", "ALLOW_LISTED", "UNKNOWN"] as const).map((r) => (
                    <MenuItem key={r} value={r}>{r}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Stack>

            <Stack direction={{ xs: "column", md: "row" }} spacing={1.25} sx={{ alignItems: "stretch" }} >
              <TextField
                label="From"
                type="date"
                value={from}
                onChange={(e) => setFrom(e.target.value)}
                slotProps={{ inputLabel: { shrink: true } }}
                fullWidth
              />
              <TextField
                label="To"
                type="date"
                value={to}
                onChange={(e) => setTo(e.target.value)}
                slotProps={{ inputLabel: { shrink: true } }}
                fullWidth
              />

              <FormControl sx={{ minWidth: 220 }} fullWidth>
                <InputLabel id="sort-label">Sort</InputLabel>
                <Select
                  labelId="sort-label"
                  label="Sort"
                  value={sort}
                  onChange={(e) => {
                    const v = e.target.value as "date_desc" | "date_asc" | "id_desc" | "id_asc";
                    if (v === "date_desc") { setSortField("creation_date"); setSortDir("desc"); }
                    else if (v === "date_asc") { setSortField("creation_date"); setSortDir("asc"); }
                    else if (v === "id_desc") { setSortField("id"); setSortDir("desc"); }
                    else { setSortField("id"); setSortDir("asc"); }
                    setPage(0);
                  }}
                >
                  <MenuItem value="date_desc">Date (new → old)</MenuItem>
                  <MenuItem value="date_asc">Date (old → new)</MenuItem>
                  <MenuItem value="id_desc">ID (high → low)</MenuItem>
                  <MenuItem value="id_asc">ID (low → high)</MenuItem>
                </Select>
              </FormControl>

              <Tooltip title={filtersActive ? "Reset filters" : "No filters applied"}>
                <span>
                  <Button
                    variant="outlined"
                    color="inherit"
                    disabled={!filtersActive}
                    onClick={resetFilters}
                    startIcon={<RestartAltOutlined />}
                    sx={{ borderRadius: 2, textTransform: "none", fontWeight: 900, minWidth: 140 }}
                  >
                    Reset
                  </Button>
                </span>
              </Tooltip>
            </Stack>

            <Divider sx={{ opacity: 0.25 }} />

            <Stack
              direction={{ xs: "column", md: "row" }}
              spacing={1}
              sx={{ justifyContent: "space-between", alignItems: { md: "center" } }}
>
              <Typography variant="body2" color="text.secondary">
                {total === 0 ? "No results" : `Showing ${start + 1}-${end} of ${total}`}
              </Typography>

              <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
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
              <Table sx={{ minWidth: 1060 }}>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 950, width: 120 }}>
                      <TableSortLabel
                        active={sortField === "id"}
                        direction={sortField === "id" ? sortDir : "desc"}
                        onClick={() => handleColumnSort("id")}
                      >ID</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>
                      <TableSortLabel
                        active={sortField === "result"}
                        direction={sortField === "result" ? sortDir : "desc"}
                        onClick={() => handleColumnSort("result")}
                      >Result</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 950, width: 130 }}>
                      <TableSortLabel
                        active={sortField === "status"}
                        direction={sortField === "status" ? sortDir : "desc"}
                        onClick={() => handleColumnSort("status")}
                      >Status</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Artifact</TableCell>
                    <TableCell sx={{ fontWeight: 950, width: 130 }}>
                      <TableSortLabel
                        active={sortField === "creation_date"}
                        direction={sortField === "creation_date" ? sortDir : "desc"}
                        onClick={() => handleColumnSort("creation_date")}
                      >Date</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 950, width: 80 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>User mail</TableCell>
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
                      {/* ID */}
                      <TableCell>
                        <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }} >
                          <Button
                            size="small"
                            variant="contained"
                            onClick={(e) => { e.stopPropagation(); setSelectedId(r.id); setOpenDrawer(true); }}
                            sx={{ borderRadius: 2, textTransform: "none", fontWeight: 950, minWidth: 0, px: 1.25 }}
                          >
                            {r.id}
                          </Button>
                          <CopyIconButton text={String(r.id)} title="Copy ID" />
                        </Stack>
                      </TableCell>

                      {/* Result — most critical, shown first */}
                      <TableCell>
                        <ResultChip result={r.result} minWidth={BADGE_W} />
                      </TableCell>

                      {/* Status — compact, auto-sized */}
                      <TableCell>
                        <StatusChip status={r.status as any} minWidth={96} />
                      </TableCell>

                      {/* Artifact */}
                      <TableCell title={r.info}>
                        <Tooltip title={r.info || ""} arrow placement="top">
                          <Typography
                            sx={{
                              maxWidth: 320,
                              whiteSpace: "nowrap",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              cursor: "help",
                            }}
                          >
                            {short(r.info, 60)}
                          </Typography>
                        </Tooltip>
                      </TableCell>

                      {/* Date */}
                      <TableCell sx={{ whiteSpace: "nowrap" }}>{fmtDate(r.created_at)}</TableCell>

                      {/* Type — compact chip */}
                      <TableCell>
                        <Chip
                          label={r.type}
                          size="small"
                          variant="outlined"
                          sx={{ fontWeight: 900, fontSize: 11 }}
                        />
                      </TableCell>

                      {/* User mail */}
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }} >
                          <Typography variant="body2" sx={{ fontWeight: 700 }}>
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
              <Stack direction="row" spacing={2} sx={{ alignItems: "flex-start", justifyContent: "space-between" }} >
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

                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
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

            {/* Drawer body — redesigned */}
            <Box sx={{ flex: 1, overflowY: "auto" }}>

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
                      {/* Human override */}
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }} >
                        <ResultChip result={String(currentClassification ?? "UNKNOWN")} minWidth={BADGE_W} />
                        <Chip size="small" label={`Score ${currentScore ?? "—"}/10`} variant="outlined" sx={{ fontWeight: 800 }} />
                        <Chip size="small" label={`Confidence ${currentConfidence ?? "—"}%`} variant="outlined" sx={{ fontWeight: 800 }} />
                      </Stack>
                      {/* AI reference row */}
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

                {/* ── Analysis results — grouped by artifact ────────────────────── */}
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
                            {/* Group header — clickable to collapse */}
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

                            {/* Reports inside the group */}
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
          </Stack>
        )}
      </Drawer>
    </Box>
    </Skeleton>
  );
}