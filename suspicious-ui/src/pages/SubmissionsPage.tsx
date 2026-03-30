// src/pages/SubmissionsPage.tsx
import * as React from "react";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Drawer,
  FormControl,
  IconButton,
  InputAdornment,
  InputLabel,
  LinearProgress,
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
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from "@mui/material";
import {
  AssignmentTurnedInOutlined,
  SearchOutlined,
  RefreshOutlined,
  OpenInNewOutlined,
  FilterAltOutlined,
  ExpandMoreOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { alpha } from "@mui/material/styles";
import { useTheme } from "@mui/material/styles";
import { getMe, type Me } from "@/api/auth";
import {
  challengeSubmission,
  getSubmissionDetails,
  listSubmissions,
  type PaginatedSubmissionsResponse,
  type SubmissionAnalyzerReport,
  type SubmissionDetails,
  type SubmissionOrdering,
  type SubmissionResult,
  type SubmissionRow,
  type SubmissionStatus,
  type SubmissionType,
} from "@/features/submissions/api";
import { useDebounced } from "@/shared/hooks/useDebounced";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import { CopyIconButton } from "@/shared/components/CopyIconButton";

// ---------------------------------------------------------------------------
// Score / confidence helpers
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
  const t = (type ?? "").toUpperCase();
  if (t === "FILE") return "File check";
  if (t === "HASH") return "Hash check";
  if (t === "MAIL") return "Email check";
  if (t === "URL") return "Link check";
  if (t === "IP") return "IP check";
  return type || "Analyzer";
}

function prettyResult(result?: SubmissionResult) {
  switch (result) {
    case "SAFE": return "Safe";
    case "INCONCLUSIVE": return "Inconclusive";
    case "UNCHALLENGED": return "Unchallenged";
    case "ALLOW_LISTED": return "Allow listed";
    case "FAILURE": return "Failure";
    case "SUSPICIOUS": return "Suspicious";
    case "DANGEROUS": return "Dangerous";
    default: return result || "Unknown";
  }
}

function summarizeForReading(report: SubmissionAnalyzerReport) {
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

function prettySummary(summary: unknown) {
  if (!summary) return null;
  if (typeof summary === "string") return summary;
  if (Array.isArray(summary)) {
    return summary.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join("\n");
  }
  if (typeof summary === "object") {
    const obj = summary as Record<string, unknown>;
    if (typeof obj.summary === "string") return obj.summary;
    if (typeof obj.message === "string") return obj.message;
    if (typeof obj.verdict === "string") return obj.verdict;
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

function matches(row: SubmissionRow, q: string) {
  const v = q.trim().toLowerCase();
  if (!v) return true;
  return (
    String(row.id).includes(v) ||
    (row.artifact ?? "").toLowerCase().includes(v) ||
    (row.status ?? "").toLowerCase().includes(v) ||
    (row.type ?? "").toLowerCase().includes(v) ||
    (row.result ?? "").toLowerCase().includes(v)
  );
}

function withinDates(rowIso: string, from?: string, to?: string) {
  if (!from && !to) return true;
  const t = new Date(rowIso).getTime();
  if (Number.isNaN(t)) return true;

  if (from) {
    const f = new Date(from + "T00:00:00").getTime();
    if (!Number.isNaN(f) && t < f) return false;
  }
  if (to) {
    const tt = new Date(to + "T23:59:59").getTime();
    if (!Number.isNaN(tt) && t > tt) return false;
  }
  return true;
}

function toBackendOrdering(
  sort: "date_desc" | "date_asc" | "id_desc" | "id_asc"
): SubmissionOrdering {
  if (sort === "date_desc") return "-created_at";
  if (sort === "date_asc") return "created_at";
  if (sort === "id_desc") return "-id";
  return "id";
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STATUS_OPTIONS: Array<SubmissionStatus | "ALL"> = [
  "ALL", "NEW", "IN_PROGRESS", "DONE", "CHALLENGED", "UNKNOWN",
];

const TYPE_OPTIONS: Array<SubmissionType | "ALL"> = [
  "ALL", "FILE", "MAIL", "URL", "IP", "HASH", "UNKNOWN",
];

const RESULT_OPTIONS: Array<SubmissionResult | "ALL"> = [
  "ALL", "DANGEROUS", "SUSPICIOUS", "INCONCLUSIVE", "SAFE",
  "FAILURE", "UNCHALLENGED", "ALLOW_LISTED", "UNKNOWN",
];

// ---------------------------------------------------------------------------
// SoftCard — theme-aware container, identical to SubmitPage / HomePage
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
// Group analyzer reports by artifact (target.kind + target.value)
// ---------------------------------------------------------------------------

type ReportGroup = {
  key: string;
  kind: string;
  value: string;
  reports: SubmissionAnalyzerReport[];
};

function groupReportsByArtifact(
  reports: SubmissionAnalyzerReport[]
): ReportGroup[] {
  const order: string[] = [];
  const map: Record<string, ReportGroup> = {};

  for (const report of reports) {
    const kind  = report.target?.kind  ?? "UNKNOWN";
    const value = report.target?.value ?? "—";
    const key   = `${kind}::${value}`;

    if (!map[key]) {
      order.push(key);
      map[key] = { key, kind, value, reports: [] };
    }
    map[key].reports.push(report);
  }

  return order.map((k) => map[k]);
}

// Icon label for each target kind
function kindLabel(kind: string) {
  const labels: Record<string, string> = {
    FILE:        "File",
    URL:         "URL",
    IP:          "IP address",
    HASH:        "Hash",
    DOMAIN:      "Domain",
    MAIL:        "Email address",
    MAIL_BODY:   "Mail body",
    MAIL_HEADER: "Mail header",
    UNKNOWN:     "Unknown",
  };
  return labels[kind] ?? kind;
}


// ---------------------------------------------------------------------------
// AnalyzerReportCard
// ---------------------------------------------------------------------------

function AnalyzerReportCard({
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

  // In light mode, tone down the semi-transparent backgrounds so they don't
  // look washed out on white.
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
              <Typography variant="body2" fontWeight={800} sx={{ mb: 0.75 }}>
                What this means
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                {readableSummary || plainSummary}
              </Typography>
            </Box>

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
                <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                  Higher means the analyzer sees more signs of risk.
                </Typography>
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
                <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                  Higher means the analyzer is more sure about its result.
                </Typography>
              </Box>
            </Stack>

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
                        background: isDark ? "rgba(255,255,255,.02)" : alpha(theme.palette.background.paper, 0.4),
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
                        <Typography variant="body2" fontWeight={800}>Summary JSON</Typography>
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

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function SubmissionsPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const qc = useQueryClient();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const [q, setQ] = React.useState("");
  const qDebounced = useDebounced(q, 200);

  const [status, setStatus] = React.useState<SubmissionStatus | "ALL">("ALL");
  const [type, setType] = React.useState<SubmissionType | "ALL">("ALL");
  const [result, setResult] = React.useState<SubmissionResult | "ALL">("ALL");

  const [sortField, setSortField] = React.useState<"created_at" | "id" | "status" | "result" | "artifact" | "type">("created_at");
  const [sortDir,   setSortDir]   = React.useState<"asc" | "desc">("desc");

  // Derived backend ordering — maps sortField/sortDir to SubmissionOrdering
  const backendOrderingFromSort = React.useMemo((): import("@/features/submissions/api").SubmissionOrdering => {
    const prefix = sortDir === "desc" ? "-" : "";
    if (sortField === "created_at") return `${prefix}created_at` as any;
    if (sortField === "id")         return `${prefix}id` as any;
    if (sortField === "status")     return `${prefix}status` as any;
    if (sortField === "result")     return `${prefix}result` as any;
    // artifact/type have no backend ordering — fall back to date
    return "-created_at";
  }, [sortField, sortDir]);

  function handleColumnSort(field: typeof sortField) {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("desc");
    }
    setPage(0);
  }

  const [from, setFrom] = React.useState("");
  const [to, setTo] = React.useState("");
  const [sort, setSort] = React.useState<"date_desc" | "date_asc" | "id_desc" | "id_asc">("date_desc");
  const [page, setPage] = React.useState(0);
  const [pageSize, setPageSize] = React.useState(10);

  const [openDrawer, setOpenDrawer] = React.useState(false);
  const [selectedId, setSelectedId] = React.useState<number | string | null>(null);
  const [challengeId, setChallengeId] = React.useState<number | null>(null);
  const [expandedAnalyzerIds, setExpandedAnalyzerIds] = React.useState<Record<number, boolean>>({});

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  const me: Me | undefined = React.useMemo(() => meQuery.data, [meQuery.data]);

  // sort dropdown kept for backwards-compat; column clicks take precedence
  const backendOrdering = backendOrderingFromSort;

  const submissionsQuery = useQuery<PaginatedSubmissionsResponse>({
    queryKey: ["submissions", { mine: true, ordering: backendOrdering, fetchSize: 100 }],
    queryFn: async () =>
      listSubmissions({ mine: true, ordering: backendOrdering, page: 1, page_size: 100 }),
    enabled: !!me,
    retry: false,
    // placeholderData keeps isFetching:true until the real response lands,
    // so the empty-state message never fires prematurely.
    // initialData would mark the query as "successful" immediately with []
    // and show "No submissions match your filters." before the fetch completes.
    placeholderData: { count: 0, next: null, previous: null, results: [] },
    refetchInterval: (query) => {
      const rows = (query.state.data as PaginatedSubmissionsResponse | undefined)?.results ?? [];
      const shouldPoll = rows.some((r) => {
        const s = ((r.status ?? "UNKNOWN") as string).toUpperCase();
        return s === "NEW" || s === "IN_PROGRESS";
      });
      return shouldPoll ? 10_000 : false;
    },
    refetchIntervalInBackground: true,
  });

  const selectedIdNum =
    typeof selectedId === "number" ? selectedId : selectedId ? Number(selectedId) : NaN;
  const hasNumericSelectedId = Number.isFinite(selectedIdNum);

  const detailsQuery = useQuery<SubmissionDetails>({
    queryKey: ["submissionDetails", selectedIdNum],
    queryFn: async () => getSubmissionDetails(selectedIdNum),
    enabled: !!me && hasNumericSelectedId && openDrawer,
    retry: false,
    staleTime: 30_000,
    gcTime: 10 * 60_000,
    placeholderData: (prev) => prev,
  });

  const challengeMutation = useMutation({
    mutationFn: async (id: number) => challengeSubmission(id),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: ["submissions"] });
      const prevEntries = qc.getQueriesData<PaginatedSubmissionsResponse>({ queryKey: ["submissions"] });
      prevEntries.forEach(([key, prev]) => {
        if (!prev) return;
        qc.setQueryData<PaginatedSubmissionsResponse>(key, {
          ...prev,
          results: prev.results.map((r) =>
            r.id === id ? { ...r, is_challenged: true, is_challengeable: false } : r
          ),
        });
      });
      return { prevEntries };
    },
    onError: (_err, _id, ctx) => {
      ctx?.prevEntries?.forEach(([key, data]) => { qc.setQueryData(key, data); });
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["submissions"] });
      qc.invalidateQueries({ queryKey: ["submissionDetails"] });
    },
    onSuccess: () => setChallengeId(null),
  });

  React.useEffect(() => {
    const urlQ = searchParams.get("q") ?? "";
    const open = searchParams.get("open");
    if (urlQ) setQ(urlQ);
    if (open) {
      const idNum = Number(open);
      if (!Number.isNaN(idNum)) {
        setSelectedId(idNum);
        setOpenDrawer(true);
      }
    }
  }, [searchParams]);

  React.useEffect(() => { setPage(0); }, [qDebounced, status, type, result, from, to, sort, sortField, sortDir, pageSize]);
  React.useEffect(() => { if (!openDrawer) setExpandedAnalyzerIds({}); }, [openDrawer]);
  React.useEffect(() => { setExpandedAnalyzerIds({}); }, [selectedId]);
  React.useEffect(() => { setExpandedAnalyzerIds({}); }, [detailsQuery.data?.analyzer_reports]);

  const rows = submissionsQuery.data?.results ?? [];
  // Client-side sort for artifact/type fields (not supported by backend ordering)
  const clientSorted = React.useMemo(() => {
    if (sortField !== "artifact" && sortField !== "type") return rows;
    return [...rows].sort((a, b) => {
      const va = (sortField === "artifact" ? a.artifact : a.type) ?? "";
      const vb = (sortField === "artifact" ? b.artifact : b.type) ?? "";
      const cmp = va.localeCompare(vb);
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [rows, sortField, sortDir]);

  const filtered = clientSorted
    .filter((r) => matches(r, qDebounced))
    .filter((r) => (status === "ALL" ? true : r.status === status))
    .filter((r) => (type === "ALL" ? true : r.type === type))
    .filter((r) => (result === "ALL" ? true : r.result === result))
    .filter((r) => withinDates(r.created_at, from || undefined, to || undefined));

  const total = filtered.length;
  const start = page * pageSize;
  const end = Math.min(total, start + pageSize);
  const pageRows = filtered.slice(start, end);
  const selectedRow = selectedId ? rows.find((r) => String(r.id) === String(selectedId)) : undefined;

  // ── Derived values and callbacks ────────────────────────────────────────
  // Must be declared BEFORE any early returns to satisfy Rules of Hooks.

  const BADGE_W = 132;
  const DIALOG_RADIUS = 2;

  const analyzerReports = detailsQuery.data?.analyzer_reports ?? [];
  const hasRawDetails = typeof detailsQuery.data?.raw !== "undefined";

  // Group reports by artifact so the drawer shows one section per checked item
  const reportGroups = React.useMemo(
    () => groupReportsByArtifact(analyzerReports),
    [analyzerReports]
  );

  const expandAllAnalyzers = React.useCallback(() => {
    setExpandedAnalyzerIds(Object.fromEntries(analyzerReports.map((r) => [r.id, true])));
  }, [analyzerReports]);

  const collapseAllAnalyzers = React.useCallback(() => {
    setExpandedAnalyzerIds({});
  }, []);

  const invertAnalyzers = React.useCallback(() => {
    setExpandedAnalyzerIds((prev) =>
      Object.fromEntries(analyzerReports.map((r) => [r.id, !prev[r.id]]))
    );
  }, [analyzerReports]);

  // Theme-aware values used in the drawer and inline cards
  const drawerCardBorder = isDark ? "rgba(255,255,255,.08)" : alpha(theme.palette.divider, 0.6);
  const drawerCardBg = isDark ? "rgba(255,255,255,.025)" : alpha(theme.palette.background.paper, 0.7);
  const refreshBtnBorder = isDark
    ? "1px solid rgba(255,255,255,.10)"
    : `1px solid ${alpha(theme.palette.divider, 0.6)}`;

  // ── Early returns (AFTER all hooks) ─────────────────────────────────────

  // With placeholderData, isLoading is always false. Use isFetching + no real
  // data yet to detect the true initial load so we show a spinner, not empty state.
  const submissionsLoading =
    submissionsQuery.isFetching && submissionsQuery.data?.results.length === 0;

  if (meQuery.isLoading || submissionsLoading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me) {
    return <Box sx={{ p: 3 }}><Alert severity="error">Not authenticated.</Alert></Box>;
  }

  if (submissionsQuery.isError) {
    return <Box sx={{ p: 3 }}><Alert severity="error">Failed to load submissions.</Alert></Box>;
  }

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
              {(me.username?.[0] ?? "U").toUpperCase()}
            </Avatar>
            <Box>
              <Typography variant="h4" fontWeight={950} letterSpacing={-0.5}>
                Submissions
              </Typography>
              <Typography color="text.secondary">
                Review your submitted files, checks, and results in plain language.
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
            <Chip icon={<AssignmentTurnedInOutlined />} label={`${total} shown`} variant="outlined" />
            <Chip icon={<FilterAltOutlined />} label="Filters available" variant="outlined" />
            {qDebounced ? <Chip label={`Search: ${qDebounced}`} variant="outlined" /> : null}
            {(submissionsQuery.data?.count ?? 0) > rows.length ? (
              <Chip
                label={`Loaded ${rows.length} of ${submissionsQuery.data?.count ?? 0}`}
                variant="outlined"
                color="warning"
              />
            ) : null}
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
            onClick={() => submissionsQuery.refetch()}
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
                placeholder="id, status, artifact, type, result"
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
                  onChange={(e) => setStatus(e.target.value as SubmissionStatus | "ALL")}
                >
                  {STATUS_OPTIONS.map((s) => (
                    <MenuItem key={s} value={s}>{s === "ALL" ? "All" : s}</MenuItem>
                  ))}
                </Select>
              </FormControl>

              <FormControl sx={{ minWidth: 160 }} fullWidth>
                <InputLabel id="type-label">Type</InputLabel>
                <Select
                  labelId="type-label"
                  label="Type"
                  value={type}
                  onChange={(e) => setType(e.target.value as SubmissionType | "ALL")}
                >
                  {TYPE_OPTIONS.map((t) => (
                    <MenuItem key={t} value={t}>{t === "ALL" ? "All" : t}</MenuItem>
                  ))}
                </Select>
              </FormControl>

              <FormControl sx={{ minWidth: 180 }} fullWidth>
                <InputLabel id="result-label">Result</InputLabel>
                <Select
                  labelId="result-label"
                  label="Result"
                  value={result}
                  onChange={(e) => setResult(e.target.value as SubmissionResult | "ALL")}
                >
                  {RESULT_OPTIONS.map((r) => (
                    <MenuItem key={r} value={r}>{r === "ALL" ? "All results" : r}</MenuItem>
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
                  onChange={(e) => {
                    const v = e.target.value as "date_desc" | "date_asc" | "id_desc" | "id_asc";
                    setSort(v);
                    if (v === "date_desc") { setSortField("created_at"); setSortDir("desc"); }
                    else if (v === "date_asc") { setSortField("created_at"); setSortDir("asc"); }
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
                  disabled={page === 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  sx={{ borderRadius: 2, textTransform: "none", fontWeight: 900 }}
                >
                  Prev
                </Button>
                <Button
                  variant="outlined"
                  disabled={end >= total}
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
          {total === 0 && !submissionsQuery.isFetching ? (
            <Box sx={{ p: 3 }}>
              <Alert severity="info">No submissions match your filters.</Alert>
            </Box>
          ) : (
            <Box sx={{ overflowX: "auto" }}>
              <Table sx={{ minWidth: 1020 }}>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 950, width: 140 }}>
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
                    <TableCell sx={{ fontWeight: 950, width: 120 }}>
                      <TableSortLabel
                        active={sortField === "status"}
                        direction={sortField === "status" ? sortDir : "desc"}
                        onClick={() => handleColumnSort("status")}
                      >Status</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>
                      <TableSortLabel
                        active={sortField === "artifact"}
                        direction={sortField === "artifact" ? sortDir : "asc"}
                        onClick={() => handleColumnSort("artifact")}
                      >Artifact</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 950, width: 130 }}>
                      <TableSortLabel
                        active={sortField === "created_at"}
                        direction={sortField === "created_at" ? sortDir : "desc"}
                        onClick={() => handleColumnSort("created_at")}
                      >Date</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 950, textAlign: "right", width: 60 }}>Tests</TableCell>
                    <TableCell sx={{ fontWeight: 950, width: 80 }}>
                      <TableSortLabel
                        active={sortField === "type"}
                        direction={sortField === "type" ? sortDir : "asc"}
                        onClick={() => handleColumnSort("type")}
                      >Type</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Challenge</TableCell>
                  </TableRow>
                </TableHead>

                <TableBody>
                  {pageRows.map((r) => {
                    const canChallenge = !!r.is_challengeable && !r.is_challenged;

                    return (
                      <TableRow
                        key={r.id}
                        hover
                        tabIndex={0}
                        sx={{ cursor: "pointer" }}
                        onClick={() => { setSelectedId(r.id); setOpenDrawer(true); }}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            setSelectedId(r.id);
                            setOpenDrawer(true);
                          }
                        }}
                      >
                        {/* ID */}
                        <TableCell>
                          <Stack direction="row" spacing={0.5} alignItems="center">
                            <Button
                              size="small"
                              variant="contained"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedId(r.id);
                                setOpenDrawer(true);
                              }}
                              sx={{ borderRadius: 2, textTransform: "none", fontWeight: 950, minWidth: 0, px: 1.25 }}
                            >
                              {r.id}
                            </Button>
                            <CopyIconButton text={String(r.id)} title="Copy ID" />
                          </Stack>
                        </TableCell>

                        {/* Result — most critical, shown immediately after ID */}
                        <TableCell>
                          <ResultChip result={r.result} minWidth={BADGE_W} />
                        </TableCell>

                        {/* Status — compact */}
                        <TableCell>
                          <StatusChip status={r.status} minWidth={96} />
                        </TableCell>

                        {/* Artifact */}
                        <TableCell title={r.artifact}>
                          <Tooltip title={r.artifact || ""} arrow placement="top">
                            <Typography
                              sx={{
                                maxWidth: 320,
                                whiteSpace: "nowrap",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                cursor: "help",
                              }}
                            >
                              {short(r.artifact, 60)}
                            </Typography>
                          </Tooltip>
                        </TableCell>

                        {/* Date */}
                        <TableCell sx={{ whiteSpace: "nowrap" }}>{fmtDate(r.created_at)}</TableCell>

                        {/* Tests */}
                        <TableCell sx={{ textAlign: "right", fontWeight: 900 }}>
                          {r.tests_done}
                        </TableCell>

                        {/* Type — compact chip */}
                        <TableCell>
                          <Chip
                            label={r.type}
                            size="small"
                            variant="outlined"
                            sx={{ fontWeight: 900, fontSize: 11 }}
                          />
                        </TableCell>

                        <TableCell onClick={(e) => e.stopPropagation()}>
                          {canChallenge ? (
                            <Button
                              size="small"
                              variant="outlined"
                              disabled={challengeMutation.isPending}
                              onClick={() => setChallengeId(r.id)}
                              sx={{ borderRadius: 2, textTransform: "none", fontWeight: 950 }}
                            >
                              Challenge
                            </Button>
                          ) : (
                            <Typography variant="body2" color="text.secondary">
                              Not available
                            </Typography>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
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
        onClose={() => setOpenDrawer(false)}
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
          }),
        }}
      >
        {!selectedRow ? (
          <Box sx={{ p: 2 }}>
            <Alert severity="info">Select a row.</Alert>
          </Box>
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
                  <Typography variant="overline" color="text.secondary">Submission</Typography>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 0.25 }}>
                    <Typography variant="h5" fontWeight={950} lineHeight={1.1}>
                      #{selectedRow.id}
                    </Typography>
                    <CopyIconButton text={String(selectedRow.id)} title="Copy ID" />
                  </Stack>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.75 }}>
                    Created {fmtDate(selectedRow.created_at)}
                  </Typography>
                </Box>
                <Button
                  onClick={() => setOpenDrawer(false)}
                  sx={{ textTransform: "none", borderRadius: 2, alignSelf: "flex-start" }}
                >
                  Close
                </Button>
              </Stack>

              <Stack direction="row" spacing={1} sx={{ mt: 1.75, flexWrap: "wrap" }}>
                <StatusChip status={selectedRow.status} minWidth={BADGE_W} />
                <Chip
                  size="small"
                  label={selectedRow.type}
                  variant="outlined"
                  sx={{
                    fontWeight: 900,
                    minWidth: BADGE_W,
                    justifyContent: "center",
                    "& .MuiChip-label": { width: "100%", textAlign: "center" },
                  }}
                />
                <ResultChip result={selectedRow.result} minWidth={BADGE_W} />
                <Chip
                  size="small"
                  label={`${selectedRow.tests_done} tests`}
                  variant="outlined"
                  sx={{ fontWeight: 900 }}
                />
              </Stack>
            </Box>

            {/* Drawer body */}
            <Box sx={{ flex: 1, overflowY: "auto", p: 2 }}>
              <Stack spacing={2}>
                {/* Overview card */}
                <Card
                  sx={{
                    borderRadius: 2,
                    border: `1px solid ${drawerCardBorder}`,
                    background: drawerCardBg,
                  }}
                >
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
                      <Typography sx={{ wordBreak: "break-word" }}>
                        {selectedRow.artifact || "—"}
                      </Typography>

                      <Typography color="text.secondary">Created</Typography>
                      <Typography>{fmtDate(selectedRow.created_at)}</Typography>

                      <Typography color="text.secondary">Submission ID</Typography>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography>{selectedRow.id}</Typography>
                        <CopyIconButton text={String(selectedRow.id)} title="Copy ID" />
                      </Stack>
                    </Box>
                  </CardContent>
                </Card>

                {/* Analysis results card */}
                <Card
                  sx={{
                    borderRadius: 2,
                    border: `1px solid ${drawerCardBorder}`,
                    background: drawerCardBg,
                  }}
                >
                  <CardContent sx={{ p: 2 }}>
                    <Stack
                      direction={{ xs: "column", sm: "row" }}
                      justifyContent="space-between"
                      alignItems={{ xs: "flex-start", sm: "center" }}
                      spacing={1}
                      sx={{ mb: 1.25 }}
                    >
                      <Typography variant="subtitle2" fontWeight={900}>
                        Analysis results
                      </Typography>

                      {!detailsQuery.isLoading && !detailsQuery.isError ? (
                        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                          <Typography variant="caption" color="text.secondary">
                            {detailsQuery.data?.analyzer_reports?.length ?? 0} report
                            {(detailsQuery.data?.analyzer_reports?.length ?? 0) === 1 ? "" : "s"}
                          </Typography>

                          {!!analyzerReports.length ? (
                            <>
                              <Button
                                size="small"
                                variant="outlined"
                                onClick={expandAllAnalyzers}
                                sx={{ textTransform: "none", borderRadius: 2, fontWeight: 800 }}
                              >
                                Expand all
                              </Button>
                              <Button
                                size="small"
                                variant="outlined"
                                onClick={collapseAllAnalyzers}
                                sx={{ textTransform: "none", borderRadius: 2, fontWeight: 800 }}
                              >
                                Collapse all
                              </Button>
                              <Button
                                size="small"
                                variant="outlined"
                                onClick={invertAnalyzers}
                                sx={{ textTransform: "none", borderRadius: 2, fontWeight: 800 }}
                              >
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
                        <Typography variant="body2" color="text.secondary">
                          Loading details…
                        </Typography>
                      </Stack>
                    ) : detailsQuery.isError ? (
                      <Alert severity="warning">Could not load details.</Alert>
                    ) : !detailsQuery.data?.analyzer_reports?.length ? (
                      <Alert severity="info">
                        No analysis details are available for this submission yet.
                      </Alert>
                    ) : (
                      <Stack spacing={2}>
                        {reportGroups.map((group) => (
                          <Box key={group.key}>
                            {/* Artifact group header */}
                            <Stack
                              direction="row"
                              spacing={1}
                              alignItems="center"
                              sx={{ mb: 1 }}
                            >
                              <Box
                                sx={{
                                  px: 1,
                                  py: 0.3,
                                  borderRadius: 1.5,
                                  fontSize: 10.5,
                                  fontWeight: 800,
                                  letterSpacing: "0.05em",
                                  textTransform: "uppercase",
                                  bgcolor: isDark
                                    ? "rgba(255,255,255,.07)"
                                    : alpha(theme.palette.primary.main, 0.08),
                                  color: isDark
                                    ? "text.secondary"
                                    : "primary.main",
                                  border: `1px solid ${isDark
                                    ? "rgba(255,255,255,.12)"
                                    : alpha(theme.palette.primary.main, 0.2)}`,
                                  flexShrink: 0,
                                }}
                              >
                                {kindLabel(group.kind)}
                              </Box>
                              <Typography
                                variant="body2"
                                fontWeight={700}
                                sx={{
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                  minWidth: 0,
                                  flex: 1,
                                }}
                                title={group.value}
                              >
                                {group.value}
                              </Typography>
                              <Typography
                                variant="caption"
                                color="text.disabled"
                                sx={{ flexShrink: 0 }}
                              >
                                {group.reports.length} analyzer{group.reports.length === 1 ? "" : "s"}
                              </Typography>
                            </Stack>

                            {/* Reports for this artifact */}
                            <Stack spacing={1}>
                              {group.reports.map((report) => (
                                <AnalyzerReportCard
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
                          </Box>
                        ))}
                      </Stack>
                    )}
                  </CardContent>
                </Card>

                {/* Raw details */}
                {hasRawDetails ? (
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
                        <Typography variant="subtitle2" fontWeight={900}>
                          Raw details (admin/debug)
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Box
                          component="pre"
                          sx={(theme) => ({
                            m: 0,
                            p: 1.5,
                            borderRadius: 2,
                            border: `1px solid ${theme.palette.divider}`,
                            backgroundColor: alpha(theme.palette.action.hover, 0.55),
                            color: theme.palette.text.primary,
                            overflow: "auto",
                            maxHeight: 320,
                            fontSize: 12,
                            lineHeight: 1.45,
                          })}
                        >
                          {JSON.stringify(detailsQuery.data?.raw, null, 2)}
                        </Box>
                      </AccordionDetails>
                    </Accordion>
                  </Card>
                ) : null}
              </Stack>
            </Box>
          </Stack>
        )}
      </Drawer>

      {/* ------------------------------------------------------------------ */}
      {/* Challenge dialog                                                    */}
      {/* ------------------------------------------------------------------ */}
      <Dialog
        open={challengeId !== null}
        onClose={() => setChallengeId(null)}
        maxWidth="xs"
        fullWidth
        PaperProps={{ sx: { borderRadius: DIALOG_RADIUS } }}
      >
        <DialogTitle>Challenge submission</DialogTitle>
        <DialogContent>
          <Typography color="text.secondary">
            Submit a challenge request for submission #{challengeId}.
          </Typography>
          {challengeMutation.isError ? (
            <Alert severity="error" sx={{ mt: 2 }}>Failed to challenge.</Alert>
          ) : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setChallengeId(null)} sx={{ borderRadius: 2 }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            disabled={challengeMutation.isPending || challengeId === null}
            onClick={() => { if (challengeId) challengeMutation.mutate(challengeId); }}
            sx={{ textTransform: "none", fontWeight: 950, borderRadius: 2 }}
          >
            {challengeMutation.isPending ? "Sending…" : "Confirm"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}