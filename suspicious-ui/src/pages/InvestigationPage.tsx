// src/pages/InvestigationPage.tsx
import * as React from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  alpha,
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

import { getMe, type Me } from "@/api/auth";
import {
  getAllInvestigations,
  getInvestigationDetails,
  editGlobalCase,
  type InvestigationDetails,
  type InvestigationRow,
  type InvestigationStatus,
  type InvestigationType,
  type InvestigationAnalyzerReport,
} from "@/features/investigation/api";

import { useDebounced } from "@/shared/hooks/useDebounced";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import { CopyIconButton } from "@/shared/components/CopyIconButton";

type InvestigationResponse = { items: InvestigationRow[] };

function GlassCard(props: React.PropsWithChildren<{ sx?: any }>) {
  return (
    <Card
      sx={{
        borderRadius: 2,
        border: "1px solid rgba(255,255,255,.10)",
        background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
        ...props.sx,
      }}
    >
      {props.children}
    </Card>
  );
}

function fmtDate(iso: string) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

function short(s: string, n = 42) {
  const t = (s ?? "").trim();
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
}

function matches(row: InvestigationRow, q: string) {
  const v = q.trim().toLowerCase();
  if (!v) return true;
  return (
    String(row.id).includes(v) ||
    (row.reporter_email ?? "").toLowerCase().includes(v) ||
    (row.info ?? "").toLowerCase().includes(v) ||
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
    const f = new Date(`${from}T00:00:00`).getTime();
    if (!Number.isNaN(f) && t < f) return false;
  }
  if (to) {
    const tt = new Date(`${to}T23:59:59`).getTime();
    if (!Number.isNaN(tt) && t > tt) return false;
  }
  return true;
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

  if (targetValue) {
    parts.push(`Checked item: ${targetValue}.`);
  }

  if (categories.length) {
    parts.push(`Detected type: ${categories.join(", ")}.`);
  }

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

function InvestigationAnalyzerReportCard({
  report,
  expanded,
  onToggle,
}: {
  report: any;
  expanded: boolean;
  onToggle: () => void;
}) {
  const risk = getRiskTone(report.score);
  const confidence = getConfidenceTone(report.confidence);

  const scorePct = normalizeScore(report.score);
  const confidencePct = normalizeConfidence(report.confidence);

  const readableSummary = prettySummary(report.report_summary);
  const plainSummary = summarizeForReading(report);

  return (
    <Card
      sx={{
        borderRadius: 3,
        border: `1px solid ${risk.softBorder}`,
        background: `linear-gradient(180deg, ${risk.softBg} 0%, rgba(255,255,255,.03) 100%)`,
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
          borderBottom: expanded ? "1px solid rgba(255,255,255,.08)" : "none",
          background: "rgba(255,255,255,.03)",
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
                border: "1px solid rgba(255,255,255,.12)",
                backgroundColor: "rgba(255,255,255,.04)",
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
                border: "1px solid rgba(255,255,255,.08)",
                background: "rgba(255,255,255,.03)",
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
                  <Typography variant="body2" fontWeight={700}>
                    Risk score
                  </Typography>
                  <Typography variant="body2" fontWeight={900}>
                    {typeof report.score === "number"
                      ? report.score.toFixed(report.score <= 10 ? 1 : 0)
                      : "—"}
                  </Typography>
                </Stack>

                <LinearProgress
                  variant="determinate"
                  value={scorePct}
                  sx={{
                    height: 10,
                    borderRadius: 999,
                    ...risk.barSx,
                  }}
                />
              </Box>

              <Box>
                <Stack direction="row" justifyContent="space-between" sx={{ mb: 0.5 }}>
                  <Typography variant="body2" fontWeight={700}>
                    Confidence
                  </Typography>
                  <Typography variant="body2" fontWeight={900}>
                    {Math.round(confidencePct)}%
                  </Typography>
                </Stack>

                <LinearProgress
                  variant="determinate"
                  value={confidencePct}
                  sx={{
                    height: 10,
                    borderRadius: 999,
                    ...confidence.barSx,
                  }}
                />
              </Box>
            </Stack>

            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: { xs: "1fr", sm: "140px 1fr" },
                gap: 1,
                p: 1.5,
                borderRadius: 2,
                border: "1px solid rgba(255,255,255,.08)",
                background: "rgba(255,255,255,.02)",
              }}
            >
              <Typography color="text.secondary" variant="body2">
                Checked item
              </Typography>
              <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
                {report.target?.value || "—"}
              </Typography>

              <Typography color="text.secondary" variant="body2">
                Item type
              </Typography>
              <Typography variant="body2">
                {report.target?.kind || "—"}
              </Typography>

              <Typography color="text.secondary" variant="body2">
                Categories
              </Typography>
              <Typography variant="body2">
                {report.categories?.length ? report.categories.join(", ") : "None listed"}
              </Typography>

              <Typography color="text.secondary" variant="body2">
                Finished
              </Typography>
              <Typography variant="body2">
                {report.created_at ? fmtDate(report.created_at) : "—"}
              </Typography>
            </Box>

            <Accordion
              disableGutters
              sx={{
                borderRadius: 2,
                border: "1px solid rgba(255,255,255,.08)",
                background: "rgba(255,255,255,.02)",
                "&:before": { display: "none" },
              }}
            >
              <AccordionSummary
                expandIcon={<ExpandMoreOutlined />}
                onClick={(e) => e.stopPropagation()}
              >
                <Typography variant="body2" fontWeight={800}>
                  Technical details
                </Typography>
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
                    <Typography color="text.secondary" variant="body2">
                      Analyzer ID
                    </Typography>
                    <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
                      {report.analyzer_id || "—"}
                    </Typography>

                    <Typography color="text.secondary" variant="body2">
                      Job ID
                    </Typography>
                    <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
                      {report.cortex_job_id || "—"}
                    </Typography>

                    <Typography color="text.secondary" variant="body2">
                      Level
                    </Typography>
                    <Typography variant="body2">
                      {report.level || "—"}
                    </Typography>

                    <Typography color="text.secondary" variant="body2">
                      Status
                    </Typography>
                    <Typography variant="body2">
                      {report.status || "—"}
                    </Typography>
                  </Box>

                  {report.report_taxonomy ? (
                    <Accordion
                      disableGutters
                      sx={{
                        borderRadius: 2,
                        border: "1px solid rgba(255,255,255,.08)",
                        background: "rgba(255,255,255,.02)",
                        "&:before": { display: "none" },
                      }}
                    >
                      <AccordionSummary
                        expandIcon={<ExpandMoreOutlined />}
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Typography variant="body2" fontWeight={800}>
                          Taxonomy JSON
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails onClick={(e) => e.stopPropagation()}>
                        <Box
                          component="pre"
                          sx={{
                            m: 0,
                            p: 1.25,
                            borderRadius: 2,
                            border: "1px solid rgba(255,255,255,.08)",
                            background: "rgba(0,0,0,.22)",
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
                        border: "1px solid rgba(255,255,255,.08)",
                        background: "rgba(255,255,255,.02)",
                        "&:before": { display: "none" },
                      }}
                    >
                      <AccordionSummary
                        expandIcon={<ExpandMoreOutlined />}
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Typography variant="body2" fontWeight={800}>
                          Summary JSON
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails onClick={(e) => e.stopPropagation()}>
                        <Box
                          component="pre"
                          sx={{
                            m: 0,
                            p: 1.25,
                            borderRadius: 2,
                            border: "1px solid rgba(255,255,255,.08)",
                            background: "rgba(0,0,0,.22)",
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
export default function InvestigationPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const qc = useQueryClient();

  const [q, setQ] = React.useState("");
  const qDebounced = useDebounced(q, 200);

  const [status, setStatus] = React.useState<InvestigationStatus | "ALL">("ALL");
  const [type, setType] = React.useState<InvestigationType | "ALL">("ALL");
  const [from, setFrom] = React.useState("");
  const [to, setTo] = React.useState("");
  const [sort, setSort] = React.useState<"date_desc" | "date_asc" | "id_desc" | "id_asc">("date_desc");
  const [page, setPage] = React.useState(0);
  const [pageSize, setPageSize] = React.useState(10);

  const [openDrawer, setOpenDrawer] = React.useState(false);
  const [selectedId, setSelectedId] = React.useState<number | string | null>(null);

  const [editMode, setEditMode] = React.useState(false);
  const [editScore, setEditScore] = React.useState<string>("");
  const [editConfidence, setEditConfidence] = React.useState<string>("");
  const [editClassification, setEditClassification] = React.useState<string>("UNKNOWN");

  const [expandedAnalyzerIds, setExpandedAnalyzerIds] = React.useState<Record<number, boolean>>({});

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  const me: Me | undefined = React.useMemo(() => meQuery.data, [meQuery.data]);

  const groups = React.useMemo(() => me?.groups ?? [], [me]);
  const isElevated = React.useMemo(
    () => groups.includes("CISO") || groups.includes("CERT") || groups.includes("Admin"),
    [groups]
  );

  const investigationsQuery = useQuery<InvestigationResponse>({
    queryKey: ["investigation"],
    queryFn: async () => getAllInvestigations(),
    enabled: !!me && isElevated,
    retry: false,
    initialData: { items: [] },
    refetchInterval: (query) => {
      const items = (query.state.data as InvestigationResponse | undefined)?.items ?? [];
      const shouldPoll = items.some((r) => {
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

  const detailsQuery = useQuery<InvestigationDetails>({
    queryKey: ["investigationDetails", selectedIdNum],
    queryFn: async () => getInvestigationDetails(selectedIdNum),
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
      if (!Number.isNaN(idNum)) {
        setSelectedId(idNum);
        setOpenDrawer(true);
      }
    }
  }, [searchParams]);

  React.useEffect(() => {
    setPage(0);
  }, [qDebounced, status, type, from, to, sort, pageSize]);

  React.useEffect(() => {
    if (!openDrawer) {
      setExpandedAnalyzerIds({});
    }
  }, [openDrawer]);

  React.useEffect(() => {
    setExpandedAnalyzerIds({});
  }, [selectedId]);

  React.useEffect(() => {
    setExpandedAnalyzerIds({});
  }, [detailsQuery.data?.analyzer_reports]);

  const rows = investigationsQuery.data?.items ?? [];

  const filtered = rows
    .filter((r) => matches(r, qDebounced))
    .filter((r) => (status === "ALL" ? true : r.status === status))
    .filter((r) => (type === "ALL" ? true : r.type === type))
    .filter((r) => withinDates(r.created_at, from || undefined, to || undefined));

  const sorted = [...filtered].sort((a, b) => {
    const ta = new Date(a.created_at).getTime();
    const tb = new Date(b.created_at).getTime();

    if (sort === "date_desc") return (Number.isFinite(tb) ? tb : 0) - (Number.isFinite(ta) ? ta : 0);
    if (sort === "date_asc") return (Number.isFinite(ta) ? ta : 0) - (Number.isFinite(tb) ? tb : 0);
    if (sort === "id_desc") return b.id - a.id;
    return a.id - b.id;
  });

  const total = sorted.length;
  const start = page * pageSize;
  const end = Math.min(total, start + pageSize);
  const pageRows = sorted.slice(start, end);

  const selectedRow = selectedId ? rows.find((r) => String(r.id) === String(selectedId)) : undefined;

  function closeDrawer() {
    setOpenDrawer(false);
    setEditMode(false);
    editMutation.reset();
  }

  React.useEffect(() => {
    setEditMode(false);
    editMutation.reset();
  }, [selectedIdNum]); // eslint-disable-line react-hooks/exhaustive-deps

  React.useEffect(() => {
    if (!openDrawer) return;
    if (!detailsQuery.data) return;

    const score = pickScore(detailsQuery.data);
    const confidence = pickConfidence(detailsQuery.data);
    const classification = pickClassification(detailsQuery.data);

    if (!editMode) {
      setEditScore(score == null ? "" : String(score));
      setEditConfidence(confidence == null ? "" : String(confidence));
      setEditClassification(String(classification).toUpperCase());
    }
  }, [openDrawer, detailsQuery.data, editMode]);

  if (meQuery.isLoading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Not authenticated.</Alert>
      </Box>
    );
  }

  if (!isElevated) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Access denied.</Alert>
      </Box>
    );
  }

  if (investigationsQuery.isLoading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (investigationsQuery.isError) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Failed to load investigations (API route / permissions).</Alert>
      </Box>
    );
  }

  const BADGE_W = 132;
  const DRAWER_RADIUS = 2;

  const classificationOptions = [
    "SAFE",
    "INCONCLUSIVE",
    "UNCHALLENGED",
    "ALLOW_LISTED",
    "FAILURE",
    "SUSPICIOUS",
    "DANGEROUS",
    "UNKNOWN",
  ];

  const scoreNum = Number(editScore);
  const confNum = Number(editConfidence);
  const scoreValid = Number.isFinite(scoreNum) && scoreNum >= 0 && scoreNum <= 10;
  const confValid = Number.isFinite(confNum) && confNum >= 0 && confNum <= 100;
  const canSave = scoreValid && confValid && !!editClassification && !editMutation.isPending;

  async function copyEmail(email?: string) {
    if (!email) return;
    try {
      await navigator.clipboard.writeText(email);
    } catch {
      // ignore
    }
  }

  const detailsReady = !!detailsQuery.data && !detailsQuery.isLoading && !detailsQuery.isError;

  const currentScore = pickScore(detailsQuery.data);
  const currentConfidence = pickConfidence(detailsQuery.data);
  const currentClassification = pickClassification(detailsQuery.data);

  const analyzerReports = detailsQuery.data?.analyzer_reports ?? [];

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

  return (
    <Box sx={{ p: { xs: 2, md: 3 } }}>
      <Stack direction={{ xs: "column", md: "row" }} spacing={2} justifyContent="space-between" sx={{ mb: 2 }}>
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
            <Chip icon={<AssignmentTurnedInOutlined />} label={`${total} shown`} variant="outlined" />
            <Chip icon={<FilterAltOutlined />} label="Filters available" variant="outlined" />
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
            sx={{ border: "1px solid rgba(255,255,255,.10)", borderRadius: 2 }}
          >
            <RefreshOutlined />
          </IconButton>
        </Stack>
      </Stack>

      <GlassCard sx={{ mb: 2 }}>
        <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
          <Stack spacing={1.5}>
            <Stack direction={{ xs: "column", md: "row" }} spacing={1.25} alignItems="stretch">
              <TextField
                value={q}
                onChange={(e) => setQ(e.target.value)}
                label="Search"
                placeholder="id, user mail, status, info, type, result"
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
                  onChange={(e) => setStatus(e.target.value as any)}
                >
                  <MenuItem value="ALL">All</MenuItem>
                  {(["NEW", "IN_PROGRESS", "DONE", "CHALLENGED", "FAILED", "REJECTED", "UNKNOWN"] as const).map(
                    (s) => (
                      <MenuItem key={s} value={s}>
                        {s}
                      </MenuItem>
                    )
                  )}
                </Select>
              </FormControl>

              <FormControl sx={{ minWidth: 160 }} fullWidth>
                <InputLabel id="type-label">Type</InputLabel>
                <Select
                  labelId="type-label"
                  label="Type"
                  value={type}
                  onChange={(e) => setType(e.target.value as any)}
                >
                  <MenuItem value="ALL">All</MenuItem>
                  {(["FILE", "MAIL", "URL", "IP", "HASH", "UNKNOWN"] as const).map((t) => (
                    <MenuItem key={t} value={t}>
                      {t}
                    </MenuItem>
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
                  onChange={(e) => setSort(e.target.value as any)}
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
                      <MenuItem key={n} value={n}>
                        {n}
                      </MenuItem>
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
      </GlassCard>

      <GlassCard>
        <CardContent sx={{ p: 0 }}>
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
                    <TableCell sx={{ fontWeight: 950 }}>Info</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Date</TableCell>
                    <TableCell sx={{ fontWeight: 950, textAlign: "right" }}>Tests</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Result</TableCell>
                  </TableRow>
                </TableHead>

                <TableBody>
                  {pageRows.map((r) => (
                    <TableRow
                      key={r.id}
                      hover
                      tabIndex={0}
                      sx={{ cursor: "pointer" }}
                      onClick={() => {
                        setSelectedId(r.id);
                        setOpenDrawer(true);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
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
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedId(r.id);
                              setOpenDrawer(true);
                            }}
                            sx={{ borderRadius: 2, textTransform: "none", fontWeight: 950 }}
                          >
                            {r.id}
                          </Button>

                          <CopyIconButton text={String(r.id)} title="Copy ID" />

                          <Tooltip title="Open details">
                            <IconButton
                              size="small"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedId(r.id);
                                setOpenDrawer(true);
                              }}
                            >
                              <OpenInNewOutlined fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </TableCell>

                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Typography sx={{ fontWeight: 900 }}>{r.reporter_email ?? "—"}</Typography>
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

                      <TableCell sx={{ textAlign: "right", fontWeight: 900 }}>{r.tests_done}</TableCell>

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
      </GlassCard>

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
        {!selectedRow ? (
          <Box sx={{ p: 2 }}>
            <Alert severity="info">Select a row.</Alert>
          </Box>
        ) : (
          <Stack sx={{ height: "100%" }}>
            {/* Header */}
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
                  <Typography variant="overline" color="text.secondary">
                    Investigation
                  </Typography>

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

                          if (editMode) {
                            const score = pickScore(detailsQuery.data);
                            const confidence = pickConfidence(detailsQuery.data);
                            const classification = pickClassification(detailsQuery.data);

                            setEditScore(score == null ? "" : String(score));
                            setEditConfidence(confidence == null ? "" : String(confidence));
                            setEditClassification(String(classification).toUpperCase());
                            editMutation.reset();
                            setEditMode(false);
                            return;
                          }

                          const score = pickScore(detailsQuery.data);
                          const confidence = pickConfidence(detailsQuery.data);
                          const classification = pickClassification(detailsQuery.data);

                          setEditScore(score == null ? "" : String(score));
                          setEditConfidence(confidence == null ? "" : String(confidence));
                          setEditClassification(String(classification).toUpperCase());
                          editMutation.reset();
                          setEditMode(true);
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
                <StatusChip status={selectedRow.status as any} minWidth={BADGE_W} />
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

            {/* Scrollable content */}
            <Box sx={{ flex: 1, overflowY: "auto", p: 2 }}>
              <Stack spacing={2}>
                {/* Overview */}
                <Card
                  sx={{
                    borderRadius: 2,
                    border: "1px solid rgba(255,255,255,.08)",
                    background: "rgba(255,255,255,.025)",
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
                        {selectedRow.info || "—"}
                      </Typography>

                      <Typography color="text.secondary">User mail</Typography>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography sx={{ wordBreak: "break-word" }}>
                          {selectedRow.reporter_email || "—"}
                        </Typography>
                        {selectedRow.reporter_email ? (
                          <IconButton size="small" onClick={() => copyEmail(selectedRow.reporter_email)}>
                            <ContentCopyOutlined fontSize="small" />
                          </IconButton>
                        ) : null}
                      </Stack>

                      <Typography color="text.secondary">Created</Typography>
                      <Typography>{fmtDate(selectedRow.created_at)}</Typography>

                      <Typography color="text.secondary">Investigation ID</Typography>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography>{selectedRow.id}</Typography>
                        <CopyIconButton text={String(selectedRow.id)} title="Copy ID" />
                      </Stack>
                    </Box>
                  </CardContent>
                </Card>

                {/* Global override */}
                <Card
                  sx={{
                    borderRadius: 2,
                    border: "1px solid rgba(255,255,255,.08)",
                    background: "rgba(255,255,255,.025)",
                  }}
                >
                  <CardContent sx={{ p: 2 }}>
                    <Typography variant="subtitle2" fontWeight={900} sx={{ mb: 1.25 }}>
                      Global override
                    </Typography>

                    {detailsQuery.isLoading ? (
                      <Stack direction="row" spacing={1} alignItems="center">
                        <CircularProgress size={18} />
                        <Typography variant="body2" color="text.secondary">
                          Loading details…
                        </Typography>
                      </Stack>
                    ) : detailsQuery.isError ? (
                      <Alert severity="warning">Could not load details.</Alert>
                    ) : (
                      <Stack spacing={1.25}>
                        <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                          <Chip
                            size="small"
                            label={`AI score: ${detailsQuery.data?.case_infos?.score_ai ?? "—"}`}
                            variant="outlined"
                          />
                          <Chip
                            size="small"
                            label={`AI confidence: ${detailsQuery.data?.case_infos?.confidence_ai ?? "—"}`}
                            variant="outlined"
                          />
                          <Chip
                            size="small"
                            label={`AI result: ${detailsQuery.data?.case_infos?.classification_ai ?? "—"}`}
                            variant="outlined"
                          />
                          <Chip
                            size="small"
                            label={`AI category: ${detailsQuery.data?.case_infos?.category_ai ?? "—"}`}
                            variant="outlined"
                          />
                        </Stack>

                        {!editMode ? (
                          <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                            <Chip
                              size="small"
                              label={`Score: ${currentScore ?? "—"} / 10`}
                              variant="outlined"
                              sx={{ fontWeight: 900 }}
                            />
                            <Chip
                              size="small"
                              label={`Confidence: ${currentConfidence ?? "—"} %`}
                              variant="outlined"
                              sx={{ fontWeight: 900 }}
                            />
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
                                  <MenuItem key={c} value={c}>
                                    {c}
                                  </MenuItem>
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
                                <Alert severity="error" sx={{ py: 0.5 }}>
                                  Save failed.
                                </Alert>
                              ) : null}
                            </Stack>
                          </Stack>
                        )}
                      </Stack>
                    )}
                  </CardContent>
                </Card>

                {/* Analyzer details */}
                <Card
                  sx={{
                    borderRadius: 2,
                    border: "1px solid rgba(255,255,255,.08)",
                    background: "rgba(255,255,255,.025)",
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
                            {analyzerReports.length} report{analyzerReports.length === 1 ? "" : "s"}
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
                    border: "1px solid rgba(255,255,255,.08)",
                    background: "rgba(255,255,255,.02)",
                  }}
                >
                  <Accordion
                    disableGutters
                    sx={{
                      borderRadius: 2,
                      border: "1px solid rgba(255,255,255,.08)",
                      background: "rgba(255,255,255,.02)",
                      "&:before": { display: "none" },
                    }}
                  >
                    <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                      <Typography variant="subtitle2" fontWeight={900}>
                        Raw details (API)
                      </Typography>
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