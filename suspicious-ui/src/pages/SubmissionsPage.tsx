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
import { getMe, type Me } from "@/api/auth";
import {
  challengeSubmission,
  getMySubmissions,
  getSubmissionDetails,
  SubmissionDetails, SubmissionAnalyzerReport,
  type SubmissionRow,
  type SubmissionStatus,
  type SubmissionType,
} from "@/features/submissions/api";

import { useDebounced } from "@/shared/hooks/useDebounced";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import { CopyIconButton } from "@/shared/components/CopyIconButton";

type SubmissionsResponse = { items: SubmissionRow[] };

function AnalyzerReportCard({ report }: { report: SubmissionAnalyzerReport }) {
  return (
    <Card
      sx={{
        borderRadius: 2,
        border: "1px solid rgba(255,255,255,.08)",
        background: "rgba(255,255,255,.025)",
      }}
    >
      <CardContent sx={{ p: 1.5 }}>
        <Stack spacing={1}>
          <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={1}>
            <Box>
              <Typography variant="subtitle2" fontWeight={900}>
                {report.analyzer_name || "Unknown analyzer"}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {report.analyzer_id} • {report.type} • {report.status}
              </Typography>
            </Box>

            <Stack direction="row" spacing={0.75} sx={{ flexWrap: "wrap", justifyContent: "flex-end" }}>
              <Chip size="small" label={`Level: ${report.level || "—"}`} variant="outlined" />
              <Chip size="small" label={`Score: ${report.score ?? "—"}`} variant="outlined" />
              <Chip
                size="small"
                label={`Confidence: ${typeof report.confidence === "number" ? report.confidence.toFixed(2) : "—"}`}
                variant="outlined"
              />
            </Stack>
          </Stack>

          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", sm: "120px 1fr" },
              gap: 1,
            }}
          >
            <Typography color="text.secondary" variant="body2">
              Target
            </Typography>
            <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
              {report.target?.value || "—"} {report.target?.kind ? `(${report.target.kind})` : ""}
            </Typography>

            <Typography color="text.secondary" variant="body2">
              Categories
            </Typography>
            <Typography variant="body2">
              {report.categories?.length ? report.categories.join(", ") : "—"}
            </Typography>

            <Typography color="text.secondary" variant="body2">
              Created
            </Typography>
            <Typography variant="body2">
              {fmtDate(report.created_at)}
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
              <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                <Typography variant="body2" fontWeight={800}>
                  Taxonomy
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Box
                  component="pre"
                  sx={{
                    m: 0,
                    p: 1.25,
                    borderRadius: 2,
                    border: "1px solid rgba(255,255,255,.08)",
                    background: "rgba(0,0,0,.18)",
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
              <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                <Typography variant="body2" fontWeight={800}>
                  Summary
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Box
                  component="pre"
                  sx={{
                    m: 0,
                    p: 1.25,
                    borderRadius: 2,
                    border: "1px solid rgba(255,255,255,.08)",
                    background: "rgba(0,0,0,.18)",
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
      </CardContent>
    </Card>
  );
}

function GlassCard(props: React.PropsWithChildren<{ sx?: any }>) {
  return (
    <Card
      sx={(theme) => ({
        borderRadius: 2,
        border: `1px solid ${alpha(theme.palette.divider, 0.9)}`,
        background: `linear-gradient(
          180deg,
          ${alpha(theme.palette.background.paper, 0.88)} 0%,
          ${alpha(theme.palette.background.paper, 0.72)} 100%
        )`,
        backdropFilter: "blur(8px)",
        ...props.sx,
      })}
    >
      {props.children}
    </Card>
  );
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

export default function SubmissionsPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const qc = useQueryClient();

  const [q, setQ] = React.useState("");
  const qDebounced = useDebounced(q, 200);

  const [status, setStatus] = React.useState<SubmissionStatus | "ALL">("ALL");
  const [type, setType] = React.useState<SubmissionType | "ALL">("ALL");
  const [from, setFrom] = React.useState("");
  const [to, setTo] = React.useState("");
  const [sort, setSort] = React.useState<"date_desc" | "date_asc" | "id_desc" | "id_asc">("date_desc");
  const [page, setPage] = React.useState(0);
  const [pageSize, setPageSize] = React.useState(10);

  const [openDrawer, setOpenDrawer] = React.useState(false);
  const [selectedId, setSelectedId] = React.useState<number | string | null>(null);
  const [challengeId, setChallengeId] = React.useState<number | null>(null);

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  const me: Me | undefined = React.useMemo(() => {
    return meQuery.data;
  }, [meQuery.data]);

  const submissionsQuery = useQuery<SubmissionsResponse>({
    queryKey: ["submissions"],
    queryFn: async () => (getMySubmissions()),
    enabled: !!me,
    retry: false,
    initialData: { items: [] },
    refetchInterval: (query) => {
      const items = (query.state.data as SubmissionsResponse | undefined)?.items ?? [];
      const shouldPoll = items.some((r) => {
        const s = ((r.status ?? "UNKNOWN") as string).toUpperCase();
        return s === "NEW" || s === "IN_PROGRESS";
      });
      return shouldPoll ? 10_000 : false;
    },
    refetchIntervalInBackground: true,
  });

  const selectedIdNum = typeof selectedId === "number" ? selectedId : selectedId ? Number(selectedId) : NaN;
  const hasNumericSelectedId = Number.isFinite(selectedIdNum);

  const detailsQuery = useQuery<SubmissionDetails>({
    queryKey: ["submissionDetails", selectedIdNum],
    queryFn: async () => {
      return getSubmissionDetails(selectedIdNum);
    },
    enabled: !!me && hasNumericSelectedId && openDrawer,
    retry: false,
    staleTime: 30_000,
    gcTime: 10 * 60_000,
    placeholderData: (prev: any) => prev,
  });

  const challengeMutation = useMutation({
    mutationFn: async (id: number) => challengeSubmission(id),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: ["submissions"] });
      const prev = qc.getQueryData<SubmissionsResponse>(["submissions"]);
      if (prev) {
        qc.setQueryData<SubmissionsResponse>(["submissions"], {
          items: prev.items.map((r) =>
            r.id === id ? { ...r, is_challenged: true, is_challengeable: false } : r
          ),
        });
      }
      return { prev };
    },
    onError: (_err, _id, ctx) => {
      if (ctx?.prev) qc.setQueryData(["submissions"], ctx.prev);
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    setPage(0);
  }, [qDebounced, status, type, from, to, sort, pageSize]);

  const rows = submissionsQuery.data?.items ?? [];

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

  if (submissionsQuery.isLoading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (submissionsQuery.isError) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Failed to load submissions (API route / permissions).</Alert>
      </Box>
    );
  }

  const BADGE_W = 132; // same width for Status/Result/Type, tweak as you like
  const DIALOG_RADIUS = 2;
  const DRAWER_RADIUS = 2;

  return (
    <Box sx={{ p: { xs: 2, md: 3 } }}>
      {/* Header */}
      <Stack direction={{ xs: "column", md: "row" }} spacing={2} justifyContent="space-between" sx={{ mb: 2 }}>
        <Stack spacing={0.4}>
          <Stack direction="row" spacing={1.25} alignItems="center">
            <Avatar sx={{ width: 46, height: 46, fontWeight: 950 }}>
              {(me.username?.[0] ?? "U").toUpperCase()}
            </Avatar>
            <Box>
              <Typography variant="h4" fontWeight={950} letterSpacing={-0.5}>
                Submissions
              </Typography>
              <Typography color="text.secondary">Your latest submissions — open an ID to see details.</Typography>
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
            sx={{ borderRadius: 2, textTransform: "none", fontWeight: 900 }} // slightly less round
          >
            New submission
          </Button>

          <IconButton
            aria-label="Refresh"
            onClick={() => submissionsQuery.refetch()}
            sx={{ border: "1px solid rgba(255,255,255,.10)", borderRadius: 2 }}
          >
            <RefreshOutlined />
          </IconButton>
        </Stack>
      </Stack>

      {/* Filters */}
      <GlassCard sx={{ mb: 2 }}>
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
                  onChange={(e) => setStatus(e.target.value as any)}
                >
                  <MenuItem value="ALL">All</MenuItem>
                  {(["NEW", "IN_PROGRESS", "DONE", "FAILED", "REJECTED", "UNKNOWN"] as const).map((s) => (
                    <MenuItem key={s} value={s}>
                      {s}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <FormControl sx={{ minWidth: 160 }} fullWidth>
                <InputLabel id="type-label">Type</InputLabel>
                <Select labelId="type-label" label="Type" value={type} onChange={(e) => setType(e.target.value as any)}>
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
                <Select labelId="sort-label" label="Sort" value={sort} onChange={(e) => setSort(e.target.value as any)}>
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
                  sx={{ borderRadius: 2, textTransform: "none", fontWeight: 900 }} // less round
                >
                  Prev
                </Button>
                <Button
                  variant="outlined"
                  disabled={end >= total}
                  onClick={() => setPage((p) => p + 1)}
                  sx={{ borderRadius: 2, textTransform: "none", fontWeight: 900 }} // less round
                >
                  Next
                </Button>
              </Stack>
            </Stack>
          </Stack>
        </CardContent>
      </GlassCard>

      {/* Table */}
      <GlassCard>
        <CardContent sx={{ p: 0 }}>
          {total === 0 ? (
            <Box sx={{ p: 3 }}>
              <Alert severity="info">No submissions match your filters.</Alert>
            </Box>
          ) : (
            <Box sx={{ overflowX: "auto" }}>
              <Table sx={{ minWidth: 980 }}>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 950 }}>ID</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Status</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Artifact</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Date</TableCell>
                    <TableCell sx={{ fontWeight: 950, textAlign: "right" }}>Tests</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Result</TableCell>
                    <TableCell sx={{ fontWeight: 950 }}>Challenge</TableCell>
                  </TableRow>
                </TableHead>

                <TableBody>
                  {pageRows.map((r) => {
                    const canChallenge = r.is_challengeable && !r.is_challenged;

                    return (
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
                              sx={{ borderRadius: 2, textTransform: "none", fontWeight: 950 }} // less round
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

                        <TableCell>
                          <StatusChip status={r.status} minWidth={BADGE_W} />
                        </TableCell>

                        <TableCell title={r.artifact}>
                          <Typography
                            sx={{
                              maxWidth: 340,
                              whiteSpace: "nowrap",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                            }}
                          >
                            {short(r.artifact, 64)}
                          </Typography>
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

                        <TableCell onClick={(e) => e.stopPropagation()}>
                          {canChallenge ? (
                            <Button
                              size="small"
                              variant="outlined"
                              disabled={challengeMutation.isPending}
                              onClick={() => setChallengeId(r.id)}
                              sx={{ borderRadius: 2, textTransform: "none", fontWeight: 950 }} // less round
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
      </GlassCard>

      {/* Details drawer */}
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
                    Submission
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
                      direction="row"
                      justifyContent="space-between"
                      alignItems="center"
                      sx={{ mb: 1.25 }}
                    >
                      <Typography variant="subtitle2" fontWeight={900}>
                        Analyzer details
                      </Typography>

                      {!detailsQuery.isLoading && !detailsQuery.isError ? (
                        <Typography variant="caption" color="text.secondary">
                          {detailsQuery.data?.analyzer_reports?.length ?? 0} report
                          {(detailsQuery.data?.analyzer_reports?.length ?? 0) === 1 ? "" : "s"}
                        </Typography>
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
                      <Alert severity="info">No analyzers triggered for this submission.</Alert>
                    ) : (
                      <Stack spacing={1.25}>
                        {detailsQuery.data.analyzer_reports.map((report) => (
                          <AnalyzerReportCard key={report.id} report={report} />
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
                    </AccordionDetails>
                  </Accordion>
                </Card>
              </Stack>
            </Box>
          </Stack>
        )}
      </Drawer>

      {/* Challenge dialog */}
      <Dialog
        open={challengeId !== null}
        onClose={() => setChallengeId(null)}
        maxWidth="xs"
        fullWidth
        PaperProps={{ sx: { borderRadius: DIALOG_RADIUS } }} // added
      >
        <DialogTitle>Challenge submission</DialogTitle>
        <DialogContent>
          <Typography color="text.secondary">Submit a challenge request for case #{challengeId}.</Typography>
          {challengeMutation.isError ? (
            <Alert severity="error" sx={{ mt: 2 }}>
              Failed to challenge.
            </Alert>
          ) : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setChallengeId(null)} sx={{ borderRadius: 2 }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            disabled={challengeMutation.isPending || challengeId === null}
            onClick={() => {
              if (challengeId) challengeMutation.mutate(challengeId);
            }}
            sx={{ textTransform: "none", fontWeight: 950, borderRadius: 2 }} // less round
          >
            {challengeMutation.isPending ? "Sending…" : "Confirm"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
