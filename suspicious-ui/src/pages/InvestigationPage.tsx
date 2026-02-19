// src/pages/InvestigationPage.tsx
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
} from "@mui/icons-material";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";

import { getMe, type Me } from "@/api/auth";
import {
  getAllInvestigations,
  getInvestigationDetails,
  editGlobalCase,
  type InvestigationRow,
  type InvestigationStatus,
  type InvestigationType,
} from "@/features/investigation/api";
import { mockInvestigations } from "@/features/investigation/mock";
import { mockInvestigationDetails } from "@/features/investigation/mockDetails";

import { useDebounced } from "@/shared/hooks/useDebounced";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import { CopyIconButton } from "@/shared/components/CopyIconButton";

import { groupAnalyzers, normalizeAnalyzers, type AnalyzerGroup } from "@/shared/hooks/detailsNormalize";
import { ArtifactAnalyzersAccordion } from "@/shared/components/ArtifactAnalyzersAccordion";

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
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit" });
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
    const f = new Date(from + "T00:00:00").getTime();
    if (!Number.isNaN(f) && t < f) return false;
  }
  if (to) {
    const tt = new Date(to + "T23:59:59").getTime();
    if (!Number.isNaN(tt) && t > tt) return false;
  }
  return true;
}

function pickCaseInfos(d: any) {
  if (!d) return null;
  return d.case_infos ?? d.caseInfos ?? d;
}

function pickScore(d: any) {
  const src = pickCaseInfos(d);
  const v = src?.score ?? src?.case_score ?? src?.caseScore;
  return v ?? null;
}

function pickConfidence(d: any) {
  const src = pickCaseInfos(d);
  const v = src?.confidence ?? src?.case_confidence ?? src?.caseConfidence;
  return v ?? null;
}

function pickClassification(d: any) {
  const src = pickCaseInfos(d);
  const v =
    src?.results ??
    src?.classification ??
    src?.category_ai ??
    src?.categoryAi ??
    src?.result ??
    src?.global_result ??
    src?.globalResult;
  return (v ?? "UNKNOWN") as string;
}

export default function InvestigationPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const useMock = import.meta.env.VITE_USE_MOCK_INVESTIGATION === "true";
  const useMockMe = import.meta.env.VITE_USE_MOCK_ME === "true";
  const useMockDetails = import.meta.env.VITE_USE_MOCK_INVESTIGATION_DETAILS === "true";

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

  // edit/save in drawer
  const [editMode, setEditMode] = React.useState(false);
  const [editScore, setEditScore] = React.useState<string>("");
  const [editConfidence, setEditConfidence] = React.useState<string>("");
  const [editClassification, setEditClassification] = React.useState<string>("UNKNOWN");

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
    enabled: !useMockMe,
  });

  const me: Me | undefined = React.useMemo(() => {
    if (useMockMe) {
      return {
        id: 1,
        username: "analyst",
        email: "analyst@example.com",
        first_name: "Mock",
        last_name: "Analyst",
        groups: ["CERT"],
      } as any;
    }
    return meQuery.data;
  }, [useMockMe, meQuery.data]);

  const groups = React.useMemo(() => (((me as any)?.groups ?? []) as string[]), [me]);
  const isElevated = React.useMemo(
    () => groups.includes("CISO") || groups.includes("CERT") || groups.includes("Admin"),
    [groups]
  );

  const investigationsQuery = useQuery<InvestigationResponse>({
    queryKey: ["investigation", useMock],
    queryFn: async () => (useMock ? mockInvestigations() : getAllInvestigations()),
    enabled: !!me && isElevated,
    retry: false,
    initialData: { items: [] },
    refetchInterval: (query) => {
      if (useMock) return false;
      const items = (query.state.data as InvestigationResponse | undefined)?.items ?? [];
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

  const detailsQuery = useQuery<any>({
    queryKey: ["investigationDetails", selectedIdNum, useMockDetails],
    queryFn: async () => {
      if (useMockDetails) return mockInvestigationDetails(selectedIdNum);
      return getInvestigationDetails(selectedIdNum);
    },
    enabled: !!me && isElevated && hasNumericSelectedId && openDrawer && !(useMock && !useMockDetails),
    retry: false,
    staleTime: 30_000,
    gcTime: 10 * 60_000,
    placeholderData: (prev: any) => prev,
  });

  const editMutation = useMutation({
    mutationFn: async (payload: { caseId: number; score: number; confidence: number; classification: string }) =>
      editGlobalCase(payload.caseId, payload.score, payload.confidence, payload.classification),
    onSuccess: () => {
      setEditMode(false);
      detailsQuery.refetch();
      investigationsQuery.refetch();
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    setPage(0);
  }, [qDebounced, status, type, from, to, sort, pageSize]);

  const rows = investigationsQuery.data.items;

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

  const analyzerGroups: AnalyzerGroup[] = React.useMemo(() => {
    if (!detailsQuery.data) return [];
    const hits = normalizeAnalyzers(detailsQuery.data);
    return groupAnalyzers(hits, detailsQuery.data);
  }, [detailsQuery.data]);

  // Close drawer helper: clears edit state and selection UI-only flags
  function closeDrawer() {
    setOpenDrawer(false);
    setEditMode(false);
    editMutation.reset();
  }

  // When switching selected id, exit edit mode + reset mutation (avoid saving wrong case / stale errors)
  React.useEffect(() => {
    setEditMode(false);
    editMutation.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIdNum]);

  // Seed edit values when details arrive (but do not fight user while typing)
  React.useEffect(() => {
    if (!openDrawer) return;
    if (!detailsQuery.data) return;

    const score = pickScore(detailsQuery.data);
    const confidence = pickConfidence(detailsQuery.data);
    const classification = pickClassification(detailsQuery.data);

    // only seed if not currently editing (or empty)
    if (!editMode) {
      setEditScore(score == null ? "" : String(score));
      setEditConfidence(confidence == null ? "" : String(confidence));
      setEditClassification(String(classification).toUpperCase());
    }
  }, [openDrawer, detailsQuery.data, editMode]);

  if (!useMockMe && meQuery.isLoading) {
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
    "SAFE-ALLOW_LISTED",
    "SUSPICIOUS",
    "UNWANTED",
    "INCONCLUSIVE",
    "DANGEROUS",
    "MALICIOUS",
    "FAILURE",
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

  return (
    <Box sx={{ p: { xs: 2, md: 3 } }}>
      {/* Header */}
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
              <Typography color="text.secondary">All submissions — open an ID to see details.</Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
            <Chip icon={<AssignmentTurnedInOutlined />} label={`${total} shown`} variant="outlined" />
            <Chip icon={<FilterAltOutlined />} label="Filters available" variant="outlined" />
            <Chip label={useMock ? "Mock mode" : "Live"} variant="outlined" />
            {useMockDetails ? <Chip label="Mock details" variant="outlined" /> : null}
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

      {/* Filters */}
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

      {/* Table */}
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

      {/* Details drawer */}
      <Drawer
        anchor="right"
        open={openDrawer}
        onClose={closeDrawer}
        PaperProps={{
          sx: {
            borderRadius: DRAWER_RADIUS,
            width: { xs: "100%", sm: 600 },
            p: 2,
            borderLeft: "1px solid rgba(255,255,255,.10)",
            background: "rgb(20, 18, 18)",
          },
        }}
      >
        <Stack spacing={1.25}>
          <Stack direction="row" alignItems="center" justifyContent="space-between">
            <Typography variant="h6" fontWeight={950}>
              Investigation details
            </Typography>

            <Stack direction="row" spacing={1} alignItems="center">

              {selectedRow ? (
                <Tooltip
                  title={detailsReady ? "" : "Load details to edit global override"}
                  arrow
                  placement="bottom"
                  disableHoverListener={detailsReady}
                >
                  {/* span required: Tooltip won’t work on disabled button */}
                  <span>
                    <Button
                      variant={editMode ? "outlined" : "contained"}
                      startIcon={editMode ? <CloseOutlined /> : <EditOutlined />}
                      onClick={() => {
                        if (!detailsReady) return;

                        if (editMode) {
                          // cancel -> re-seed from current details
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

                        // entering edit mode -> seed from details
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
              ) : null}
              <Button onClick={closeDrawer} sx={{ textTransform: "none", borderRadius: 2 }}>
                Close
              </Button>
            </Stack>
          </Stack>

          <Divider sx={{ opacity: 0.25 }} />

          {!selectedRow ? (
            <Alert severity="info">Select a row.</Alert>
          ) : (
            <>
              <Stack spacing={0.5}>
                <Typography variant="overline" color="text.secondary">
                  ID
                </Typography>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Typography variant="h5" fontWeight={950}>
                    {selectedRow.id}
                  </Typography>
                  <CopyIconButton text={String(selectedRow.id)} title="Copy ID" />
                </Stack>
              </Stack>

              <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                <Chip size="small" label="Status" variant="outlined" />
                <StatusChip status={selectedRow.status as any} minWidth={BADGE_W} />

                <Chip size="small" label="Type" variant="outlined" />
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

                <Chip size="small" label="Result" variant="outlined" />
                <ResultChip result={selectedRow.result} minWidth={BADGE_W} />

                <Chip
                  size="small"
                  label={`Tests: ${selectedRow.tests_done}`}
                  variant="outlined"
                  sx={{ fontWeight: 900 }}
                />
              </Stack>

              <Divider sx={{ opacity: 0.25 }} />

              <Typography fontWeight={900}>User mail</Typography>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography color="text.secondary" sx={{ wordBreak: "break-word" }}>
                  {selectedRow.reporter_email ?? "—"}
                </Typography>
                {selectedRow.reporter_email ? (
                  <Tooltip title="Copy email">
                    <IconButton size="small" onClick={() => copyEmail(selectedRow.reporter_email)}>
                      <ContentCopyOutlined fontSize="small" />
                    </IconButton>
                  </Tooltip>
                ) : null}
              </Stack>

              <Typography fontWeight={900} sx={{ mt: 1 }}>
                Info
              </Typography>
              <Typography color="text.secondary" sx={{ wordBreak: "break-word" }}>
                {selectedRow.info}
              </Typography>

              <Typography fontWeight={900} sx={{ mt: 1 }}>
                Created
              </Typography>
              <Typography color="text.secondary">{fmtDate(selectedRow.created_at)}</Typography>

              <Divider sx={{ opacity: 0.25 }} />

              {/* Global edit (Edit -> Save) */}
              <Typography fontWeight={900}>Global override</Typography>

              {detailsQuery.isLoading ? (
                <CircularProgress size={18} />
              ) : detailsQuery.isError ? (
                <Alert severity="warning">Could not load details.</Alert>
              ) : (
                <GlassCard>
                  <CardContent sx={{ p: 2 }}>
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
                  </CardContent>
                </GlassCard>
              )}

              <Divider sx={{ opacity: 0.25 }} />

              <Typography fontWeight={900}>Analyzer details</Typography>

              {detailsQuery.isLoading ? (
                <CircularProgress size={18} />
              ) : detailsQuery.isError ? (
                <Alert severity="warning">Could not load details.</Alert>
              ) : (
                <ArtifactAnalyzersAccordion groups={analyzerGroups} defaultExpanded />
              )}

              <Divider sx={{ opacity: 0.25 }} />
              <Typography fontWeight={900}>Raw details (API)</Typography>

              {detailsQuery.isLoading ? (
                <CircularProgress size={18} />
              ) : detailsQuery.isError ? (
                <Alert severity="warning">Could not load details.</Alert>
              ) : (
                <Box
                  component="pre"
                  sx={{
                    m: 0,
                    p: 1.5,
                    borderRadius: 2,
                    border: "1px solid rgba(255,255,255,.10)",
                    background: "rgba(0,0,0,.20)",
                    overflow: "auto",
                    maxHeight: 260,
                    fontSize: 12,
                  }}
                >
                  {JSON.stringify(detailsQuery.data, null, 2)}
                </Box>
              )}
            </>
          )}
        </Stack>
      </Drawer>
    </Box>
  );
}
