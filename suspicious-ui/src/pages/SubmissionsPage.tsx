import * as React from "react";
import {
  Alert,
  Box,
  Button,
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
  TableSortLabel,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
} from "@mui/material";
import {
  AssignmentTurnedInOutlined,
  SearchOutlined,
  RefreshOutlined,
  OpenInNewOutlined,
  ExpandMoreOutlined,
  RestartAltOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { alpha } from "@mui/material/styles";
import { useTheme } from "@mui/material/styles";
import { getMe, type Me } from "@/api/auth";
import { getProfile } from "@/features/profile/api";
import { UserAvatar } from "@/features/profile/components/UserAvatar";
import {
  challengeSubmission,
  getSubmissionDetails,
  listSubmissions,
  type PaginatedSubmissionsResponse,
  type SubmissionAnalyzerReport,
  type SubmissionDetails,
  type SubmissionOrdering,
  type SubmissionResult,
  type SubmissionStatus,
  type SubmissionType,
} from "@/features/submissions/api";
import { useDebounced } from "@/shared/hooks/useDebounced";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import { CopyIconButton } from "@/shared/components/CopyIconButton";
import MailPreview from "@/shared/components/MailPreview";

import { SoftCard } from "@/features/submissions/components/cards";
import { AnalyzerReportCard } from "@/features/submissions/components/AnalyzerReportCard";
import { UrlGroupList } from "@/features/submissions/components/UrlGroupList";
import { CommentThread } from "@/features/comments/CommentThread";
import { addCaseComment, getCaseComments } from "@/features/comments/api";
import {
  RESULT_OPTIONS,
  STATUS_OPTIONS,
  TYPE_OPTIONS,
  fmtDate,
  groupReportsByArtifact,
  kindLabel,
  withinDates,
} from "@/features/submissions/utils";

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

  const filtersActive =
    q !== "" ||
    status !== "ALL" ||
    type !== "ALL" ||
    result !== "ALL" ||
    from !== "" ||
    to !== "" ||
    sort !== "date_desc" ||
    sortField !== "created_at" ||
    sortDir !== "desc";

  const resetFilters = React.useCallback(() => {
    setQ("");
    setStatus("ALL");
    setType("ALL");
    setResult("ALL");
    setFrom("");
    setTo("");
    setSort("date_desc");
    setSortField("created_at");
    setSortDir("desc");
    setPage(0);
  }, []);

  const [openDrawer, setOpenDrawer] = React.useState(false);
  const [selectedId, setSelectedId] = React.useState<number | string | null>(null);
  const [challengeId, setChallengeId] = React.useState<number | null>(null);
  const [proposedResult, setProposedResult] = React.useState<"Safe" | "Dangerous" | null>(null);
  const [challengeReason, setChallengeReason] = React.useState("");
  const [expandedAnalyzerIds, setExpandedAnalyzerIds] = React.useState<Record<number, boolean>>({});
  const [expandedGroups, setExpandedGroups] = React.useState<Record<string, boolean>>({});

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  const me: Me | undefined = React.useMemo(() => meQuery.data, [meQuery.data]);

  const profileQuery = useQuery({
    queryKey: ["profile"],
    queryFn: getProfile,
    enabled: !!me,
    retry: false,
  });

  // sort dropdown kept for backwards-compat; column clicks take precedence
  const backendOrdering = backendOrderingFromSort;

  const submissionsQuery = useQuery<PaginatedSubmissionsResponse>({
    queryKey: ["submissions", { mine: true, ordering: backendOrdering, fetchSize: 100, search: qDebounced }],
    queryFn: async () =>
      listSubmissions({ mine: true, ordering: backendOrdering, page: 1, page_size: 100, search: qDebounced || undefined }),
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
    mutationFn: async (vars: { id: number; proposed_result: "Safe" | "Dangerous"; reason: string }) =>
      challengeSubmission(vars.id, { proposed_result: vars.proposed_result, reason: vars.reason }),
    onMutate: async (vars) => {
      await qc.cancelQueries({ queryKey: ["submissions"] });
      const prevEntries = qc.getQueriesData<PaginatedSubmissionsResponse>({ queryKey: ["submissions"] });
      prevEntries.forEach(([key, prev]) => {
        if (!prev) return;
        qc.setQueryData<PaginatedSubmissionsResponse>(key, {
          ...prev,
          results: prev.results.map((r) =>
            r.id === vars.id ? { ...r, is_challenged: true, is_challengeable: false } : r
          ),
        });
      });
      return { prevEntries };
    },
    onError: (_err, _vars, ctx) => {
      ctx?.prevEntries?.forEach(([key, data]) => { qc.setQueryData(key, data); });
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["submissions"] });
      qc.invalidateQueries({ queryKey: ["submissionDetails"] });
    },
    onSuccess: () => {
      setChallengeId(null);
      setProposedResult(null);
      setChallengeReason("");
    },
  });

  const commentsQuery = useQuery({
    queryKey: ["caseComments", selectedIdNum],
    queryFn: () => getCaseComments(selectedIdNum),
    enabled: !!me && hasNumericSelectedId && openDrawer,
    retry: false,
  });

  const addCommentMutation = useMutation({
    mutationFn: (body: string) => addCaseComment(selectedIdNum, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["caseComments", selectedIdNum] });
    },
  });

  // Sync from deep-link URL params (?q, ?open) on first render and whenever
  // they change — adjusted during render instead of in an effect.
  const urlSyncKey = `${searchParams.get("q") ?? ""}|${searchParams.get("open") ?? ""}`;
  const [prevUrlSyncKey, setPrevUrlSyncKey] = React.useState<string | null>(null);
  if (urlSyncKey !== prevUrlSyncKey) {
    setPrevUrlSyncKey(urlSyncKey);
    const urlQ = searchParams.get("q") ?? "";
    if (urlQ) setQ(urlQ);
    const open = searchParams.get("open");
    if (open) {
      const idNum = Number(open);
      if (!Number.isNaN(idNum)) {
        setSelectedId(idNum);
        setOpenDrawer(true);
      }
    }
  }

  // Reset to first page when any filter/sort changes.
  const filterKey = [qDebounced, status, type, result, from, to, sort, sortField, sortDir, pageSize].join("|");
  const [prevFilterKey, setPrevFilterKey] = React.useState(filterKey);
  if (filterKey !== prevFilterKey) {
    setPrevFilterKey(filterKey);
    setPage(0);
  }

  // Collapse expansion when the drawer closes.
  const [prevOpenDrawer, setPrevOpenDrawer] = React.useState(openDrawer);
  if (openDrawer !== prevOpenDrawer) {
    setPrevOpenDrawer(openDrawer);
    if (!openDrawer) {
      setExpandedAnalyzerIds({});
      setExpandedGroups({});
    }
  }

  // Collapse expansion when the selected item changes.
  const [prevSelectedId, setPrevSelectedId] = React.useState(selectedId);
  if (selectedId !== prevSelectedId) {
    setPrevSelectedId(selectedId);
    setExpandedAnalyzerIds({});
    setExpandedGroups({});
  }

  // Collapse analyzer rows when a fresh set of reports arrives. Keyed on the
  // query's update timestamp (stable across renders, unlike the data array ref).
  const reportsKey = detailsQuery.dataUpdatedAt;
  const [prevReportsKey, setPrevReportsKey] = React.useState(reportsKey);
  if (reportsKey !== prevReportsKey) {
    setPrevReportsKey(reportsKey);
    setExpandedAnalyzerIds({});
  }

  const rows = React.useMemo(
    () => submissionsQuery.data?.results ?? [],
    [submissionsQuery.data]
  );
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

  const analyzerReports = React.useMemo(
    () => detailsQuery.data?.analyzer_reports ?? [],
    [detailsQuery.data]
  );
  const urlArtifacts = detailsQuery.data?.url_artifacts ?? [];
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
    <Skeleton
      name="submissions-page"
      loading={submissionsQuery.isPending || meQuery.isPending}
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
            <UserAvatar
              avatar={profileQuery.data?.avatar}
              initials={(me.username?.[0] ?? "U").toUpperCase()}
              sx={{ width: 46, height: 46, fontWeight: 950 }}
            />
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 950, letterSpacing: -0.5 }} >
                Submissions
              </Typography>
              <Typography color="text.secondary">
                Track your submissions and their analysis results.
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
            <Chip icon={<AssignmentTurnedInOutlined />} label={`${total} shown`} variant="outlined" />
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
            <Stack direction={{ xs: "column", md: "row" }} spacing={1.25} sx={{ alignItems: "stretch" }} >
              <TextField
                value={q}
                onChange={(e) => setQ(e.target.value)}
                label="Search"
                placeholder="id, status, artifact, type, result"
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
                          <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }} >
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

                        {/* Artifact (with email preview thumbnail when available) */}
                        <TableCell title={r.artifact}>
                          <Stack direction="row" spacing={1.25} sx={{ alignItems: "center" }}>
                            {r.mail_preview_url ? (
                              <MailPreview
                                url={r.mail_preview_url}
                                variant="thumbnail"
                                alt={`Preview of email for case ${r.id}`}
                              />
                            ) : null}
                            <Tooltip title={r.artifact || ""} arrow placement="top">
                              <Typography
                                sx={{
                                  maxWidth: 520,
                                  display: "-webkit-box",
                                  WebkitLineClamp: 2,
                                  WebkitBoxOrient: "vertical",
                                  overflow: "hidden",
                                  wordBreak: "break-word",
                                  cursor: "help",
                                }}
                              >
                                {r.artifact || "—"}
                              </Typography>
                            </Tooltip>
                          </Stack>
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
            }),
          },
        }}
      >
        {!selectedRow ? (
          <Box sx={{ p: 2 }}>
            <Alert severity="info">Select a row.</Alert>
          </Box>
        ) : (
          <Stack sx={{ height: "100%" }}>
            {/* Drawer header — result-focused */}
            <Box
              sx={(theme) => ({
                px: 2.25,
                py: 1.75,
                borderBottom: `1px solid ${theme.palette.divider}`,
                background: `linear-gradient(180deg, ${alpha(theme.palette.action.hover, 0.22)} 0%, ${alpha(theme.palette.background.paper, 0)} 100%)`,
              })}
            >
              <Stack direction="row" spacing={2} sx={{ alignItems: "flex-start", justifyContent: "space-between" }} >
                <Box>
                  <Typography variant="overline" color="text.secondary">Submission</Typography>
                  <Stack direction="row" spacing={1} sx={{ mt: 0.25, alignItems: "center" }}>
                    <Typography variant="h5" sx={{ fontWeight: 950, lineHeight: 1.1 }} >
                      #{selectedRow.id}
                    </Typography>
                    <CopyIconButton text={String(selectedRow.id)} title="Copy ID" />
                  </Stack>
                </Box>
                <Button onClick={() => setOpenDrawer(false)}
                  sx={{ textTransform: "none", borderRadius: 2, alignSelf: "flex-start" }}>
                  Close
                </Button>
              </Stack>

              {/* Verdict + status chips — the key info at a glance */}
              <Stack direction="row" spacing={1} sx={{ mt: 1.5, flexWrap: "wrap" }}>
                <ResultChip result={selectedRow.result} minWidth={BADGE_W} />
                <StatusChip status={selectedRow.status} minWidth={96} />
                <Chip size="small" label={selectedRow.type} variant="outlined"
                  sx={{ fontWeight: 900, justifyContent: "center" }} />
                <Chip size="small" label={`${selectedRow.tests_done} tests`} variant="outlined"
                  sx={{ fontWeight: 900 }} />
              </Stack>
            </Box>

            {/* Drawer body — redesigned */}
            <Box sx={{ flex: 1, overflowY: "auto" }}>

              {/* ── Summary strip ──────────────────────────────────────────────── */}
              <Box
                sx={{
                  px: 2.25, py: 1.5,
                  display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 1,
                  borderBottom: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.55)}`,
                  background: isDark ? alpha("#fff", 0.015) : alpha(theme.palette.grey[50], 0.6),
                }}
              >
                {[
                  { label: "Submission", value: `#${selectedRow.id}` },
                  { label: "Tests run", value: selectedRow.tests_done ?? "—" },
                  { label: "Submitted", value: fmtDate(selectedRow.created_at) },
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

                {/* ── Verdict (read-only) ───────────────────────────────────────── */}
                {detailsQuery.data?.case_infos ? (
                  <Box sx={{ px: 2.25, py: 2 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                      Verdict
                    </Typography>
                    <Stack spacing={1.25}>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
                        <ResultChip result={String(detailsQuery.data.case_infos.classification ?? "UNKNOWN")} minWidth={BADGE_W} />
                        <Chip size="small" label={`Score ${detailsQuery.data.case_infos.score ?? "—"}/10`} variant="outlined" sx={{ fontWeight: 800 }} />
                        <Chip size="small" label={`Confidence ${detailsQuery.data.case_infos.confidence ?? "—"}%`} variant="outlined" sx={{ fontWeight: 800 }} />
                      </Stack>
                      <Stack direction="row" spacing={0.75} sx={{ opacity: 0.65, flexWrap: "wrap" }}>
                        <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, mr: 0.25 }}>AI:</Typography>
                        {[
                          `${detailsQuery.data.case_infos.classification_ai ?? "—"}`,
                          `score ${detailsQuery.data.case_infos.score_ai ?? "—"}`,
                          `conf ${detailsQuery.data.case_infos.confidence_ai ?? "—"}%`,
                          detailsQuery.data.case_infos.category_ai ? `cat ${detailsQuery.data.case_infos.category_ai}` : null,
                        ].filter(Boolean).map((label) => (
                          <Chip key={label as string} size="small" label={label as string} variant="outlined"
                            sx={{ height: 18, fontSize: 10, "& .MuiChip-label": { px: 0.75 } }} />
                        ))}
                      </Stack>
                    </Stack>
                  </Box>
                ) : null}

                {/* ── Artifact ──────────────────────────────────────────────────── */}
                <Box sx={{ px: 2.25, py: 2 }}>
                  <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                    Artifact
                  </Typography>
                  <Typography sx={{ wordBreak: "break-all", fontWeight: 700, fontSize: 13.5 }}>
                    {selectedRow.artifact || "—"}
                  </Typography>
                </Box>

                {/* ── Your comments ───────────────────────────────────────────── */}
                <CommentThread
                  title="Your comments"
                  comments={commentsQuery.data ?? []}
                  isLoading={commentsQuery.isLoading}
                  onAdd={(body) => addCommentMutation.mutate(body)}
                  isAdding={addCommentMutation.isPending}
                />

                {/* ── Email preview (only when the case is a mail) ─────────────── */}
                {selectedRow.mail_preview_url ? (
                  <Box sx={{ px: 2.25, py: 2 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
                      Email preview
                    </Typography>
                    <MailPreview
                      url={selectedRow.mail_preview_url}
                      variant="full"
                      alt={`Preview of email for case ${selectedRow.id}`}
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
                        <Button size="small"
                          onClick={() => setExpandedGroups(Object.fromEntries(reportGroups.map((g) => [g.key, true])))}
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
                            {/* Group header */}
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
                              <Typography variant="body2"
                                sx={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: 700 }}
                                title={group.value}>
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
                                    <AnalyzerReportCard
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

                {/* ── URL artifacts — grouped by domain ────────────────────── */}
                {urlArtifacts.length > 0 && (
                  <Box sx={{ px: 2.25, pt: 2, pb: 1 }}>
                    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 1.25 }}>
                      URLs · {urlArtifacts.length} artifact{urlArtifacts.length !== 1 ? "s" : ""}
                    </Typography>
                    <UrlGroupList submissionId={selectedIdNum} urls={urlArtifacts} />
                  </Box>
                )}
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
        onClose={() => {
          setChallengeId(null);
          setProposedResult(null);
          setChallengeReason("");
        }}
        maxWidth="xs"
        fullWidth
        slotProps={{ paper: { sx: { borderRadius: DIALOG_RADIUS } } }}
      >
        <DialogTitle>Challenge submission</DialogTitle>
        <DialogContent>
          <Typography color="text.secondary">
            Tell us what you think the verdict should be for submission #{challengeId}.
          </Typography>
          <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
            What should the verdict be?
          </Typography>
          <ToggleButtonGroup
            value={proposedResult}
            exclusive
            onChange={(_, v) => v && setProposedResult(v)}
            size="small"
          >
            <ToggleButton value="Safe">Safe</ToggleButton>
            <ToggleButton value="Dangerous">Dangerous</ToggleButton>
          </ToggleButtonGroup>
          <TextField
            label="Why? (optional)"
            value={challengeReason}
            onChange={(e) => setChallengeReason(e.target.value)}
            multiline
            minRows={2}
            fullWidth
            sx={{ mt: 2 }}
          />
          {challengeMutation.isError ? (
            <Alert severity="error" sx={{ mt: 2 }}>Failed to challenge.</Alert>
          ) : null}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setChallengeId(null);
              setProposedResult(null);
              setChallengeReason("");
            }}
            sx={{ borderRadius: 2 }}
          >
            Cancel
          </Button>
          <Button
            variant="contained"
            disabled={challengeMutation.isPending || challengeId === null || proposedResult === null}
            onClick={() => {
              if (challengeId && proposedResult) {
                challengeMutation.mutate({ id: challengeId, proposed_result: proposedResult, reason: challengeReason });
              }
            }}
            sx={{ textTransform: "none", fontWeight: 950, borderRadius: 2 }}
          >
            {challengeMutation.isPending ? "Sending…" : "Confirm"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
    </Skeleton>
  );
}