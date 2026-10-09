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
  Collapse,
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
  TablePagination,
  TableRow,
  TableSortLabel,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
  useMediaQuery,
} from "@mui/material";
import {
  AssignmentTurnedInOutlined,
  SearchOutlined,
  RefreshOutlined,
  OpenInNewOutlined,
  ExpandMoreOutlined,
  RestartAltOutlined,
  FilterList,
  DescriptionOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { useNavigate, useSearchParams } from "react-router";
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
  type SubmissionStatus,
  type SubmissionType,
} from "@/features/submissions/api";
import { useDebounced } from "@/shared/hooks/useDebounced";
import { CalmStatusChip } from "@/features/submissions/components/CalmStatusChip";
import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import { RecentSubmissionsList } from "@/features/home/components/RecentSubmissionsList";
import { EmptyState } from "@/shared/components/EmptyState";
import { SheetHeader } from "@/shared/components/SheetHeader";
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

// Page

export default function SubmissionsPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const qc = useQueryClient();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const isPhone = useMediaQuery(theme.breakpoints.down("sm"));

  const [q, setQ] = React.useState("");
  const qDebounced = useDebounced(q, 200);

  const [status, setStatus] = React.useState<SubmissionStatus | "ALL">("ALL");
  const [type, setType] = React.useState<SubmissionType | "ALL">("ALL");
  const [result, setResult] = React.useState<SubmissionResult | "ALL">("ALL");

  const [sortField, setSortField] = React.useState<"created_at" | "id" | "status" | "result" | "artifact" | "type">("created_at");
  const [sortDir,   setSortDir]   = React.useState<"asc" | "desc">("desc");

  const backendOrderingFromSort = React.useMemo((): import("@/features/submissions/api").SubmissionOrdering => {
    const prefix = sortDir === "desc" ? "-" : "";
    if (sortField === "created_at") return `${prefix}created_at` as any;
    if (sortField === "id")         return `${prefix}id` as any;
    if (sortField === "status")     return `${prefix}status` as any;
    if (sortField === "result")     return `${prefix}result` as any;
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

  const activeCount = [status !== "ALL", type !== "ALL", result !== "ALL", from !== "", to !== "", sort !== "date_desc"].filter(Boolean).length;
  const [filtersOpen, setFiltersOpen] = React.useState(false);

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

  const backendOrdering = backendOrderingFromSort;

  const submissionsQuery = useQuery<PaginatedSubmissionsResponse>({
    queryKey: ["submissions", { mine: true, ordering: backendOrdering, fetchSize: 100, search: qDebounced }],
    queryFn: async () =>
      listSubmissions({ mine: true, ordering: backendOrdering, page: 1, page_size: 100, search: qDebounced || undefined }),
    enabled: !!me,
    retry: false,
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

  // Drop ?open= on close so tapping the same phone ID link again re-triggers the URL sync.
  const closeDrawer = () => {
    setOpenDrawer(false);
    if (searchParams.has("open")) {
      const next = new URLSearchParams(searchParams);
      next.delete("open");
      setSearchParams(next, { replace: true });
    }
  };

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

  const filterKey = [qDebounced, status, type, result, from, to, sort, sortField, sortDir, pageSize].join("|");
  const [prevFilterKey, setPrevFilterKey] = React.useState(filterKey);
  if (filterKey !== prevFilterKey) {
    setPrevFilterKey(filterKey);
    setPage(0);
  }

  const [prevOpenDrawer, setPrevOpenDrawer] = React.useState(openDrawer);
  if (openDrawer !== prevOpenDrawer) {
    setPrevOpenDrawer(openDrawer);
    if (!openDrawer) {
      setExpandedAnalyzerIds({});
      setExpandedGroups({});
    }
  }

  const [prevSelectedId, setPrevSelectedId] = React.useState(selectedId);
  if (selectedId !== prevSelectedId) {
    setPrevSelectedId(selectedId);
    setExpandedAnalyzerIds({});
    setExpandedGroups({});
  }

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

  const canChallenge = (r: { is_challengeable?: boolean; is_challenged?: boolean }) =>
    !!r.is_challengeable && !r.is_challenged;
  const challengeButton = (r: { id: number | string }) => (
    <Button
      size="small"
      variant="outlined"
      disabled={challengeMutation.isPending}
      onClick={() => setChallengeId(Number(r.id))}
      sx={{ borderRadius: 2, textTransform: "none", fontWeight: 700, ml: "auto" }}
    >
      Challenge
    </Button>
  );

  const total = filtered.length;
  const start = page * pageSize;
  const end = Math.min(total, start + pageSize);
  const pageRows = filtered.slice(start, end);
  const showChallenge = pageRows.some(canChallenge);
  const selectedRow = selectedId ? rows.find((r) => String(r.id) === String(selectedId)) : undefined;

  // ── Derived values and callbacks ────────────────────────────────────────

  const BADGE_W = 132;
  const DIALOG_RADIUS = 2;

  const analyzerReports = React.useMemo(
    () => detailsQuery.data?.analyzer_reports ?? [],
    [detailsQuery.data]
  );
  const urlArtifacts = detailsQuery.data?.url_artifacts ?? [];
  const hasRawDetails = typeof detailsQuery.data?.raw !== "undefined";

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

  const drawerCardBorder = isDark ? "rgba(255,255,255,.08)" : alpha(theme.palette.divider, 0.6);
  const drawerCardBg = isDark ? "rgba(255,255,255,.025)" : alpha(theme.palette.background.paper, 0.7);
  const refreshBtnBorder = isDark
    ? "1px solid rgba(255,255,255,.10)"
    : `1px solid ${alpha(theme.palette.divider, 0.6)}`;

  // ── Early returns (AFTER all hooks) ─────────────────────────────────────

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
      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={2}
        sx={{ mb: 2, justifyContent: "space-between" }}
      >
        <Stack spacing={0.4}>
          <Box>
            <Typography variant="pageTitle" component="h1">
              Submissions
            </Typography>
            <Typography color="text.secondary">
              Track your submissions and their analysis results.
            </Typography>
          </Box>

          <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
            <Chip icon={<AssignmentTurnedInOutlined />} label={filtersActive ? `${total} match` : `${total} total`} variant="outlined" />
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

      <SoftCard sx={{ mb: 2 }}>
        <CardContent sx={{ p: { xs: 2, md: 2.5 }, "&:last-child": { pb: { xs: 2, md: 2.5 } } }}>
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
              <Button
                variant="outlined"
                color="inherit"
                aria-expanded={filtersOpen}
                aria-controls="submission-filters"
                onClick={() => setFiltersOpen((o) => !o)}
                startIcon={<FilterList />}
                sx={{ borderRadius: 2, textTransform: "none", fontWeight: 700, minWidth: 120, flexShrink: 0 }}
              >
                Filters
                {activeCount > 0 ? <Chip size="small" label={activeCount} color="primary" sx={{ ml: 1, height: 20 }} /> : null}
              </Button>
              {filtersActive ? (
                <Button
                  variant="text"
                  color="inherit"
                  onClick={resetFilters}
                  startIcon={<RestartAltOutlined />}
                  sx={{ borderRadius: 2, textTransform: "none", fontWeight: 700, flexShrink: 0 }}
                >
                  Reset
                </Button>
              ) : null}
            </Stack>

            <Collapse id="submission-filters" in={filtersOpen} unmountOnExit>
              <Stack spacing={1.25} sx={{ pt: 0.5 }}>
                <Stack direction={{ xs: "column", md: "row" }} spacing={1.25} sx={{ alignItems: "stretch" }} >
                  <FormControl fullWidth>
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

                  <FormControl fullWidth>
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

                  <FormControl fullWidth>
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

                  <FormControl fullWidth>
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
              </Stack>
            </Collapse>
          </Stack>
        </CardContent>
      </SoftCard>

      <SoftCard>
        <CardContent sx={{ p: 0 }}>
          {total === 0 && !submissionsQuery.isFetching ? (
            <Box sx={{ p: 4 }}>
              {filtersActive ? (
                <EmptyState
                  title="No submissions match"
                  hint="Try a different search or clear the filters."
                  action={<Button onClick={resetFilters} sx={{ textTransform: "none", mt: 1 }}>Clear filters</Button>}
                />
              ) : (
                <EmptyState
                  title="No submissions yet"
                  hint="Submit a file, URL or indicators to see them here."
                  action={<Button variant="contained" onClick={() => navigate("/submit")} sx={{ textTransform: "none", mt: 1 }}>Submit</Button>}
                />
              )}
            </Box>
          ) : isPhone ? (
            <RecentSubmissionsList
              rows={pageRows}
              hrefFor={(r) =>
                `/submissions?open=${encodeURIComponent(String(r.id))}`
              }
              calmStatus
              action={(r) => {
                const full = pageRows.find((x) => x.id === r.id);
                return full && canChallenge(full) ? challengeButton(r) : null;
              }}
            />
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
                    {showChallenge ? <TableCell sx={{ fontWeight: 950 }}>Challenge</TableCell> : null}
                  </TableRow>
                </TableHead>

                <TableBody>
                  {pageRows.map((r) => {
                    return (
                      <TableRow
                        key={r.id}
                        hover
                        tabIndex={0}
                        sx={{
                          cursor: "pointer",
                          "&:hover .copy-artifact, &:focus-within .copy-artifact": { opacity: 1 },
                        }}
                        onClick={() => { setSelectedId(r.id); setOpenDrawer(true); }}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            setSelectedId(r.id);
                            setOpenDrawer(true);
                          }
                        }}
                      >
                        <TableCell>
                          <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }} >
                            <Button
                              size="small"
                              variant="outlined"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedId(r.id);
                                setOpenDrawer(true);
                              }}
                              sx={{ borderRadius: 2, textTransform: "none", fontWeight: 700, minWidth: 0, px: 1.25, boxShadow: "none" }}
                            >
                              {r.id}
                            </Button>
                            <CopyIconButton text={String(r.id)} title="Copy ID" />
                          </Stack>
                        </TableCell>

                        <TableCell>
                          <ResultChip result={r.result} minWidth={BADGE_W} />
                        </TableCell>

                        <TableCell>
                          <CalmStatusChip status={r.status} minWidth={96} />
                        </TableCell>

                        <TableCell sx={{ maxWidth: 420 }}>
                          <Stack direction="row" spacing={1.25} sx={{ alignItems: "center", minWidth: 0 }}>
                            {r.mail_preview_url ? (
                              <MailPreview
                                url={r.mail_preview_url}
                                variant="thumbnail"
                                alt={`Preview of email for case ${r.id}`}
                              />
                            ) : null}
                            <Typography noWrap title={r.artifact} sx={{ minWidth: 0, flex: "0 1 auto" }}>
                              {r.artifact || "—"}
                            </Typography>
                            {r.artifact ? (
                              <Box className="copy-artifact" sx={{ display: "inline-flex", flexShrink: 0, opacity: 0, "@media (hover: none)": { opacity: 1 } }}>
                                <CopyIconButton text={r.artifact} title="Copy artifact" />
                              </Box>
                            ) : null}
                          </Stack>
                        </TableCell>

                        <TableCell sx={{ whiteSpace: "nowrap" }}>{fmtDate(r.created_at)}</TableCell>

                        <TableCell>
                          <Chip
                            label={r.type}
                            size="small"
                            variant="outlined"
                            sx={{ fontWeight: 900, fontSize: 11 }}
                          />
                        </TableCell>

                        {showChallenge ? (
                          <TableCell onClick={(e) => e.stopPropagation()}>
                            {canChallenge(r) ? challengeButton(r) : null}
                          </TableCell>
                        ) : null}
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </Box>
          )}
        </CardContent>
      </SoftCard>

      {/* ponytail: client-side paging over the first 100 fetched rows (page_size: 100) */}
      <TablePagination
        component="div"
        count={total}
        page={page}
        rowsPerPage={pageSize}
        rowsPerPageOptions={[10, 25, 50]}
        onPageChange={(_, p) => setPage(p)}
        onRowsPerPageChange={(e) => { setPageSize(Number(e.target.value)); setPage(0); }}
        labelDisplayedRows={({ from: f, to: t, count }) => `${f}–${t} of ${count}`}
        sx={{
          "& .MuiTablePagination-toolbar": { flexWrap: "wrap", justifyContent: { xs: "center", sm: "flex-end" }, px: 0 },
          "& .MuiTablePagination-spacer": { display: { xs: "none", sm: "block" } },
        }}
      />

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
            <SheetHeader>
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
                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                  <Button
                    variant="outlined"
                    startIcon={<DescriptionOutlined />}
                    onClick={() =>
                      window.open(`/api/cases/${selectedRow.id}/report/`, "_blank")
                    }
                    sx={{ textTransform: "none", borderRadius: 2, fontWeight: 800 }}
                  >
                    Full report
                  </Button>
                  <Button onClick={closeDrawer}
                    sx={{ textTransform: "none", borderRadius: 2, alignSelf: "flex-start" }}>
                    Close
                  </Button>
                </Stack>
              </Stack>

              <Stack direction="row" spacing={1} sx={{ mt: 1.5, flexWrap: "wrap" }}>
                <ResultChip result={selectedRow.result} minWidth={BADGE_W} />
                <StatusChip status={selectedRow.status} minWidth={96} />
                <Chip size="small" label={selectedRow.type} variant="outlined"
                  sx={{ fontWeight: 900, justifyContent: "center" }} />
                <Chip size="small" label={`${selectedRow.tests_done} tests`} variant="outlined"
                  sx={{ fontWeight: 900 }} />
              </Stack>
            </SheetHeader>

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
                  onAdd={(body) => addCommentMutation.mutateAsync(body)}
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

                {/* Analysis results: grouped by artifact */}
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

                {/* URL artifacts: grouped by domain */}
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