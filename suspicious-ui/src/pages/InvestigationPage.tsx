import * as React from "react";
import {
  Alert,
  LinearProgress,
  Box,
  Button,
  CardContent,
  Chip,
  CircularProgress,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
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
  Typography,
  useMediaQuery,
} from "@mui/material";
import {
  AssignmentTurnedInOutlined,
  SearchOutlined,
  RefreshOutlined,
  RestartAltOutlined,
  ReplayOutlined,
  FilterList,
} from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { useNavigate, useSearchParams } from "react-router";
import { alpha } from "@mui/material/styles";
import { useTheme } from "@mui/material/styles";

import { getMe, type Me } from "@/api/auth";
import {
  getAllInvestigations,
  getInvestigationDetails,
  editGlobalCase,
  redoAnalysis,
  buildSortOrdering,
  type InvestigationDetails,
  type InvestigationListResponse,
  type InvestigationResult,
  type InvestigationStatus,
  type InvestigationType,
} from "@/features/investigation/api";
import { useDebounced } from "@/shared/hooks/useDebounced";
import { CalmStatusChip } from "@/features/submissions/components/CalmStatusChip";
import { EmptyState } from "@/shared/components/EmptyState";
import { RecentSubmissionsList } from "@/features/home/components/RecentSubmissionsList";
import { ResultChip } from "@/shared/components/ResultChip";
import { CopyIconButton } from "@/shared/components/CopyIconButton";

import { CisoScopeDialog } from "@/features/home/components/CisoScopeDialog";
import { SoftCard } from "@/features/investigation/components/cards";
import { InvestigationDrawer } from "@/features/investigation/components/InvestigationDrawer";
import { addCaseComment, getCaseComments } from "@/features/comments/api";
import {
  fmtDate,
  pickClassification,
  pickConfidence,
  pickScore,
} from "@/features/investigation/utils";

// Page

export default function InvestigationPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const qc = useQueryClient();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const isPhone = useMediaQuery(theme.breakpoints.down("sm"));

  const [q, setQ] = React.useState("");
  const qDebounced = useDebounced(q, 250);

  const [status, setStatus] = React.useState<InvestigationStatus | "ALL">("ALL");
  const [type, setType] = React.useState<InvestigationType | "ALL">("ALL");
  const [result, setResult] = React.useState<InvestigationResult | "ALL">("ALL");
  const [from, setFrom] = React.useState("");
  const [to, setTo] = React.useState("");
  const [sortField, setSortField] = React.useState<"creation_date" | "id" | "status" | "result">("creation_date");
  const [sortDir,   setSortDir]   = React.useState<"asc" | "desc">("desc");

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

  // Narrowing (search or a filter) makes the server count a match count; sort never narrows.
  const anyFilterActive =
    !!qDebounced || status !== "ALL" || type !== "ALL" || result !== "ALL" || !!from || !!to;
  const [pageSize, setPageSize] = React.useState(10);

  const sortActive = sortField !== "creation_date" || sortDir !== "desc";
  const activeCount = [status !== "ALL", type !== "ALL", result !== "ALL", from !== "", to !== "", sortActive].filter(Boolean).length;
  const filtersActive = q !== "" || activeCount > 0;
  const [filtersOpen, setFiltersOpen] = React.useState(false);

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


  const meQuery = useQuery<Me>({ queryKey: ["me"], queryFn: getMe, retry: false });
  const me = meQuery.data;

  const groups = React.useMemo(() => me?.groups ?? [], [me]);
  const isElevated = React.useMemo(
    () => groups.includes("CISO") || groups.includes("CERT") || groups.includes("Admin"),
    [groups]
  );
  // A CISO with no scope set can't meaningfully browse cases yet: prompt them
  // to pick one first (same modal Home shows on first connection).
  const needsScope =
    !!me &&
    groups.includes("CISO") &&
    !groups.includes("CERT") &&
    !groups.includes("Admin") &&
    !me.ciso_scope;

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
      sort: needsRawOrdering ? "date_desc" : sort,
      ordering: needsRawOrdering
        ? buildSortOrdering(sortField, sortDir)
        : undefined,
    };
  }, [page, pageSize, qDebounced, status, type, result, from, to, sort, sortField, sortDir]);

  const investigationsQuery = useQuery<InvestigationListResponse>({
    queryKey: ["investigation", investigationListParams],
    queryFn: () => getAllInvestigations(investigationListParams),
    enabled: !!me && isElevated && !needsScope,
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

  const redoMutation = useMutation({
    mutationFn: (caseId: number) => redoAnalysis(caseId),
    onSuccess: async () => {
      // ponytail: detailsQuery.refetch() already covers this query directly;
      // also invalidating ["investigationDetails"] would double-fire it
      // since the query is active (invalidate + explicit refetch both fetch).
      await Promise.all([
        detailsQuery.refetch(),
        investigationsQuery.refetch(),
        qc.invalidateQueries({ queryKey: ["investigation"] }),
      ]);
    },
  });
  const [redoConfirmOpen, setRedoConfirmOpen] = React.useState(false);

  const commentsQuery = useQuery({
    queryKey: ["caseComments", selectedIdNum],
    queryFn: () => getCaseComments(selectedIdNum),
    enabled: !!me && isElevated && hasNumericSelectedId && openDrawer,
    retry: false,
  });

  const addCommentMutation = useMutation({
    mutationFn: (body: string) => addCaseComment(selectedIdNum, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["caseComments", selectedIdNum] });
    },
  });

  const urlSyncKey = `${searchParams.get("q") ?? ""}|${searchParams.get("open") ?? ""}`;
  const [prevUrlSyncKey, setPrevUrlSyncKey] = React.useState<string | null>(null);
  if (urlSyncKey !== prevUrlSyncKey) {
    setPrevUrlSyncKey(urlSyncKey);
    const urlQ = searchParams.get("q") ?? "";
    if (urlQ) setQ(urlQ);
    const open = searchParams.get("open");
    // Back removes ?open=; keep the drawer in step (row clicks leave the key unchanged).
    if (!open) setOpenDrawer(false);
    if (open) {
      const idNum = Number(open);
      if (Number.isFinite(idNum)) { setSelectedId(idNum); setOpenDrawer(true); }
    }
  }

  const filterKey = [qDebounced, status, type, result, from, to, sort, pageSize].join("|");
  const [prevFilterKey, setPrevFilterKey] = React.useState(filterKey);
  if (filterKey !== prevFilterKey) { setPrevFilterKey(filterKey); setPage(0); }

  const [prevSelectedId, setPrevSelectedId] = React.useState(selectedId);
  if (selectedId !== prevSelectedId) {
    setPrevSelectedId(selectedId);
    setEditMode(false);
  }

  React.useEffect(() => {
    editMutation.reset();
    redoMutation.reset();
    setRedoConfirmOpen(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

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

  const selectedRow = selectedId != null
    ? rows.find((r) => String(r.id) === String(selectedId))
    : undefined;
  const drawerRow = selectedRow || detailsQuery.data;
  // Drop ?open= on close so tapping the same phone ID link again re-triggers the URL sync.
  function closeDrawer() {
    setOpenDrawer(false);
    setEditMode(false);
    editMutation.reset();
    if (searchParams.has("open")) {
      const next = new URLSearchParams(searchParams);
      next.delete("open");
      setSearchParams(next, { replace: true });
    }
  }

  if (meQuery.isLoading) {
    return <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}><CircularProgress /></Box>;
  }
  if (!me) {
    return <Box sx={{ p: 3 }}><Alert severity="error">Not authenticated.</Alert></Box>;
  }
  if (!isElevated) {
    return <Box sx={{ p: 3 }}><Alert severity="error">Access denied.</Alert></Box>;
  }
  if (needsScope) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="info">Select your management scope to view investigations.</Alert>
        <CisoScopeDialog open allowAll={groups.includes("Admin")} />
      </Box>
    );
  }
  if (investigationsQuery.isLoading && !investigationsQuery.data) {
    return <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}><CircularProgress /></Box>;
  }
  if (investigationsQuery.isError) {
    return <Box sx={{ p: 3 }}><Alert severity="error">Failed to load investigations.</Alert></Box>;
  }

  const BADGE_W = 132;

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
      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={2}
        sx={{ mb: 2, justifyContent: "space-between" }}
      >
        <Stack spacing={0.4}>
          <Box>
            <Typography variant="pageTitle" component="h1">
              Investigation
            </Typography>
            <Typography color="text.secondary">
              Browse every case and open one to inspect its analysis.
            </Typography>
          </Box>

          <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
            {/* While a new search loads, the count on screen belongs to the previous one: show no number rather than a wrong "match". */}
            <Chip icon={<AssignmentTurnedInOutlined />} label={investigationsQuery.isPlaceholderData ? "…" : `${total} ${anyFilterActive ? "match" : "total"}`} variant="outlined" />
          </Stack>
        </Stack>

        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
          <Button
            variant="contained"
            onClick={() => navigate("/submit")}
            sx={{ borderRadius: 2, textTransform: "none" }}
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

      <SoftCard sx={{ mb: 2 }}>
        <CardContent sx={{ p: { xs: 2, md: 2.5 }, "&:last-child": { pb: { xs: 2, md: 2.5 } } }}>
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
              <Button
                variant="outlined"
                color="inherit"
                aria-expanded={filtersOpen}
                aria-controls="investigation-filters"
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

            <Collapse id="investigation-filters" in={filtersOpen} unmountOnExit>
              <Stack spacing={1.25} sx={{ pt: 0.5 }}>
                <Stack direction={{ xs: "column", md: "row" }} spacing={1.25} sx={{ alignItems: "stretch" }} >
                  <FormControl fullWidth>
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

                  <FormControl fullWidth>
                    <InputLabel id="type-label">Type</InputLabel>
                    <Select
                      labelId="type-label"
                      label="Type"
                      value={type}
                      onChange={(e) => setType(e.target.value as InvestigationType | "ALL")}
                    >
                      <MenuItem value="ALL">All</MenuItem>
                      {(["FILE", "MAIL", "URL", "IP", "HASH", "IOC", "UNKNOWN"] as const).map((t) => (
                        <MenuItem key={t} value={t}>{t}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>

                  <FormControl fullWidth>
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

                  <FormControl fullWidth>
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
                </Stack>
              </Stack>
            </Collapse>
          </Stack>
        </CardContent>
      </SoftCard>

      <SoftCard>
        <CardContent sx={{ p: 0 }}>
          {investigationsQuery.isFetching ? <LinearProgress /> : null}

          {total === 0 ? (
            <Box sx={{ p: 4 }}>
              {anyFilterActive ? (
                <EmptyState
                  title="No cases match"
                  hint="Try a different search or clear the filters."
                  action={<Button onClick={resetFilters} sx={{ textTransform: "none", mt: 1 }}>Clear filters</Button>}
                />
              ) : (
                <EmptyState
                  title="No cases yet"
                  hint={me.ciso_scope
                    ? `No submissions have been sent within your scope (${me.ciso_scope}).`
                    : "Submitted cases appear here."}
                />
              )}
            </Box>
          ) : isPhone ? (
            <RecentSubmissionsList
              rows={rows.map((r) => ({ ...r, artifact: r.info }))}
              replace
              hrefFor={(r) => `/investigation?open=${encodeURIComponent(String(r.id))}`}
              calmStatus
              secondary={(r) => r.reporter_email ?? "—"}
            />
          ) : (
            <Box sx={{ overflowX: "auto" }}>
              <Table sx={{ minWidth: 1060 }}>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700, width: 140 }}>
                      <TableSortLabel
                        active={sortField === "id"}
                        direction={sortField === "id" ? sortDir : "desc"}
                        onClick={() => handleColumnSort("id")}
                      >ID</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>
                      <TableSortLabel
                        active={sortField === "result"}
                        direction={sortField === "result" ? sortDir : "desc"}
                        onClick={() => handleColumnSort("result")}
                      >Result</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 700, width: 130 }}>
                      <TableSortLabel
                        active={sortField === "status"}
                        direction={sortField === "status" ? sortDir : "desc"}
                        onClick={() => handleColumnSort("status")}
                      >Status</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Artifact</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: 130 }}>
                      <TableSortLabel
                        active={sortField === "creation_date"}
                        direction={sortField === "creation_date" ? sortDir : "desc"}
                        onClick={() => handleColumnSort("creation_date")}
                      >Date</TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 700, width: 80 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>User mail</TableCell>
                  </TableRow>
                </TableHead>

                <TableBody>
                  {rows.map((r) => (
                    <TableRow
                      key={r.id}
                      hover
                      tabIndex={0}
                      sx={{
                        cursor: "pointer",
                        // Copy icons stay out of the scan until the row is pointed at or focused; touch has no hover.
                        "& .copy-reveal": { opacity: 0, "@media (hover: none)": { opacity: 1 } },
                        "&:hover .copy-reveal, &:focus-within .copy-reveal": { opacity: 1 },
                      }}
                      onClick={() => { setSelectedId(r.id); setOpenDrawer(true); }}
                      onKeyDown={(e) => {
                        // Keys on the row's own controls (ID, copy buttons) are theirs: Enter on Copy copies.
                        if (e.target !== e.currentTarget) return;
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
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
                            onClick={(e) => { e.stopPropagation(); setSelectedId(r.id); setOpenDrawer(true); }}
                            sx={{ borderRadius: 2, textTransform: "none", fontWeight: 700, minWidth: 0, px: 1.25, boxShadow: "none" }}
                          >
                            {r.id}
                          </Button>
                          <Box className="copy-reveal" sx={{ display: "inline-flex" }}>
                            <CopyIconButton text={String(r.id)} title="Copy ID" />
                          </Box>
                        </Stack>
                      </TableCell>

                      <TableCell>
                        <ResultChip result={r.result} minWidth={BADGE_W} />
                      </TableCell>

                      <TableCell>
                        <CalmStatusChip status={String(r.status ?? "UNKNOWN")} minWidth={96} />
                      </TableCell>

                      <TableCell sx={{ maxWidth: 360 }}>
                        <Typography noWrap title={r.info || undefined} sx={{ minWidth: 0 }}>
                          {r.info || "—"}
                        </Typography>
                      </TableCell>

                      <TableCell sx={{ whiteSpace: "nowrap" }}>{fmtDate(r.created_at)}</TableCell>

                      <TableCell>
                        <Chip label={r.type} size="small" variant="outlined" sx={{ fontSize: 11 }} />
                      </TableCell>

                      <TableCell sx={{ maxWidth: 280 }}>
                        <Stack direction="row" spacing={0.5} sx={{ alignItems: "center", minWidth: 0 }} >
                          <Typography variant="body2" noWrap title={r.reporter_email || undefined} sx={{ minWidth: 0 }}>
                            {r.reporter_email ?? "—"}
                          </Typography>
                          {r.reporter_email ? (
                            <Box className="copy-reveal" sx={{ display: "inline-flex", flexShrink: 0 }}>
                              <CopyIconButton text={r.reporter_email} title="Copy email" />
                            </Box>
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

      {/* Server-side paging: count is the server total, the page is fetched on change. */}
      {total > 0 ? (
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
      ) : null}

      <InvestigationDrawer
        open={openDrawer}
        onClose={closeDrawer}
        drawerRow={drawerRow}
        caseId={selectedIdNum}
        detailsQuery={detailsQuery}
        editMutation={editMutation}
        editMode={editMode}
        setEditMode={setEditMode}
        editScore={editScore}
        setEditScore={setEditScore}
        editConfidence={editConfidence}
        setEditConfidence={setEditConfidence}
        editClassification={editClassification}
        setEditClassification={setEditClassification}
        onRedo={() => setRedoConfirmOpen(true)}
        commentsQuery={commentsQuery}
        addCommentMutation={addCommentMutation}
        siblings={rows.map((r) => r.id)}
        onNavigate={(id) => {
          // The URL sync selects the case; replace keeps prev/next out of the history.
          const next = new URLSearchParams(searchParams);
          next.set("open", String(id));
          setSearchParams(next, { replace: true });
        }}
      />

      <Dialog open={redoConfirmOpen} onClose={() => setRedoConfirmOpen(false)}>
        <DialogTitle>Redo analysis?</DialogTitle>
        <DialogContent>
          <Typography variant="body2">
            This re-runs every analyzer for this case's artifacts. The current
            verdict is cleared and the case goes back to in-progress. Prior
            analyzer results stay visible as history, they are not deleted.
            This may trigger billed or rate-limited external lookups.
          </Typography>
          {redoMutation.isError ? (
            <Alert severity="error" sx={{ mt: 1.5 }}>
              {(redoMutation.error as { response?: { data?: { detail?: string } } })
                ?.response?.data?.detail ?? "Redo failed. Please try again."}
            </Alert>
          ) : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRedoConfirmOpen(false)} disabled={redoMutation.isPending}>
            Cancel
          </Button>
          <Button
            variant="contained"
            color="warning"
            disabled={redoMutation.isPending || !hasNumericSelectedId}
            startIcon={redoMutation.isPending ? <CircularProgress size={13} color="inherit" /> : <ReplayOutlined />}
            onClick={() => {
              if (!hasNumericSelectedId) return;
              redoMutation.mutate(selectedIdNum, {
                onSuccess: () => setRedoConfirmOpen(false),
              });
            }}
          >
            {redoMutation.isPending ? "Redoing…" : "Redo analysis"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
    </Skeleton>
  );
}