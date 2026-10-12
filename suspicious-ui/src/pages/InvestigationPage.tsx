import * as React from "react";
import {
  Alert,
  LinearProgress,
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
  ContentCopyOutlined,
  RestartAltOutlined,
  ReplayOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { useNavigate, useSearchParams } from "react-router";
import { alpha } from "@mui/material/styles";
import { useTheme } from "@mui/material/styles";

import { getMe, type Me } from "@/api/auth";
import { getProfile } from "@/features/profile/api";
import { UserAvatar } from "@/features/profile/components/UserAvatar";
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
import { StatusChip } from "@/shared/components/StatusChip";
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
  short,
} from "@/features/investigation/utils";

// Page

export default function InvestigationPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
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

  const anyFilterActive =
    !!qDebounced || status !== "ALL" || type !== "ALL" || result !== "ALL" || !!from || !!to;
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


  const meQuery = useQuery<Me>({ queryKey: ["me"], queryFn: getMe, retry: false });
  const me = meQuery.data;

  const profileQuery = useQuery({
    queryKey: ["profile"],
    queryFn: getProfile,
    enabled: !!me,
    retry: false,
  });

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
  const start = total === 0 ? 0 : page * pageSize;
  const end = Math.min(total, start + rows.length);

  const selectedRow = selectedId != null
    ? rows.find((r) => String(r.id) === String(selectedId))
    : undefined;
  const drawerRow = selectedRow || detailsQuery.data;
  function closeDrawer() { setOpenDrawer(false); setEditMode(false); editMutation.reset(); }

  async function copyEmail(email?: string) {
    if (!email) return;
    try { await navigator.clipboard.writeText(email); } catch { /* ignore */ }
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
          <Stack direction="row" spacing={1.25} sx={{ alignItems: "center" }} >
            <UserAvatar
              avatar={profileQuery.data?.avatar}
              initials={(me.username?.[0] ?? "A").toUpperCase()}
              sx={{ width: 46, height: 46, fontWeight: 950 }}
            />
            <Box>
              <Typography variant="pageTitle" component="h1">
                Investigation
              </Typography>
              <Typography color="text.secondary">
                Browse every case and open one to inspect its analysis.
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
            <Chip icon={<AssignmentTurnedInOutlined />} label={`${total} shown`} variant="outlined" />
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
                  {(["FILE", "MAIL", "URL", "IP", "HASH", "IOC", "UNKNOWN"] as const).map((t) => (
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

      <SoftCard>
        <CardContent sx={{ p: 0 }}>
          {investigationsQuery.isFetching ? <LinearProgress /> : null}

          {total === 0 ? (
            <Box sx={{ p: 3 }}>
              <Alert severity="info">
                {anyFilterActive
                  ? "No investigations match your filters."
                  : me.ciso_scope
                    ? `No submissions have been sent within your scope (${me.ciso_scope}).`
                    : "No investigations yet."}
              </Alert>
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

                      <TableCell>
                        <ResultChip result={r.result} minWidth={BADGE_W} />
                      </TableCell>

                      <TableCell>
                        <StatusChip status={r.status as any} minWidth={96} />
                      </TableCell>

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

                      <TableCell sx={{ whiteSpace: "nowrap" }}>{fmtDate(r.created_at)}</TableCell>

                      <TableCell>
                        <Chip
                          label={r.type}
                          size="small"
                          variant="outlined"
                          sx={{ fontWeight: 900, fontSize: 11 }}
                        />
                      </TableCell>

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
          // ponytail: selects directly and mirrors ?open= (replace); Task 4 owns the rest of the URL sync.
          setSelectedId(id);
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