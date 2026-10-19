import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  InputAdornment,
  Slider,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  TextField,
  ToggleButton,
  Typography,
} from "@mui/material";
import { RestoreOutlined, SaveOutlined, SearchOutlined } from "@mui/icons-material";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { listAnalyzers, updateAnalyzerWeight, type Analyzer } from "@/features/settings/api";
import { runBatch, summarise } from "@/features/settings/batch";
import { useReportUnsaved } from "@/features/settings/unsaved";
import {
  clampWeight,
  formatShare,
  round1,
  shares,
  valueText,
  wouldZeroTotal,
} from "@/features/settings/weights";

type SortKey = "name" | "weight" | "share";
type SortDir = "asc" | "desc";

// Rows are grids on phones, so the table, head and body stop sizing columns there.
const rowSx = {
  display: { xs: "grid", sm: "table-row" },
  gridTemplateColumns: "1fr auto",
  borderBottom: { xs: 1, sm: 0 },
  borderColor: "divider",
  "& > td": { borderBottom: { xs: 0, sm: 1 }, borderColor: "divider" },
};

const shareSx = {
  gridColumn: "1 / -1",
  "&::before": { content: '"Share of total: "', display: { xs: "inline", sm: "none" }, color: "text.secondary", typography: "body2" },
};

const ZERO_TOTAL_MESSAGE =
  "At least one active analyzer needs a weight above 0, otherwise no case can be scored.";

/**
 * Text is kept only while it still means the current draft, so a Reset or a
 * slider move replaces whatever was half typed. A cleared field stays empty.
 */
function WeightInput({ name, value, onChange }: { name: string; value: number; onChange: (v: number) => void }) {
  const [text, setText] = React.useState<string | null>(null);
  const keepText = text !== null && (text === "" || clampWeight(parseFloat(text)) === value);
  return (
    <TextField
      type="number"
      size="small"
      value={keepText ? text : value.toFixed(1)}
      onChange={(e) => {
        setText(e.target.value);
        const n = parseFloat(e.target.value);
        if (!Number.isNaN(n)) onChange(clampWeight(n));
      }}
      onBlur={() => setText(null)}
      slotProps={{
        htmlInput: { "aria-label": `${name} weight value`, min: 0, max: 1, step: 0.1 },
      }}
      sx={{ width: 104, flexShrink: 0 }}
    />
  );
}

export function ScoringTable() {
  const qc = useQueryClient();
  const query = useQuery<Analyzer[]>({
    queryKey: ["settings", "scoring"],
    queryFn: listAnalyzers,
    retry: false,
  });

  const [drafts, setDrafts] = React.useState<Record<number, number>>({});
  const [search, setSearch] = React.useState("");
  const [modifiedOnly, setModifiedOnly] = React.useState(false);
  const [sort, setSort] = React.useState<{ key: SortKey; dir: SortDir }>({ key: "name", dir: "asc" });
  const [saving, setSaving] = React.useState(false);
  const [status, setStatus] = React.useState("");
  const [error, setError] = React.useState("");

  const analyzers = React.useMemo(() => query.data ?? [], [query.data]);
  const weightOf = React.useCallback(
    (a: Analyzer) => drafts[a.id] ?? round1(a.weight),
    [drafts],
  );
  const modified = analyzers.filter((a) => weightOf(a) !== round1(a.weight));
  const modifiedIds = new Set(modified.map((a) => a.id));

  useReportUnsaved("scoring", modified.length > 0);

  const withDrafts = React.useMemo(
    () => analyzers.map((a) => ({ id: a.id, is_active: a.is_active, weight: weightOf(a) })),
    [analyzers, weightOf],
  );
  const shareById = React.useMemo(() => shares(withDrafts), [withDrafts]);
  const total = withDrafts.reduce((sum, r) => sum + r.weight, 0);

  const visible = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    const rows = analyzers.filter(
      (a) =>
        (!q || a.name.toLowerCase().includes(q) || a.analyzer_cortex_id.toLowerCase().includes(q)) &&
        (!modifiedOnly || modifiedIds.has(a.id)),
    );
    const value = (a: Analyzer) =>
      sort.key === "weight" ? weightOf(a) : sort.key === "share" ? (shareById.get(a.id) ?? 0) : 0;
    const sign = sort.dir === "asc" ? 1 : -1;
    return rows.sort(
      (a, b) =>
        sign * (sort.key === "name" ? a.name.localeCompare(b.name) : value(a) - value(b)) ||
        a.name.localeCompare(b.name),
    );
    // modifiedIds is derived from the same inputs as weightOf.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analyzers, search, modifiedOnly, sort, weightOf, shareById]);

  function setWeight(id: number, weight: number) {
    setStatus("");
    setError("");
    setDrafts((prev) => ({ ...prev, [id]: weight }));
  }

  function resetAll() {
    setStatus("");
    setError("");
    setDrafts({});
  }

  function toggleSort(key: SortKey) {
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));
  }

  async function saveAll() {
    setStatus("");
    setError("");
    if (modified.length === 0) {
      setStatus("Nothing to save");
      return;
    }
    if (wouldZeroTotal(withDrafts)) {
      setError(ZERO_TOTAL_MESSAGE);
      return;
    }
    setSaving(true);
    try {
      const result = await runBatch(modified, (a) => updateAnalyzerWeight(a.id, weightOf(a)));
      setStatus(summarise(result.ok, result.failed, "saved"));
      await qc.invalidateQueries({ queryKey: ["settings", "scoring"] });
      // Failed rows keep their draft so nothing typed is lost; saved ones now match the server.
      const saved = new Set(result.ok.map((a) => a.id));
      setDrafts((prev) => Object.fromEntries(Object.entries(prev).filter(([id]) => !saved.has(Number(id)))));
    } finally {
      setSaving(false);
    }
  }

  if (query.isLoading) {
    return <Box sx={{ py: 4, display: "grid", placeItems: "center" }}><CircularProgress /></Box>;
  }
  if (query.isError) {
    return <Alert severity="error">Failed to load analyzers.</Alert>;
  }

  const sortHeader = (key: SortKey, label: string) => (
    <TableCell
      sortDirection={sort.key === key ? sort.dir : false}
      aria-sort={sort.key === key ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}
    >
      <TableSortLabel
        active={sort.key === key}
        direction={sort.key === key ? sort.dir : "asc"}
        onClick={() => toggleSort(key)}
        aria-label={`Sort by ${label}`}
      >
        {label}
      </TableSortLabel>
    </TableCell>
  );

  return (
    <Stack spacing={2}>
      <Typography variant="body2" color="text.secondary">
        Weights are relative. A case's score is the weighted average of the analyzers that ran on it, so changing
        one weight changes every analyzer's share.
      </Typography>

      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} sx={{ alignItems: { sm: "center" } }}>
        <TextField
          type="search"
          size="small"
          placeholder="Search by name or id"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          slotProps={{
            htmlInput: { "aria-label": "Search analyzers" },
            input: {
              startAdornment: (
                <InputAdornment position="start"><SearchOutlined fontSize="small" /></InputAdornment>
              ),
            },
          }}
          sx={{ flex: 1, maxWidth: { sm: 360 } }}
        />
        <ToggleButton
          value="modified"
          size="small"
          selected={modifiedOnly}
          aria-pressed={modifiedOnly}
          onChange={() => setModifiedOnly((v) => !v)}
          sx={{ textTransform: "none" }}
        >
          Modified only
        </ToggleButton>
      </Stack>

      <TableContainer sx={{ maxWidth: "100%" }}>
        <Table size="small" aria-label="Analyzer weights" sx={{ display: { xs: "block", sm: "table" } }}>
          <caption style={{ captionSide: "top", textAlign: "left" }}>Analyzer weights</caption>
          <TableHead sx={{ display: { xs: "block", sm: "table-header-group" } }}>
            {/* Phone: rows stack as small cards, so the header becomes a wrapping row of sort buttons. */}
            <TableRow sx={{ display: { xs: "flex", sm: "table-row" }, flexWrap: "wrap" }}>
              {sortHeader("name", "Analyzer")}
              {sortHeader("weight", "Weight")}
              {sortHeader("share", "Share of total")}
              <TableCell sx={{ display: { xs: "none", sm: "table-cell" } }}>State</TableCell>
            </TableRow>
          </TableHead>
          <TableBody sx={{ display: { xs: "block", sm: "table-row-group" } }}>
            {visible.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4}>
                  <Typography variant="body2" color="text.secondary">
                    {analyzers.length === 0 ? "No analyzers found." : "No analyzers match."}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : null}
            {visible.map((a) => {
              const weight = weightOf(a);
              const share = shareById.get(a.id) ?? 0;
              return (
                <TableRow key={a.id} hover sx={rowSx}>
                  <TableCell sx={{ minWidth: { xs: 0, sm: 150 }, gridColumn: 1, gridRow: 1 }}>
                    <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }}>
                      <Typography variant="body2" sx={{ fontWeight: 700 }}>{a.name}</Typography>
                      {!a.is_active ? <Chip size="small" variant="outlined" label="Inactive" /> : null}
                    </Stack>
                    <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace", overflowWrap: "anywhere" }}>
                      {a.analyzer_cortex_id}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ minWidth: { sm: 220 }, gridColumn: "1 / -1" }}>
                    <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
                      <Slider
                        size="small"
                        min={0}
                        max={1}
                        step={0.1}
                        value={weight}
                        onChange={(_, v) => setWeight(a.id, clampWeight(Number(v)))}
                        aria-label={`${a.name} weight`}
                        getAriaValueText={(v) => valueText(v, shareById.get(a.id) ?? 0)}
                        sx={{ minWidth: 80, flex: 1 }}
                      />
                      <WeightInput name={a.name} value={weight} onChange={(v) => setWeight(a.id, v)} />
                    </Stack>
                  </TableCell>
                  <TableCell sx={shareSx}>
                    <Typography variant="body2" color="text.secondary" component="span">
                      {formatShare(share, total)}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ gridColumn: 2, gridRow: 1 }}>
                    {modifiedIds.has(a.id) ? (
                      <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }}>
                        <Box
                          aria-hidden
                          sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: "primary.main", flexShrink: 0 }}
                        />
                        <Typography variant="body2">Modified</Typography>
                      </Stack>
                    ) : null}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>

      {error ? <Alert severity="error" role="alert">{error}</Alert> : null}

      {/* Mounted before any result exists so screen readers announce the text when it lands. */}
      <Typography role="status" variant="body2" color="text.secondary">{status}</Typography>

      <Stack
        direction="row"
        spacing={1.5}
        sx={{
          position: "sticky",
          bottom: 0,
          zIndex: 1,
          alignItems: "center",
          py: 1.25,
          px: 2,
          bgcolor: "background.paper",
          borderTop: 1,
          borderColor: modified.length ? "primary.main" : "divider",
        }}
      >
        <Typography variant="body2" sx={{ flex: 1, fontWeight: 700 }}>
          {modified.length
            ? `${modified.length} unsaved change${modified.length === 1 ? "" : "s"}`
            : "No unsaved changes"}
        </Typography>
        {modified.length ? (
          <Button size="small" startIcon={<RestoreOutlined />} onClick={resetAll} sx={{ textTransform: "none" }}>
            Reset to saved
          </Button>
        ) : null}
        <Button
          size="small"
          variant="contained"
          disabled={saving}
          startIcon={saving ? <CircularProgress size={13} color="inherit" /> : <SaveOutlined />}
          onClick={saveAll}
          sx={{ textTransform: "none" }}
        >
          Save all
        </Button>
      </Stack>
    </Stack>
  );
}
