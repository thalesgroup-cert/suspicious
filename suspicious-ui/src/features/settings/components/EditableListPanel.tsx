import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Collapse,
  IconButton,
  InputAdornment,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import {
  AddOutlined,
  CheckBoxOutlineBlank,
  CheckBoxOutlined,
  ContentCopyOutlined,
  DeleteOutlined,
  FileUploadOutlined,
  IndeterminateCheckBoxOutlined,
  SearchOutlined,
} from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSnackbar } from "notistack";

import {
  addFromFile,
  addItems,
  listItems,
  removeItem,
  type EditableListSection,
  type ListItem,
} from "@/features/settings/api";
import { EmptyList, InnerCard } from "@/features/settings/components/cards";

function parseMulti(input: string) {
  return input.split(/[\n,; ]+/g).map((s) => s.trim()).filter(Boolean);
}

// ListItemRow — individual item with copy + delete
function ListItemRow({
  item,
  selected,
  onToggleSelect,
  onDelete,
  deleting,
  selectionMode,
}: {
  item: ListItem;
  selected: boolean;
  onToggleSelect: () => void;
  onDelete: () => void;
  deleting: boolean;
  selectionMode: boolean;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const { enqueueSnackbar } = useSnackbar();

  return (
    <InnerCard
      hover
      sx={{
        px: 1.5,
        py: 1,
        display: "flex",
        alignItems: "center",
        gap: 1.25,
        borderColor: selected
          ? alpha(theme.palette.primary.main, isDark ? 0.45 : 0.5)
          : undefined,
        background: selected
          ? alpha(theme.palette.primary.main, isDark ? 0.08 : 0.05)
          : undefined,
        transition: "all .14s ease",
      }}
    >
      {/* Selection checkbox */}
      <IconButton
        size="small"
        onClick={onToggleSelect}
        sx={{ opacity: selectionMode || selected ? 1 : 0, transition: "opacity .14s", p: 0.25 }}
        aria-label={selected ? "Deselect" : "Select"}
      >
        {selected
          ? <CheckBoxOutlined fontSize="small" color="primary" />
          : <CheckBoxOutlineBlank fontSize="small" />}
      </IconButton>

      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography
          sx={{
            fontWeight: 700,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            fontSize: 13.5,
          }}
        >
          {item.value}
        </Typography>
        {item.created_at ? (
          <Typography variant="caption" color="text.disabled" sx={{ fontSize: 11 }}>
            Added {new Date(item.created_at).toLocaleString()}
          </Typography>
        ) : null}
      </Box>

      <Stack direction="row" spacing={0.5}>
        <Tooltip title="Copy value">
          <IconButton
            size="small"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(item.value);
                enqueueSnackbar("Copied.", { variant: "info" });
              } catch { /* ignore */ }
            }}
            sx={{ opacity: 0.55, "&:hover": { opacity: 1 } }}
          >
            <ContentCopyOutlined sx={{ fontSize: 14 }} />
          </IconButton>
        </Tooltip>

        <Tooltip title="Delete">
          <IconButton
            size="small"
            onClick={onDelete}
            disabled={deleting}
            sx={{
              color: theme.palette.error.main,
              opacity: 0.55,
              "&:hover": { opacity: 1, background: alpha(theme.palette.error.main, 0.1) },
            }}
          >
            {deleting
              ? <CircularProgress size={13} color="error" />
              : <DeleteOutlined sx={{ fontSize: 14 }} />}
          </IconButton>
        </Tooltip>
      </Stack>
    </InnerCard>
  );
}

// AddBar — textarea + submit (supports multi-line paste)
function AddBar({
  onAdd,
  placeholder,
  loading,
}: {
  onAdd: (values: string[]) => void;
  placeholder: string;
  loading: boolean;
}) {
  const [input, setInput] = React.useState("");

  const submit = () => {
    const values = parseMulti(input);
    if (!values.length) return;
    onAdd(values);
    setInput("");
  };

  return (
    <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start" }} >
      <TextField
        size="small"
        placeholder={placeholder}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
            e.preventDefault();
            submit();
          }
        }}
        multiline
        maxRows={3}
        fullWidth
        helperText="Enter, comma or space separated — Ctrl+Enter to submit"
        sx={{
          "& .MuiFormHelperText-root": { fontSize: 11, mt: 0.4 },
        }}
      />
      <Button
        variant="contained"
        onClick={submit}
        disabled={!input.trim() || loading}
        startIcon={loading ? <CircularProgress size={14} color="inherit" /> : <AddOutlined />}
        sx={{
          borderRadius: 2.5,
          textTransform: "none",
          fontWeight: 900,
          minWidth: 90,
          mt: 0.25,
          whiteSpace: "nowrap",
        }}
      >
        Add
      </Button>
    </Stack>
  );
}

// BulkToolbar
function BulkToolbar({
  total,
  selected,
  onSelectAll,
  onClearSelection,
  onDeleteSelected,
  deleting,
}: {
  total: number;
  selected: number;
  onSelectAll: () => void;
  onClearSelection: () => void;
  onDeleteSelected: () => void;
  deleting: boolean;
}) {
  const theme = useTheme();
  const allSelected = selected > 0 && selected === total;
  const someSelected = selected > 0 && !allSelected;

  return (
    <Stack
      direction="row"
      spacing={1}
      sx={{ px: 1.25,
        py: 0.75,
        borderRadius: 2,
        background: alpha(theme.palette.primary.main, 0.07),
        border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`, alignItems: "center" }}
    >
      <IconButton size="small" onClick={allSelected ? onClearSelection : onSelectAll} sx={{ p: 0.25 }}>
        {allSelected
          ? <CheckBoxOutlined fontSize="small" color="primary" />
          : someSelected
          ? <IndeterminateCheckBoxOutlined fontSize="small" color="primary" />
          : <CheckBoxOutlineBlank fontSize="small" />}
      </IconButton>

      <Typography variant="body2" sx={{ flex: 1, fontWeight: 700 }}>
        {selected > 0 ? `${selected} selected` : `${total} item${total !== 1 ? "s" : ""}`}
      </Typography>

      {selected > 0 ? (
        <>
          <Button
            size="small"
            onClick={onClearSelection}
            sx={{ textTransform: "none", fontWeight: 700 }}
          >
            Clear
          </Button>
          <Button
            size="small"
            variant="outlined"
            color="error"
            startIcon={deleting ? <CircularProgress size={12} color="error" /> : <DeleteOutlined />}
            disabled={deleting}
            onClick={onDeleteSelected}
            sx={{ textTransform: "none", fontWeight: 900, borderRadius: 2 }}
          >
            Delete {selected}
          </Button>
        </>
      ) : null}
    </Stack>
  );
}

// EditableListPanel — full-featured list manager
export function EditableListPanel({
  section,
  placeholder,
  fileAccept = ".txt,.csv,.json",
}: {
  section: EditableListSection;
  placeholder: string;
  fileAccept?: string;
}) {
  const qc = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const [filter, setFilter] = React.useState("");
  const [selectedIds, setSelectedIds] = React.useState<Set<string>>(new Set());
  const [showFilter, setShowFilter] = React.useState(false);
  const [deletingId, setDeletingId] = React.useState<string | null>(null);

  const listQuery = useQuery<ListItem[]>({
    queryKey: ["settings", "list", section],
    queryFn: () => listItems(section),
    retry: false,
  });

  const addMutation = useMutation({
    mutationFn: (values: string[]) => addItems(section, values),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["settings", "list", section] });

      const created  = (res?.created  ?? []).length;
      const dupes    = (res?.duplicates ?? []) as string[];
      const watchers = (res?.watcher_conflicts ?? []) as string[];

      // ── Success: items created ───────────────────────────────────────
      if (created > 0) {
        enqueueSnackbar(
          `${created} value${created !== 1 ? "s" : ""} added.`,
          { variant: "success" }
        );
      }

      // ── Warning: already in this list ────────────────────────────────
      if (dupes.length > 0) {
        const preview = dupes.slice(0, 3).join(", ");
        const extra   = dupes.length > 3 ? ` +${dupes.length - 3} more` : "";
        enqueueSnackbar(
          `Already in list: ${preview}${extra}`,
          { variant: "warning" }
        );
      }

      // ── Info: already in paired Watcher list ─────────────────────────
      if (watchers.length > 0) {
        const preview = watchers.slice(0, 3).join(", ");
        const extra   = watchers.length > 3 ? ` +${watchers.length - 3} more` : "";
        enqueueSnackbar(
          `Already in Watcher list: ${preview}${extra} — no action needed`,
          { variant: "info" }
        );
      }

      // ── Nothing happened ─────────────────────────────────────────────
      if (created === 0 && dupes.length === 0 && watchers.length === 0) {
        enqueueSnackbar("No values were added.", { variant: "info" });
      }
    },
    onError: () => enqueueSnackbar("Failed to add values.", { variant: "error" }),
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => removeItem(section, id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "list", section] });
      setSelectedIds((prev) => { const next = new Set(prev); next.delete(deletingId!); return next; });
      setDeletingId(null);
    },
    onError: () => { enqueueSnackbar("Failed to remove item.", { variant: "error" }); setDeletingId(null); },
  });

  const importMutation = useMutation({
    mutationFn: (file: File) => addFromFile(section, file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "list", section] });
      enqueueSnackbar("File imported.", { variant: "success" });
    },
    onError: () => enqueueSnackbar("Failed to import file.", { variant: "error" }),
  });

  const items = React.useMemo(() => listQuery.data ?? [], [listQuery.data]);
  const filtered = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    return q ? items.filter((it) => it.value.toLowerCase().includes(q)) : items;
  }, [items, filter]);

  const allVisibleIds = filtered.map((it) => it.id);
  const selectedCount = allVisibleIds.filter((id) => selectedIds.has(id)).length;

  function handleSelectAll() {
    setSelectedIds(new Set(allVisibleIds));
  }

  function handleClear() {
    setSelectedIds(new Set());
  }

  async function handleBulkDelete() {
    const toDelete = allVisibleIds.filter((id) => selectedIds.has(id));
    for (const id of toDelete) {
      setDeletingId(id);
      await removeItem(section, id);
    }
    qc.invalidateQueries({ queryKey: ["settings", "list", section] });
    setSelectedIds(new Set());
    setDeletingId(null);
    enqueueSnackbar(`${toDelete.length} item${toDelete.length !== 1 ? "s" : ""} deleted.`, { variant: "success" });
  }

  const selectionMode = selectedIds.size > 0;

  return (
    <Stack spacing={2}>
      {/* Add bar */}
      <AddBar
        placeholder={placeholder}
        onAdd={(values) => addMutation.mutate(values)}
        loading={addMutation.isPending}
      />

      {/* Toolbar row */}
      <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }} >
        <Button
          size="small"
          variant="outlined"
          component="label"
          startIcon={importMutation.isPending ? <CircularProgress size={13} /> : <FileUploadOutlined />}
          disabled={importMutation.isPending}
          sx={{ borderRadius: 2.5, textTransform: "none", fontWeight: 900 }}
        >
          Import file
          <input
            hidden
            type="file"
            accept={fileAccept}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) importMutation.mutate(f);
              e.currentTarget.value = "";
            }}
          />
        </Button>

        <Tooltip title={showFilter ? "Hide search" : "Search items"}>
          <IconButton
            size="small"
            onClick={() => setShowFilter((v) => !v)}
            sx={{
              border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
              borderRadius: 2,
              color: showFilter ? theme.palette.primary.main : undefined,
            }}
          >
            <SearchOutlined fontSize="small" />
          </IconButton>
        </Tooltip>

        <Chip
          size="small"
          label={`${items.length} total`}
          variant="outlined"
          sx={{ ml: "auto" }}
        />
      </Stack>

      {/* Search collapse */}
      <Collapse in={showFilter}>
        <TextField
          size="small"
          placeholder="Filter items…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          autoFocus
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
      </Collapse>

      {/* List */}
      {listQuery.isLoading ? (
        <Box sx={{ py: 4, display: "grid", placeItems: "center" }}>
          <CircularProgress size={24} />
        </Box>
      ) : listQuery.isError ? (
        <Alert severity="error">Failed to load list.</Alert>
      ) : (
        <Stack spacing={1}>
          {/* Bulk toolbar — only when items exist */}
          {filtered.length > 0 ? (
            <BulkToolbar
              total={filtered.length}
              selected={selectedCount}
              onSelectAll={handleSelectAll}
              onClearSelection={handleClear}
              onDeleteSelected={handleBulkDelete}
              deleting={removeMutation.isPending}
            />
          ) : null}

          {/* Item list */}
          {filtered.length === 0 ? (
            <EmptyList message={filter ? `No items matching "${filter}"` : "No items yet."} />
          ) : (
            <Stack
              spacing={0.6}
              sx={{
                maxHeight: 400,
                overflowY: "auto",
                pr: 0.5,
                // thin scrollbar
                "&::-webkit-scrollbar": { width: 4 },
                "&::-webkit-scrollbar-thumb": {
                  borderRadius: 999,
                  background: alpha(theme.palette.divider, 0.5),
                },
              }}
            >
              {filtered.map((it) => (
                <ListItemRow
                  key={it.id}
                  item={it}
                  selected={selectedIds.has(it.id)}
                  onToggleSelect={() => setSelectedIds((prev) => {
                    const next = new Set(prev);
                    next.has(it.id) ? next.delete(it.id) : next.add(it.id);
                    return next;
                  })}
                  onDelete={() => {
                    setDeletingId(it.id);
                    removeMutation.mutate(it.id);
                  }}
                  deleting={deletingId === it.id && removeMutation.isPending}
                  selectionMode={selectionMode}
                />
              ))}
            </Stack>
          )}
        </Stack>
      )}
    </Stack>
  );
}
