import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  Checkbox,
  CircularProgress,
  IconButton,
  InputAdornment,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import {
  AddOutlined,
  ContentCopyOutlined,
  DeleteOutlined,
  FileUploadOutlined,
  SearchOutlined,
} from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSnackbar, type SnackbarKey } from "notistack";

import { ensureContrast, flatten } from "@/shared/lib/contrast";

import {
  addFromFile,
  addItems,
  listItems,
  removeItem,
  type EditableListSection,
  type ListItem,
} from "@/features/settings/api";
import { runBatch, summarise } from "@/features/settings/batch";
import { EmptyList } from "@/features/settings/components/cards";
import { EntryDate } from "@/features/settings/components/EntryDate";
import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";

function parseMulti(input: string) {
  return input.split(/[\n,; ]+/g).map((s) => s.trim()).filter(Boolean);
}

const ListItemRow = React.memo(function ListItemRow({
  item,
  selected,
  onToggleSelect,
  onDelete,
  deleting,
  deleteDisabled,
}: {
  item: ListItem;
  selected: boolean;
  /** Stable across renders so memo skips rows a selection change did not touch. */
  onToggleSelect: (id: string) => void;
  onDelete: (item: ListItem) => void;
  deleting: boolean;
  /** True while any removal or bulk run is in flight, so they never overlap. */
  deleteDisabled: boolean;
}) {
  const theme = useTheme();
  const { enqueueSnackbar } = useSnackbar();

  return (
    <Box
      component="li"
      sx={{
        // Date sits beside the value on wide screens and under it on phones, so long lists stay dense.
        display: "grid",
        alignItems: "center",
        columnGap: 0.5,
        gridTemplateColumns: { xs: "auto minmax(0, 1fr) auto auto", sm: "auto minmax(0, 1fr) auto auto auto" },
        gridTemplateAreas: {
          xs: '"check value copy del" ". date date date"',
          sm: '"check value date copy del"',
        },
        pl: 0.5,
        pr: 1,
        py: 0.25,
        borderTop: 1,
        borderColor: "divider",
        // The checked box carries the state; the tint only supports it.
        bgcolor: selected ? alpha(theme.palette.primary.main, 0.08) : undefined,
        "&:hover": { bgcolor: selected ? undefined : "action.hover" },
      }}
    >
      <Checkbox
        size="small"
        sx={{ gridArea: "check" }}
        checked={selected}
        onChange={() => onToggleSelect(item.id)}
        slotProps={{ input: { "aria-label": `Select ${item.value}` } }}
      />

      <Typography
        component="span"
        sx={{ gridArea: "value", py: 0.75, fontFamily: "monospace", fontWeight: 600, fontSize: 13.5, overflowWrap: "anywhere" }}
      >
        {item.value}
      </Typography>
      <EntryDate
        iso={item.created_at}
        label="Added"
        sx={{ gridArea: "date", pb: { xs: 0.5, sm: 0 }, pr: { sm: 1 }, whiteSpace: "nowrap" }}
      />

      <IconButton
        size="small"
        sx={{ gridArea: "copy" }}
        title="Copy value"
        aria-label={`Copy ${item.value}`}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(item.value);
            enqueueSnackbar("Copied.", { variant: "info" });
          } catch { /* ignore */ }
        }}
      >
        <ContentCopyOutlined sx={{ fontSize: 16 }} />
      </IconButton>

      <IconButton
        size="small"
        title="Delete"
        aria-label={`Delete ${item.value}`}
        onClick={() => onDelete(item)}
        disabled={deleting || deleteDisabled}
        sx={{ gridArea: "del", color: "error.main", "&:hover": { background: alpha(theme.palette.error.main, 0.1) } }}
      >
        {deleting
          ? <CircularProgress size={16} color="error" />
          : <DeleteOutlined sx={{ fontSize: 16 }} />}
      </IconButton>
    </Box>
  );
});

function AddBar({
  onAdd,
  placeholder,
  loading,
  title,
}: {
  onAdd: (values: string[]) => void;
  placeholder: string;
  loading: boolean;
  /** Names the field: a placeholder is not an accessible name. */
  title: string;
}) {
  const [input, setInput] = React.useState("");
  const hintId = React.useId();
  const theme = useTheme();
  // The theme's disabled contained button keeps the brand fill and loses the label; same neutral fill as the connector Save button.
  const disabledFill = flatten(theme.palette.action.disabledBackground, theme.palette.background.paper);
  const disabledText = ensureContrast(flatten(theme.palette.text.secondary, disabledFill), disabledFill, 4.5);
  // Hidden while loading: the field is already cleared then, and "enter a value" would be the wrong reason.
  const showHint = !input.trim() && !loading;

  const submit = () => {
    const values = parseMulti(input);
    if (!values.length) return;
    onAdd(values);
    setInput("");
  };

  return (
    <Box>
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
        slotProps={{ htmlInput: { "aria-label": `Add values to ${title}` } }}
        helperText="Enter, comma or space separated. Ctrl+Enter to submit"
        sx={{
          "& .MuiFormHelperText-root": { fontSize: 11, mt: 0.4 },
        }}
      />
      <Button
        variant="contained"
        onClick={submit}
        disabled={!input.trim() || loading}
        aria-describedby={showHint ? hintId : undefined}
        startIcon={loading ? <CircularProgress size={14} color="inherit" /> : <AddOutlined />}
        sx={{
          borderRadius: 2.5,
          textTransform: "none",
          fontWeight: 700,
          minWidth: 90,
          mt: 0.25,
          whiteSpace: "nowrap",
          "&.Mui-disabled": { bgcolor: disabledFill, color: disabledText, backgroundImage: "none" },
        }}
      >
        Add
      </Button>
    </Stack>
    {showHint ? (
      <Typography id={hintId} variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5, ml: 1.75 }}>
        Enter at least one value
      </Typography>
    ) : null}
    </Box>
  );
}

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
  const allSelected = selected > 0 && selected === total;
  const someSelected = selected > 0 && !allSelected;
  // The bar is a translucent hover tint, so the theme's accent and error colours lose contrast on it.
  const theme = useTheme();
  const bar = flatten(theme.palette.action.hover, theme.palette.background.paper);
  const onBar = (c: string) => ensureContrast(flatten(c, bar), bar, 4.5);

  return (
    <Stack direction="row" spacing={1} sx={{ pl: 0.5, pr: 1, py: 0.5, alignItems: "center", bgcolor: "action.hover" }}>
      <Checkbox
        size="small"
        checked={allSelected}
        indeterminate={someSelected}
        onChange={allSelected ? onClearSelection : onSelectAll}
        slotProps={{ input: { "aria-label": allSelected ? "Deselect all" : "Select all" } }}
      />

      <Typography variant="body2" sx={{ flex: 1, fontWeight: 600 }}>
        {selected > 0 ? `${selected} selected` : `${total} ${total === 1 ? "entry" : "entries"}`}
      </Typography>

      {selected > 0 ? (
        <>
          <Button size="small" onClick={onClearSelection} sx={{ textTransform: "none", fontWeight: 600, color: onBar(theme.palette.primary.main) }}>
            Clear
          </Button>
          <Button
            size="small"
            variant="outlined"
            color="error"
            startIcon={deleting ? <CircularProgress size={12} color="error" /> : <DeleteOutlined />}
            disabled={deleting}
            onClick={onDeleteSelected}
            sx={{ textTransform: "none", fontWeight: 600, borderRadius: 2, color: onBar(theme.palette.error.main) }}
          >
            Delete {selected}
          </Button>
        </>
      ) : null}
    </Stack>
  );
}

export function EditableListPanel({
  section,
  title,
  placeholder,
  purpose,
  fileAccept = ".txt,.csv,.json",
}: {
  section: EditableListSection;
  /** Names the list in the bulk-delete confirmation. */
  title: string;
  placeholder: string;
  /** One documented sentence on what the list does; omitted when the repo does not say. */
  purpose?: string;
  fileAccept?: string;
}) {
  const qc = useQueryClient();
  const { enqueueSnackbar, closeSnackbar } = useSnackbar();

  const [filter, setFilter] = React.useState("");
  const [selectedIds, setSelectedIds] = React.useState<Set<string>>(new Set());
  const [deletingId, setDeletingId] = React.useState<string | null>(null);
  // Count captured when the dialog opens so its text does not change while it fades out.
  const [confirmBulk, setConfirmBulk] = React.useState<number | null>(null);
  const [bulkRunning, setBulkRunning] = React.useState(false);
  const [bulkStatus, setBulkStatus] = React.useState<string | null>(null);
  // Snackbar keys already being undone: a fast double click must not re-add twice.
  const undoing = React.useRef(new Set<SnackbarKey>());
  const fileInput = React.useRef<HTMLInputElement>(null);
  const filterInput = React.useRef<HTMLInputElement>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: ["settings", "list", section] });

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
          `Already in Watcher list: ${preview}${extra}, no action needed`,
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

  async function undoRemove(value: string, key: SnackbarKey) {
    if (undoing.current.has(key)) return;
    undoing.current.add(key);
    closeSnackbar(key);
    try {
      const res = await addItems(section, [value]);
      // A 2xx with nothing created means the value was already back (or is in the Watcher list): not a restore.
      if ((res?.created ?? []).length > 0) {
        enqueueSnackbar(`Restored ${value}.`, { variant: "success" });
      } else {
        enqueueSnackbar(`${value} was not restored (already in the list or in the Watcher list)`, { variant: "warning" });
      }
    } catch {
      enqueueSnackbar(`Could not restore ${value}`, { variant: "error" });
    } finally {
      refresh();
    }
  }

  const removeMutation = useMutation({
    mutationFn: (item: ListItem) => removeItem(section, item.id),
    onSuccess: (_res, item) => {
      refresh();
      setSelectedIds((prev) => { const next = new Set(prev); next.delete(item.id); return next; });
      setBulkStatus(null);
      setDeletingId(null);
      // No confirm for one entry: undo is cheaper than a dialog on every click.
      // The Undo colour is set via sx because the theme's text-button colour beats color="inherit" and is unreadable on the snackbar blue.
      enqueueSnackbar(`Removed ${item.value}.`, {
        variant: "info",
        // Longer than the app's 3 s default: the user has to read, aim and click Undo.
        autoHideDuration: 8000,
        action: (key) => (
          <Button size="small" sx={{ color: "inherit", fontWeight: 700 }} onClick={() => undoRemove(item.value, key)}>
            Undo
          </Button>
        ),
      });
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

  // Any selection change makes the last bulk result stale.
  const toggleSelect = React.useCallback((id: string) => {
    setBulkStatus(null);
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  // mutate is referentially stable in TanStack Query, so rows keep the same callback across renders.
  const { mutate: removeMutate } = removeMutation;
  const deleteOne = React.useCallback((item: ListItem) => {
    setDeletingId(item.id);
    removeMutate(item);
  }, [removeMutate]);

  function handleSelectAll() {
    setBulkStatus(null);
    setSelectedIds(new Set(allVisibleIds));
  }

  function handleClear() {
    setBulkStatus(null);
    setSelectedIds(new Set());
  }

  async function runBulkDelete() {
    setConfirmBulk(null);
    const toDelete = filtered.filter((it) => selectedIds.has(it.id));
    setBulkRunning(true);
    setBulkStatus(null);
    const { ok, failed } = await runBatch(toDelete, async (it) => {
      setDeletingId(it.id);
      await removeItem(section, it.id);
    });
    // Inline only: the status region is mounted even when the list ends up empty, and a snackbar would be announced twice.
    setBulkStatus(summarise(ok, failed, "deleted"));
    // Drop only what was deleted: failed rows stay selected for a retry, and selected rows a filter hides stay too.
    const deleted = new Set(ok.map((it) => it.id));
    setSelectedIds((prev) => new Set([...prev].filter((id) => !deleted.has(id))));
    setDeletingId(null);
    setBulkRunning(false);
    await refresh();
    // The Delete button this run started from is disabled, then gone, and the dialog's own button leaves with its fade: without
    // this focus falls to <body>. Never steal it from a control the user has since moved to.
    const now = document.activeElement as HTMLElement | null;
    if (!now || now === document.body || (now as HTMLButtonElement).disabled || now.closest('[role="dialog"]')) {
      filterInput.current?.focus();
    }
  }

  return (
    <Stack spacing={2}>
      {purpose ? <Typography variant="body2" color="text.secondary">{purpose}</Typography> : null}

      <AddBar
        title={title}
        placeholder={placeholder}
        onAdd={(values) => addMutation.mutate(values)}
        loading={addMutation.isPending}
      />

      <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap", rowGap: 1 }}>
        <TextField
          size="small"
          placeholder="Filter entries…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          sx={{ flex: "1 1 220px" }}
          slotProps={{
            htmlInput: { "aria-label": `Search ${title}`, ref: filterInput },
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
          size="small"
          variant="outlined"
          // A real button that clicks the hidden input: a label styled as a button does nothing on Enter or Space.
          onClick={() => fileInput.current?.click()}
          startIcon={importMutation.isPending ? <CircularProgress size={13} /> : <FileUploadOutlined />}
          disabled={importMutation.isPending}
          sx={{ borderRadius: 2.5, textTransform: "none", fontWeight: 600 }}
        >
          Import file
          <input
            hidden
            ref={fileInput}
            type="file"
            accept={fileAccept}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) importMutation.mutate(f);
              e.currentTarget.value = "";
            }}
          />
        </Button>

        <Chip size="small" label={`${items.length} total`} variant="outlined" />
      </Stack>

      {/* Mounted before any result exists so screen readers announce the text when it lands. Empty it is visually hidden and out of
          flow, never display:none, which would drop the live region from the accessibility tree. */}
      <Typography
        role="status"
        variant="body2"
        color="text.secondary"
        sx={{
          "&:empty": { position: "absolute", width: "1px", height: "1px", m: 0, overflow: "hidden", clip: "rect(0 0 0 0)" },
        }}
      >
        {bulkStatus}
      </Typography>

      {listQuery.isLoading ? (
        <Box sx={{ py: 4, display: "grid", placeItems: "center" }}>
          <CircularProgress size={24} />
        </Box>
      ) : listQuery.isError ? (
        <Alert severity="error">Failed to load list.</Alert>
      ) : filtered.length === 0 ? (
        <EmptyList message={filter ? `No entries matching "${filter}"` : "No entries yet. Paste values above or import a file."} />
      ) : (
        <Box sx={{ border: 1, borderColor: "divider", borderRadius: 2, overflow: "hidden" }}>
          <BulkToolbar
            total={filtered.length}
            selected={selectedCount}
            onSelectAll={handleSelectAll}
            onClearSelection={handleClear}
            onDeleteSelected={() => setConfirmBulk(selectedCount)}
            deleting={removeMutation.isPending || bulkRunning}
          />
          {/* Focusable so keyboard users can scroll a long list. */}
          <Box
            role="region"
            tabIndex={0}
            aria-label={`${title} entries`}
            sx={{ maxHeight: 440, overflowY: "auto" }}
          >
            <Box component="ul" sx={{ listStyle: "none", m: 0, p: 0 }}>
              {filtered.map((it) => (
                <ListItemRow
                  key={it.id}
                  item={it}
                  selected={selectedIds.has(it.id)}
                  onToggleSelect={toggleSelect}
                  onDelete={deleteOne}
                  deleting={deletingId === it.id && (removeMutation.isPending || bulkRunning)}
                  deleteDisabled={bulkRunning || removeMutation.isPending}
                />
              ))}
            </Box>
          </Box>
        </Box>
      )}

      <ConfirmDialog
        open={confirmBulk !== null}
        title="Delete entries"
        body={`Delete ${confirmBulk} ${confirmBulk === 1 ? "entry" : "entries"} from ${title}? This cannot be undone.`}
        confirmLabel="Delete"
        destructive
        onConfirm={runBulkDelete}
        onCancel={() => setConfirmBulk(null)}
      />
    </Stack>
  );
}
