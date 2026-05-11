// src/pages/SettingsPage.tsx
import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Grid,
  IconButton,
  InputAdornment,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
  Slider,
  Collapse,
  Badge,
  LinearProgress,
} from "@mui/material";
import {
  AddOutlined,
  DeleteOutlined,
  FileUploadOutlined,
  RefreshOutlined,
  SearchOutlined,
  SettingsOutlined,
  BlockOutlined,
  CheckCircleOutlined,
  CampaignOutlined,
  InsertDriveFileOutlined,
  ExtensionOutlined,
  GroupsOutlined,
  MailOutlined,
  TuneOutlined,
  ShieldOutlined,
  ContentCopyOutlined,
  LockOutlined,
  PowerSettingsNewOutlined,
  CheckBoxOutlined,
  CheckBoxOutlineBlank,
  IndeterminateCheckBoxOutlined,
  DoneAllOutlined,
  SaveOutlined,
  RestoreOutlined,
  VisibilityOutlined,
  VisibilityOffOutlined,
} from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSnackbar } from "notistack";

import { getMe, type Me } from "@/api/auth";
import {
  addFromFile,
  addItems,
  getFeederStatus,
  listAnalyzers,
  listItems,
  removeItem,
  setFeederStatus,
  updateAnalyzerWeight,
  type Analyzer,
  type CisoUser,
  type ListItem,
  type SettingsSection,
  type EditableListSection,
} from "@/features/settings/api";
import FeederHealthBadge from "@/shared/components/FeederHealthBadge";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SectionKind = "list" | "toggle" | "scoring" | "ciso_users" | "domain_pair";

type SectionMeta = {
  key: SettingsSection;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  kind: SectionKind;
  badge?: number;
};

// ---------------------------------------------------------------------------
// SoftCard — shared theme-aware card (mirrors other pages)
// ---------------------------------------------------------------------------

function SoftCard(props: React.PropsWithChildren<{ sx?: object }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Card
      sx={{
        borderRadius: 4,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.9)}`,
        background: isDark
          ? `linear-gradient(180deg, ${alpha("#fff", 0.03)}, ${alpha("#fff", 0.02)})`
          : `linear-gradient(180deg, ${alpha("#fff", 0.88)}, ${alpha(theme.palette.grey[50], 0.96)})`,
        boxShadow: isDark
          ? "0 12px 32px rgba(0,0,0,.28)"
          : "0 10px 28px rgba(15,23,42,.06)",
        ...props.sx,
      }}
    >
      {props.children}
    </Card>
  );
}

// A tighter inner card for list items / sub-panels
function InnerCard(props: React.PropsWithChildren<{ sx?: object; hover?: boolean }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Box
      sx={{
        borderRadius: 2.5,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.14 : 0.55)}`,
        background: isDark ? alpha("#fff", 0.025) : alpha(theme.palette.background.paper, 0.6),
        transition: "border-color .15s ease, background .15s ease",
        ...(props.hover && {
          "&:hover": {
            borderColor: alpha(theme.palette.divider, isDark ? 0.28 : 0.8),
            background: isDark ? alpha("#fff", 0.04) : alpha(theme.palette.background.paper, 0.9),
          },
        }),
        ...props.sx,
      }}
    >
      {props.children}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Icon badge helper
// ---------------------------------------------------------------------------

function NavIcon({ icon, isDark }: { icon: React.ReactNode; isDark: boolean }) {
  const theme = useTheme();
  return (
    <Box
      sx={{
        width: 32,
        height: 32,
        borderRadius: 2,
        display: "grid",
        placeItems: "center",
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.6)}`,
        background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
        flexShrink: 0,
        "& svg": { fontSize: 17 },
      }}
    >
      {icon}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// parseMulti
// ---------------------------------------------------------------------------

function parseMulti(input: string) {
  return input.split(/[\n,; ]+/g).map((s) => s.trim()).filter(Boolean);
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

function EmptyList({ message }: { message: string }) {
  const theme = useTheme();
  return (
    <Stack spacing={1} sx={{ py: 5, alignItems: "center", justifyContent: "center" }}>
      <Box
        sx={{
          width: 48,
          height: 48,
          borderRadius: 3,
          display: "grid",
          placeItems: "center",
          background: alpha(theme.palette.action.hover, 0.5),
          "& svg": { fontSize: 26, opacity: 0.4 },
        }}
      >
        <SearchOutlined />
      </Box>
      <Typography variant="body2" color="text.disabled" sx={{ fontWeight: 600 }}>
        {message}
      </Typography>
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// ListItemRow — individual item with copy + delete
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// AddBar — textarea + submit (supports multi-line paste)
// ---------------------------------------------------------------------------

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
  const theme = useTheme();

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

// ---------------------------------------------------------------------------
// BulkToolbar
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// EditableListPanel — full-featured list manager
// ---------------------------------------------------------------------------

function EditableListPanel({
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

  const items = listQuery.data ?? [];
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

// ---------------------------------------------------------------------------
// ReadOnlyListPanel
// ---------------------------------------------------------------------------

function ReadOnlyListPanel({
  section,
  title,
  subtitle,
}: {
  section: "watcher_legit_domains" | "watcher_monitored_domains";
  title: string;
  subtitle: string;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const [filter, setFilter] = React.useState("");
  const [showItems, setShowItems] = React.useState(false);

  const listQuery = useQuery<ListItem[]>({
    queryKey: ["settings", "list", section],
    queryFn: () => listItems(section),
    retry: false,
  });

  const items = listQuery.data ?? [];
  const filtered = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    return q ? items.filter((it) => it.value.toLowerCase().includes(q)) : items;
  }, [items, filter]);

  return (
    <InnerCard sx={{ p: 2 }}>
      <Stack spacing={1.5}>
        <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", justifyContent: "space-between" }} >
          <Box>
            <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }} >
              <LockOutlined sx={{ fontSize: 14, opacity: 0.55 }} />
              <Typography sx={{ fontWeight: 950, fontSize: 14 }} >{title}</Typography>
            </Stack>
            <Typography variant="caption" color="text.secondary">{subtitle}</Typography>
          </Box>
          <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }} >
            <Chip size="small" label="Watcher sync" color="info" variant="outlined" />
            <Chip size="small" label={`${items.length}`} variant="outlined" />
          </Stack>
        </Stack>

        <Stack direction="row" spacing={1}>
          <TextField
            size="small"
            placeholder="Search synced domains…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
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
          <Tooltip title={showItems ? "Hide list" : "Show list"}>
            <IconButton
              size="small"
              onClick={() => setShowItems((v) => !v)}
              sx={{
                border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
                borderRadius: 2,
                color: showItems ? theme.palette.primary.main : undefined,
              }}
            >
              {showItems ? <VisibilityOffOutlined fontSize="small" /> : <VisibilityOutlined fontSize="small" />}
            </IconButton>
          </Tooltip>
        </Stack>

        <Collapse in={showItems}>
          {listQuery.isLoading ? (
            <Box sx={{ py: 3, display: "grid", placeItems: "center" }}><CircularProgress size={20} /></Box>
          ) : listQuery.isError ? (
            <Alert severity="error">Failed to load.</Alert>
          ) : filtered.length === 0 ? (
            <EmptyList message={filter ? `No items matching "${filter}"` : "No synced items."} />
          ) : (
            <Stack
              spacing={0.5}
              sx={{
                maxHeight: 320,
                overflowY: "auto",
                pr: 0.25,
                "&::-webkit-scrollbar": { width: 4 },
                "&::-webkit-scrollbar-thumb": { borderRadius: 999, background: alpha(theme.palette.divider, 0.5) },
              }}
            >
              {filtered.map((it) => (
                <InnerCard key={it.id} sx={{ px: 1.5, py: 0.9 }}>
                  <Typography sx={{ fontWeight: 700, fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {it.value}
                  </Typography>
                  {it.created_at ? (
                    <Typography variant="caption" color="text.disabled" sx={{ fontSize: 11 }}>
                      {new Date(it.created_at).toLocaleString()}
                    </Typography>
                  ) : null}
                </InnerCard>
              ))}
            </Stack>
          )}
        </Collapse>
      </Stack>
    </InnerCard>
  );
}

// ---------------------------------------------------------------------------
// DomainPairPanel
// ---------------------------------------------------------------------------

function DomainPairPanel({ editableSection }: { editableSection: "domains_allow" | "domains_deny" }) {
  const isAllow = editableSection === "domains_allow";

  return (
    <Stack spacing={2}>
      <EditableListPanel
        section={editableSection}
        placeholder="Paste domains, one per line or comma-separated…"
      />
      <ReadOnlyListPanel
        section={isAllow ? "watcher_legit_domains" : "watcher_monitored_domains"}
        title={isAllow ? "Watcher legit domains" : "Watcher monitored domains"}
        subtitle="Read-only — synchronized from Watcher automatically."
      />
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// FeederPanel — enhanced toggle with status indicator
// ---------------------------------------------------------------------------

function FeederPanel() {
  const qc = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const statusQuery = useQuery({
    queryKey: ["settings", "email_feeder"],
    queryFn: getFeederStatus,
    retry: false,
  });

  const toggleMutation = useMutation({
    mutationFn: (enabled: boolean) => setFeederStatus(enabled),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["settings", "email_feeder"] });
      enqueueSnackbar(
        res.enabled ? "Email feeder enabled." : "Email feeder disabled.",
        { variant: res.enabled ? "success" : "info" }
      );
    },
    onError: () => enqueueSnackbar("Failed to update feeder status.", { variant: "error" }),
  });

  const enabled = statusQuery.data?.enabled ?? false;
  const pending = statusQuery.isLoading || toggleMutation.isPending;

  return (
    <Stack spacing={2}>
      <InnerCard sx={{ p: 0, overflow: "hidden" }}>
        {/* Status bar accent */}
        <Box
          sx={{
            height: 4,
            background: enabled
              ? "linear-gradient(90deg, #22C55E, #16A34A)"
              : alpha(theme.palette.divider, 0.4),
            transition: "background .4s ease",
          }}
        />

        <Stack
          direction={{ xs: "column", sm: "row" }}
          spacing={2}
          sx={{ p: 2.5, alignItems: { sm: "center" }, justifyContent: "space-between" }}
        >
          <Stack direction="row" spacing={1.75} sx={{ alignItems: "center" }} >
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 3,
                display: "grid",
                placeItems: "center",
                background: enabled
                  ? alpha("#22C55E", 0.12)
                  : alpha(theme.palette.action.hover, 0.5),
                border: `1px solid ${enabled ? alpha("#22C55E", 0.3) : alpha(theme.palette.divider, isDark ? 0.18 : 0.5)}`,
                transition: "all .3s ease",
                "& svg": { fontSize: 24, color: enabled ? "#22C55E" : undefined, transition: "color .3s ease" },
              }}
            >
              <PowerSettingsNewOutlined />
            </Box>

            <Box>
              <Typography sx={{ fontWeight: 950, fontSize: 15 }} >Email feeder</Typography>
              <Typography variant="body2" color="text.secondary">
                Automatically ingest suspicious emails and create cases.
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1.5} sx={{ alignItems: "center", flexWrap: "wrap" }} >
            {/* Live runtime status — polled from feeder /health */}
            <FeederHealthBadge />
            {/* Operator-controlled toggle (Django settings) */}
            <Chip
              size="small"
              label={pending ? "…" : enabled ? "Running" : "Stopped"}
              sx={{
                fontWeight: 900,
                bgcolor: enabled
                  ? alpha("#22C55E", 0.12)
                  : alpha(theme.palette.action.hover, 0.6),
                color: enabled ? "#22C55E" : "text.secondary",
                border: `1px solid ${enabled ? alpha("#22C55E", 0.3) : alpha(theme.palette.divider, 0.4)}`,
                transition: "all .3s ease",
              }}
            />
            <Switch
              checked={enabled}
              onChange={(e) => toggleMutation.mutate(e.target.checked)}
              disabled={pending}
              color="success"
            />
          </Stack>
        </Stack>
      </InnerCard>

      <InnerCard sx={{ p: 2 }}>
        <Typography variant="body2" color="text.secondary" sx={{ fontSize: 13 }}>
          When enabled, the feeder polls the configured mailbox and automatically creates
          new analysis cases for each suspicious message. Disabling it will stop ingestion
          immediately — existing cases are unaffected.
        </Typography>
      </InnerCard>
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// ScoringPanel — sliders with live preview, dirty tracking, bulk save
// ---------------------------------------------------------------------------

function ScoringPanel() {
  const qc = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const analyzersQuery = useQuery<Analyzer[]>({
    queryKey: ["settings", "scoring"],
    queryFn: listAnalyzers,
    retry: false,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, weight }: { id: number; weight: number }) =>
      updateAnalyzerWeight(id, weight),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings", "scoring"] }),
    onError: () => enqueueSnackbar("Failed to save weight.", { variant: "error" }),
  });

  const [drafts, setDrafts] = React.useState<Record<number, number>>({});

  React.useEffect(() => {
    if (!analyzersQuery.data) return;
    const next: Record<number, number> = {};
    for (const a of analyzersQuery.data) next[a.id] = a.weight;
    setDrafts(next);
  }, [analyzersQuery.data]);

  if (analyzersQuery.isLoading) {
    return <Box sx={{ py: 4, display: "grid", placeItems: "center" }}><CircularProgress /></Box>;
  }
  if (analyzersQuery.isError) {
    return <Alert severity="error">Failed to load analyzers.</Alert>;
  }

  const analyzers = analyzersQuery.data ?? [];
  const dirtyIds = analyzers.filter((a) => Number((drafts[a.id] ?? a.weight).toFixed(1)) !== Number(a.weight.toFixed(1))).map((a) => a.id);

  async function saveAll() {
    for (const id of dirtyIds) {
      await updateAnalyzerWeight(id, Number((drafts[id] ?? 0).toFixed(1)));
    }
    qc.invalidateQueries({ queryKey: ["settings", "scoring"] });
    enqueueSnackbar(`${dirtyIds.length} weight${dirtyIds.length !== 1 ? "s" : ""} saved.`, { variant: "success" });
  }

  function resetAll() {
    const reset: Record<number, number> = {};
    for (const a of analyzers) reset[a.id] = a.weight;
    setDrafts(reset);
  }

  return (
    <Stack spacing={2}>
      {/* Bulk action bar */}
      {dirtyIds.length > 0 ? (
        <InnerCard
          sx={{
            px: 2,
            py: 1.25,
            display: "flex",
            alignItems: "center",
            gap: 1.5,
            borderColor: alpha(theme.palette.warning.main, 0.4),
            background: alpha(theme.palette.warning.main, isDark ? 0.06 : 0.04),
          }}
        >
          <Typography variant="body2" sx={{ flex: 1, fontWeight: 700 }}>
            {dirtyIds.length} unsaved change{dirtyIds.length !== 1 ? "s" : ""}
          </Typography>
          <Button
            size="small"
            startIcon={<RestoreOutlined />}
            onClick={resetAll}
            sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2 }}
          >
            Reset all
          </Button>
          <Button
            size="small"
            variant="contained"
            startIcon={
              updateMutation.isPending
                ? <CircularProgress size={13} color="inherit" />
                : <DoneAllOutlined />
            }
            disabled={updateMutation.isPending}
            onClick={saveAll}
            sx={{ textTransform: "none", fontWeight: 900, borderRadius: 2 }}
          >
            Save all
          </Button>
        </InnerCard>
      ) : null}

      {/* Analyzer cards */}
      <Stack spacing={1.25}>
        {analyzers.map((a) => {
          const draft = drafts[a.id] ?? a.weight;
          const isDirty = Number(draft.toFixed(1)) !== Number(a.weight.toFixed(1));
          const savingThis = updateMutation.isPending && updateMutation.variables?.id === a.id;

          // Weight color
          const weightColor =
            draft >= 0.7 ? "#22C55E"
            : draft >= 0.4 ? "#F59E0B"
            : "#EF4444";

          return (
            <InnerCard
              key={a.id}
              sx={{
                p: 2,
                borderColor: isDirty ? alpha(theme.palette.warning.main, 0.35) : undefined,
                background: isDirty
                  ? alpha(theme.palette.warning.main, isDark ? 0.04 : 0.02)
                  : undefined,
                transition: "all .18s ease",
              }}
            >
              <Stack spacing={1.75}>
                <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", justifyContent: "space-between" }} >
                  <Box sx={{ minWidth: 0 }}>
                    <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }} >
                      <Typography sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 950, fontSize: 14 }}>
                        {a.name}
                      </Typography>
                      {!a.is_active ? (
                        <Chip size="small" label="Inactive" variant="outlined" color="warning" sx={{ height: 18, "& .MuiChip-label": { px: 0.75, fontSize: 10 } }} />
                      ) : null}
                      {isDirty ? (
                        <Chip size="small" label="Modified" variant="outlined" color="warning" sx={{ height: 18, "& .MuiChip-label": { px: 0.75, fontSize: 10 } }} />
                      ) : null}
                    </Stack>
                    <Typography variant="caption" color="text.disabled" sx={{ fontFamily: "monospace", fontSize: 11 }}>
                      {a.analyzer_cortex_id}
                    </Typography>
                  </Box>

                  {/* Weight badge */}
                  <Box
                    sx={{
                      px: 1.25,
                      py: 0.5,
                      borderRadius: 2,
                      background: alpha(weightColor, 0.12),
                      border: `1px solid ${alpha(weightColor, 0.3)}`,
                      minWidth: 56,
                      textAlign: "center",
                      transition: "all .2s ease",
                    }}
                  >
                    <Typography sx={{ fontWeight: 950, fontSize: 18, lineHeight: 1, color: weightColor, transition: "color .2s" }}>
                      {draft.toFixed(1)}
                    </Typography>
                    <Typography sx={{ fontSize: 10, color: "text.disabled", mt: 0.1 }}>
                      weight
                    </Typography>
                  </Box>
                </Stack>

                {/* Slider + progress */}
                <Stack spacing={0.75}>
                  <LinearProgress
                    variant="determinate"
                    value={draft * 100}
                    sx={{
                      height: 5,
                      borderRadius: 999,
                      bgcolor: alpha(weightColor, 0.12),
                      "& .MuiLinearProgress-bar": {
                        bgcolor: weightColor,
                        transition: "background-color .2s ease",
                        borderRadius: 999,
                      },
                    }}
                  />

                  <Slider
                    value={draft}
                    min={0}
                    max={1}
                    step={0.1}
                    marks
                    onChange={(_, v) => setDrafts((prev) => ({ ...prev, [a.id]: Number(v) }))}
                    sx={{
                      color: weightColor,
                      transition: "color .2s",
                      "& .MuiSlider-mark": { width: 3, height: 3, borderRadius: 99, opacity: 0.6 },
                      "& .MuiSlider-markLabel": { display: "none" },
                      "& .MuiSlider-rail": { opacity: 0.25 },
                    }}
                  />

                  <Stack direction="row" sx={{ justifyContent: "space-between" }} >
                    {[0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1].map((v) => (
                      <Typography key={v} variant="caption" color={draft === v ? "text.primary" : "text.disabled"}
                        sx={{ fontSize: 10, fontWeight: draft === v ? 900 : 400, cursor: "pointer", lineHeight: 1 }}
                        onClick={() => setDrafts((prev) => ({ ...prev, [a.id]: v }))}
                      >
                        {v === 0 ? "0" : v === 1 ? "1" : ""}
                      </Typography>
                    ))}
                  </Stack>
                </Stack>

                <Stack direction="row" spacing={1} sx={{ justifyContent: "flex-end" }} >
                  {isDirty ? (
                    <Button
                      size="small"
                      startIcon={<RestoreOutlined />}
                      onClick={() => setDrafts((prev) => ({ ...prev, [a.id]: a.weight }))}
                      sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2 }}
                    >
                      Reset
                    </Button>
                  ) : null}
                  <Button
                    size="small"
                    variant={isDirty ? "contained" : "outlined"}
                    disabled={!isDirty || savingThis}
                    startIcon={
                      savingThis
                        ? <CircularProgress size={13} color="inherit" />
                        : <SaveOutlined />
                    }
                    onClick={() =>
                      updateMutation.mutate({ id: a.id, weight: Number(draft.toFixed(1)) })
                    }
                    sx={{ textTransform: "none", fontWeight: 900, borderRadius: 2 }}
                  >
                    {savingThis ? "Saving…" : "Save"}
                  </Button>
                </Stack>
              </Stack>
            </InnerCard>
          );
        })}
      </Stack>
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// CisoUsersPanel
// ---------------------------------------------------------------------------

function CisoUsersPanel() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const [filter, setFilter] = React.useState("");

  const query = useQuery<CisoUser[]>({
    queryKey: ["settings", "list", "ciso_users"],
    queryFn: () => listItems("ciso_users"),
    retry: false,
  });

  const items = query.data ?? [];
  const filtered = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) =>
      [it.username, it.email, it.function, it.region, it.country, it.gbu, it.scope]
        .filter(Boolean).join(" ").toLowerCase().includes(q)
    );
  }, [items, filter]);

  return (
    <Stack spacing={2}>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
        <TextField
          size="small"
          placeholder="Search by username, email, scope, region…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          fullWidth
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start"><SearchOutlined fontSize="small" /></InputAdornment>
              ),
            },
          }}
        />
        <Chip size="small" label={`${filtered.length} / ${items.length}`} variant="outlined" />
      </Stack>

      {query.isLoading ? (
        <Box sx={{ py: 4, display: "grid", placeItems: "center" }}><CircularProgress /></Box>
      ) : query.isError ? (
        <Alert severity="error">Failed to load CISO users.</Alert>
      ) : filtered.length === 0 ? (
        <EmptyList message={filter ? `No users matching "${filter}"` : "No CISO users."} />
      ) : (
        <Stack spacing={1}>
          {filtered.map((user) => (
            <InnerCard key={user.id} hover sx={{ p: 2 }}>
              <Stack spacing={1.25}>
                <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ justifyContent: "space-between", alignItems: { sm: "center" } }} >
                  <Stack direction="row" spacing={1.25} sx={{ alignItems: "center" }} >
                    <Box
                      sx={{
                        width: 40,
                        height: 40,
                        borderRadius: 2.5,
                        display: "grid",
                        placeItems: "center",
                        background: alpha(theme.palette.primary.main, 0.1),
                        border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                      }}
                    >
                      <Typography color="primary" sx={{ fontWeight: 950, fontSize: 15 }} >
                        {(user.username?.[0] ?? "?").toUpperCase()}
                      </Typography>
                    </Box>
                    <Box>
                      <Typography sx={{ fontWeight: 950, fontSize: 14 }} >{user.username}</Typography>
                      <Typography variant="caption" color="text.secondary">{user.email || "No email"}</Typography>
                    </Box>
                  </Stack>

                  {user.scope ? (
                    <Chip
                      size="small"
                      icon={<ShieldOutlined />}
                      label={user.scope}
                      variant="outlined"
                      color="primary"
                    />
                  ) : (
                    <Chip size="small" label="No scope" variant="outlined" />
                  )}
                </Stack>

                <Divider sx={{ opacity: isDark ? 0.12 : 0.35 }} />

                <Box
                  sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr", sm: "repeat(2, 1fr)", md: "repeat(4, 1fr)" },
                    gap: 1,
                  }}
                >
                  {[
                    ["Function", user.function],
                    ["GBU", user.gbu],
                    ["Country", user.country],
                    ["Region", user.region],
                  ].map(([label, value]) => (
                    <Box key={label}>
                      <Typography variant="caption" color="text.disabled" sx={{ fontWeight: 700, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5 }}>
                        {label}
                      </Typography>
                      <Typography variant="body2" sx={{ fontSize: 13, fontWeight: 700 }}>
                        {value || "—"}
                      </Typography>
                    </Box>
                  ))}
                </Box>
              </Stack>
            </InnerCard>
          ))}
        </Stack>
      )}
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// Section content router
// ---------------------------------------------------------------------------

function SectionContent({ section }: { section: SectionMeta }) {
  switch (section.kind) {
    case "domain_pair":
      return (
        <DomainPairPanel
          editableSection={section.key as "domains_allow" | "domains_deny"}
        />
      );
    case "list":
      return (
        <EditableListPanel
          section={section.key as EditableListSection}
          placeholder="Paste values, one per line or comma-separated…"
        />
      );
    case "toggle":
      return <FeederPanel />;
    case "scoring":
      return <ScoringPanel />;
    case "ciso_users":
      return <CisoUsersPanel />;
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// SECTIONS definition
// ---------------------------------------------------------------------------

const SECTIONS: SectionMeta[] = [
  {
    key: "domains_allow",
    title: "Domains allowlist",
    subtitle: "Manage local allowlist and Watcher legit domains.",
    icon: <CheckCircleOutlined />,
    kind: "domain_pair",
  },
  {
    key: "domains_deny",
    title: "Domains denylist",
    subtitle: "Manage local denylist and Watcher monitored domains.",
    icon: <BlockOutlined />,
    kind: "domain_pair",
  },
  {
    key: "campaign_domains_allow",
    title: "Campaign domains",
    subtitle: "Allow campaign or newsletter domains.",
    icon: <CampaignOutlined />,
    kind: "list",
  },
  {
    key: "emails_files_allow",
    title: "Files allowlist",
    subtitle: "Allow known safe file hashes.",
    icon: <InsertDriveFileOutlined />,
    kind: "list",
  },
  {
    key: "filetypes_allow",
    title: "Filetypes allowlist",
    subtitle: "Allow known safe file extensions.",
    icon: <ExtensionOutlined />,
    kind: "list",
  },
  {
    key: "ciso_users",
    title: "CISO users",
    subtitle: "Review scoped CISO identities.",
    icon: <GroupsOutlined />,
    kind: "ciso_users",
  },
  {
    key: "email_feeder",
    title: "Email feeder",
    subtitle: "Enable or disable the feeder service.",
    icon: <MailOutlined />,
    kind: "toggle",
  },
  {
    key: "scoring",
    title: "Analyzer scoring",
    subtitle: "Tune analyzer weights.",
    icon: <TuneOutlined />,
    kind: "scoring",
  },
];

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function SettingsPage() {
  const qc = useQueryClient();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const meQuery = useQuery<Me>({ queryKey: ["me"], queryFn: getMe, retry: false });
  const me = meQuery.data;
  const groups = me?.groups ?? [];
  const isAllowed = groups.includes("Admin") || groups.includes("CERT");

  const [active, setActive] = React.useState<SettingsSection>("domains_allow");
  const activeMeta = SECTIONS.find((s) => s.key === active)!;

  if (meQuery.isLoading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me || !isAllowed) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Not authorized (Admin / CERT only).</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: { xs: 1.5, md: 2.5 } }}>
      {/* ---------------------------------------------------------------- */}
      {/* Page header                                                       */}
      {/* ---------------------------------------------------------------- */}
      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={1.5}
        sx={{ mb: 2.5, justifyContent: "space-between" }}
      >
        <Stack spacing={0.3}>
          <Typography variant="h4" sx={{ fontWeight: 950, letterSpacing: -0.5 }} >
            Settings
          </Typography>
          <Typography color="text.secondary">
            Manage lists, feeder state and analyzer scoring.
          </Typography>
        </Stack>

        <Tooltip title="Refresh all settings">
          <IconButton
            aria-label="Refresh all"
            onClick={() => qc.invalidateQueries({ queryKey: ["settings"] })}
            sx={{
              alignSelf: { xs: "flex-start", md: "center" },
              border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
              borderRadius: 2,
            }}
          >
            <RefreshOutlined />
          </IconButton>
        </Tooltip>
      </Stack>

      <Grid container spacing={2} sx={{ alignItems: "flex-start" }} >
        {/* ---------------------------------------------------------------- */}
        {/* Sidebar nav                                                       */}
        {/* ---------------------------------------------------------------- */}
        <Grid size={{ xs: 12, md: 3.5, lg: 3 }}>
          <SoftCard sx={{ overflow: "hidden", position: { md: "sticky" }, top: { md: 16 } }}>
            <CardContent sx={{ p: 1.5 }}>
              {/* Console identity */}
              <Stack direction="row" spacing={1.25} sx={{ px: 1, py: 1, mb: 0.5, alignItems: "center" }}>
                <Box
                  sx={{
                    width: 42,
                    height: 42,
                    borderRadius: 3,
                    display: "grid",
                    placeItems: "center",
                    border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
                    background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                    "& svg": { fontSize: 22 },
                  }}
                >
                  <SettingsOutlined />
                </Box>
                <Box sx={{ minWidth: 0 }}>
                  <Typography sx={{ fontWeight: 950, fontSize: 14 }} >Admin console</Typography>
                  <Typography variant="caption" color="text.secondary" noWrap>{me.username}</Typography>
                </Box>
              </Stack>

              <Divider sx={{ opacity: isDark ? 0.18 : 0.45, my: 1 }} />

              {/* Section list */}
              <List dense disablePadding>
                {SECTIONS.map((s) => {
                  const isActive = active === s.key;
                  return (
                    <ListItemButton
                      key={s.key}
                      selected={isActive}
                      onClick={() => setActive(s.key)}
                      sx={{
                        borderRadius: 2.5,
                        mx: 0.25,
                        my: 0.35,
                        py: 1,
                        px: 1.25,
                        transition: "all .15s ease",
                        "&.Mui-selected": {
                          background: alpha(theme.palette.primary.main, isDark ? 0.12 : 0.08),
                          "&:hover": {
                            background: alpha(theme.palette.primary.main, isDark ? 0.16 : 0.11),
                          },
                        },
                      }}
                    >
                      <NavIcon icon={s.icon} isDark={isDark} />
                      <ListItemText
                        primary={s.title}
                        secondary={s.subtitle}
                        sx={{ ml: 1.25 }}
                        slotProps={{
                          primary: {
                            sx: {
                              fontWeight: isActive ? 950 : 800,
                              fontSize: 13.5,
                              color: isActive ? "primary.main" : undefined,
                            },
                          },
                          secondary: {
                            sx: { display: { xs: "none", md: "block" }, fontSize: 11, mt: 0.15 },
                          },
                        }}
                      />
                    </ListItemButton>
                  );
                })}
              </List>
            </CardContent>
          </SoftCard>
        </Grid>

        {/* ---------------------------------------------------------------- */}
        {/* Main content panel                                               */}
        {/* ---------------------------------------------------------------- */}
        <Grid size={{ xs: 12, md: 8.5, lg: 9 }}>
          <SoftCard>
            <CardContent sx={{ p: { xs: 2, md: 3 } }}>
              {/* Section header */}
              <Stack
                direction={{ xs: "column", sm: "row" }}
                spacing={1.25}
                sx={{ mb: 2.5, justifyContent: "space-between", alignItems: { sm: "center" } }}
              >
                <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }} >
                  <Box
                    sx={{
                      width: 46,
                      height: 46,
                      borderRadius: 3,
                      display: "grid",
                      placeItems: "center",
                      border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
                      background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                      "& svg": { fontSize: 22 },
                      flexShrink: 0,
                    }}
                  >
                    {activeMeta.icon}
                  </Box>
                  <Box>
                    <Typography variant="h6" sx={{ fontWeight: 950, letterSpacing: -0.2 }} >
                      {activeMeta.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {activeMeta.subtitle}
                    </Typography>
                  </Box>
                </Stack>

                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<RefreshOutlined />}
                  onClick={() => qc.invalidateQueries({ queryKey: ["settings", "list", active] })}
                  sx={{ borderRadius: 2.5, textTransform: "none", fontWeight: 900, flexShrink: 0 }}
                >
                  Refresh
                </Button>
              </Stack>

              <Divider sx={{ opacity: isDark ? 0.18 : 0.45, mb: 2.5 }} />

              {/* Section body */}
              <SectionContent section={activeMeta} />
            </CardContent>
          </SoftCard>
        </Grid>
      </Grid>
    </Box>
  );
}