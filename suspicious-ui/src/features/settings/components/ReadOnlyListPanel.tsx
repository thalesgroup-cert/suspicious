import * as React from "react";
import {
  Alert,
  Box,
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
  LockOutlined,
  SearchOutlined,
  VisibilityOffOutlined,
  VisibilityOutlined,
} from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useQuery } from "@tanstack/react-query";

import { listItems, type ListItem } from "@/features/settings/api";
import { EmptyList, InnerCard } from "@/features/settings/components/cards";
import { EditableListPanel } from "@/features/settings/components/EditableListPanel";

export function ReadOnlyListPanel({
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

  const items = React.useMemo(() => listQuery.data ?? [], [listQuery.data]);
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

export function DomainPairPanel({ editableSection }: { editableSection: "domains_allow" | "domains_deny" }) {
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
