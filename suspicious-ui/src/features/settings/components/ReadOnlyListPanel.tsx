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
  Typography,
} from "@mui/material";
import {
  LockOutlined,
  SearchOutlined,
  VisibilityOffOutlined,
  VisibilityOutlined,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";

import { listItems, type ListItem } from "@/features/settings/api";
import { EntryDate } from "@/features/settings/components/EntryDate";
import { EmptyList } from "@/features/settings/components/cards";
import { EditableListPanel } from "@/features/settings/components/EditableListPanel";

export function ReadOnlyListPanel({
  section,
  title,
  subtitle,
}: {
  section: "watcher_legit_domains" | "watcher_monitored_domains";
  /** Which Watcher list this is; the block heading itself is fixed. */
  title: string;
  subtitle: string;
}) {
  const headingId = React.useId();
  const regionId = React.useId();
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
    <Box
      component="section"
      aria-labelledby={headingId}
      sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: 2 }}
    >
      {/* No Stack spacing: the collapsed list must add no gap, so the spacing lives inside the parts that collapse. */}
      <Stack>
        <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", justifyContent: "space-between" }}>
          <Box>
            <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }}>
              <LockOutlined aria-hidden sx={{ fontSize: 16, color: "text.secondary" }} />
              <Typography id={headingId} variant="subtitle1" component="h3" sx={{ fontWeight: 600 }}>
                Synced from Watcher (read-only)
              </Typography>
            </Stack>
            <Typography variant="body2" color="text.secondary">{title}. {subtitle}</Typography>
          </Box>
          <Chip size="small" label={`${items.length} synced`} variant="outlined" />
        </Stack>

        <Stack direction="row" spacing={1} sx={{ mt: 1.5 }}>
          <TextField
            size="small"
            placeholder="Search synced domains…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            fullWidth
            slotProps={{
              htmlInput: { "aria-label": `Search ${title}` },
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchOutlined fontSize="small" />
                  </InputAdornment>
                ),
              },
            }}
          />
          <IconButton
            size="small"
            onClick={() => setShowItems((v) => !v)}
            aria-expanded={showItems}
            aria-controls={regionId}
            aria-label={showItems ? "Hide list" : "Show list"}
            sx={{ border: 1, borderColor: "divider", borderRadius: 2, color: showItems ? "primary.main" : undefined }}
          >
            {showItems ? <VisibilityOffOutlined fontSize="small" /> : <VisibilityOutlined fontSize="small" />}
          </IconButton>
        </Stack>

        {!showItems && filter.trim() ? (
          <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
            Expand to see {filtered.length} {filtered.length === 1 ? "match" : "matches"}
          </Typography>
        ) : null}

        <Collapse in={showItems} id={regionId}>
          <Box sx={{ pt: 1.5 }}>
          {listQuery.isLoading ? (
            <Box sx={{ py: 3, display: "grid", placeItems: "center" }}><CircularProgress size={20} /></Box>
          ) : listQuery.isError ? (
            <Alert severity="error">Failed to load.</Alert>
          ) : filtered.length === 0 ? (
            <EmptyList message={filter ? `No entries matching "${filter}"` : "No synced entries yet."} />
          ) : (
            <Box
              role="region"
              tabIndex={0}
              aria-label={title}
              sx={{ maxHeight: 320, overflowY: "auto", border: 1, borderColor: "divider", borderRadius: 2 }}
            >
              <Box component="ul" sx={{ listStyle: "none", m: 0, p: 0 }}>
                {filtered.map((it) => (
                  <Box
                    component="li"
                    key={it.id}
                    sx={{ px: 1.5, py: 0.75, borderTop: 1, borderColor: "divider", "&:first-of-type": { borderTop: 0 } }}
                  >
                    <Typography component="span" sx={{ display: "block", fontFamily: "monospace", fontWeight: 600, fontSize: 13, overflowWrap: "anywhere" }}>
                      {it.value}
                    </Typography>
                    {/* created_at is the row's creation_date: when Suspicious first saw the domain, not Watcher's own date. */}
                    <EntryDate iso={it.created_at} label="First synced" sx={{ display: "block" }} />
                  </Box>
                ))}
              </Box>
            </Box>
          )}
          </Box>
        </Collapse>
      </Stack>
    </Box>
  );
}

export function DomainPairPanel({
  editableSection,
  title,
  purpose,
}: {
  editableSection: "domains_allow" | "domains_deny";
  title: string;
  purpose?: string;
}) {
  const isAllow = editableSection === "domains_allow";

  return (
    <Stack spacing={2.5}>
      <EditableListPanel
        section={editableSection}
        title={title}
        placeholder="Paste domains, one per line or comma-separated…"
        purpose={purpose}
      />
      <ReadOnlyListPanel
        section={isAllow ? "watcher_legit_domains" : "watcher_monitored_domains"}
        title={isAllow ? "Watcher legit domains" : "Watcher monitored domains"}
        subtitle="Synchronized from Watcher automatically."
      />
    </Stack>
  );
}
