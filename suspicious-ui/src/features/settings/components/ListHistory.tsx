import * as React from "react";
import { Alert, Box, Button, CircularProgress, Collapse, Typography } from "@mui/material";
import { ExpandMore, HistoryOutlined } from "@mui/icons-material";

import type { EditableListSection } from "@/features/settings/api";
import { EntryDate } from "@/features/settings/components/EntryDate";
import { StatusLabel } from "@/features/settings/components/StatusLabel";
import { useListHistory } from "@/features/settings/useListHistory";

const EMPTY = "No changes recorded yet. History starts when this version is installed.";

/** Collapsed by default; the first page is requested only once opened. */
export function ListHistory({ section }: { section: EditableListSection }) {
  const [open, setOpen] = React.useState(false);
  const regionId = React.useId();
  const q = useListHistory(section, open);
  const events = q.data?.pages.flatMap((p) => p.results) ?? [];

  return (
    <Box>
      <Button
        size="small"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls={regionId}
        startIcon={<HistoryOutlined />}
        endIcon={<ExpandMore sx={{ transform: open ? "rotate(180deg)" : "none", transition: "transform .2s" }} />}
        sx={{ textTransform: "none", fontWeight: 600, color: "text.secondary" }}
      >
        History
      </Button>
      <Collapse in={open} unmountOnExit>
        <Box id={regionId} sx={{ pt: 1 }}>
          {q.isLoading ? (
            <Box sx={{ py: 2, display: "grid", placeItems: "center" }}><CircularProgress size={20} aria-label="Loading history" /></Box>
          ) : null}
          {/* Kept above the list so a failed later page does not hide the events already loaded. */}
          {q.isError ? <Alert severity="error" sx={{ mb: events.length ? 1 : 0 }}>Failed to load history.</Alert> : null}
          {!q.isLoading && !q.isError && events.length === 0 ? (
            <Typography variant="body2" color="text.secondary">{EMPTY}</Typography>
          ) : null}
          {events.length > 0 ? (
            <Box component="ul" aria-label="Change history" sx={{ listStyle: "none", m: 0, p: 0, border: 1, borderColor: "divider", borderRadius: 2, overflow: "hidden" }}>
              {events.map((e) => (
                <Box
                  key={e.id}
                  component="li"
                  sx={{ display: "flex", alignItems: "baseline", gap: 1.5, flexWrap: "wrap", px: 1.5, py: 0.75, borderTop: 1, borderColor: "divider", "&:first-of-type": { borderTop: 0 } }}
                >
                  {/* The sentence below carries the same word; the icon + word is the visual cue only. */}
                  <Box aria-hidden="true" sx={{ minWidth: 88 }}>
                    <StatusLabel size="small" tone={e.action === "added" ? "ok" : "danger"} label={e.action === "added" ? "Added" : "Removed"} />
                  </Box>
                  <Typography component="span" sx={{ fontFamily: "monospace", fontWeight: 600, fontSize: 13.5, overflowWrap: "anywhere" }}>
                    {e.value}
                  </Typography>
                  <EntryDate iso={e.created_at} label={e.action === "added" ? "Added" : "Removed"} by={e.username || null} withTime />
                </Box>
              ))}
            </Box>
          ) : null}
          {q.hasNextPage ? (
            <Button size="small" onClick={() => q.fetchNextPage()} disabled={q.isFetchingNextPage} sx={{ mt: 1, textTransform: "none", fontWeight: 600 }}>
              Load more
            </Button>
          ) : null}
        </Box>
      </Collapse>
    </Box>
  );
}
