import * as React from "react";
import { Box, Button, Stack, TextField, Typography } from "@mui/material";
import { SoftCard } from "@/shared/components/SoftCard";
import type { CaseComment } from "./api";

function fmtCommentDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export type CommentThreadProps = {
  title: string;
  comments: CaseComment[];
  isLoading: boolean;
  onAdd: (body: string) => void;
  isAdding: boolean;
};

export function CommentThread({ title, comments, isLoading, onAdd, isAdding }: CommentThreadProps) {
  const [draft, setDraft] = React.useState("");

  const handleAdd = () => {
    const trimmed = draft.trim();
    if (!trimmed) return;
    onAdd(trimmed);
    setDraft("");
  };

  return (
    <Box sx={{ px: 2.25, py: 2 }}>
      <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
        {title}
      </Typography>

      <Stack spacing={1} sx={{ mb: 1.25 }}>
        {isLoading ? (
          <Typography variant="body2" color="text.secondary">Loading…</Typography>
        ) : comments.length === 0 ? (
          <Typography variant="body2" color="text.secondary">No comments yet.</Typography>
        ) : (
          comments.map((c) => (
            <SoftCard key={c.id} sx={{ p: 1.25 }}>
              <Stack direction="row" spacing={1} sx={{ alignItems: "baseline", mb: 0.25 }}>
                <Typography variant="caption" sx={{ fontWeight: 700 }}>{c.author_email}</Typography>
                <Typography variant="caption" color="text.disabled">{fmtCommentDate(c.created_at)}</Typography>
              </Stack>
              <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>{c.body}</Typography>
            </SoftCard>
          ))
        )}
      </Stack>

      <Stack direction="row" spacing={1}>
        <TextField
          size="small"
          fullWidth
          multiline
          minRows={2}
          placeholder="Add a comment…"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
        />
        <Button
          variant="contained"
          size="small"
          disabled={!draft.trim() || isAdding}
          onClick={handleAdd}
          sx={{ alignSelf: "flex-end" }}
        >
          Add
        </Button>
      </Stack>
    </Box>
  );
}
