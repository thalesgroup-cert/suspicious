import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  LinearProgress,
  Slider,
  Stack,
  Typography,
} from "@mui/material";
import {
  DoneAllOutlined,
  RestoreOutlined,
  SaveOutlined,
} from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSnackbar } from "notistack";

import { listAnalyzers, updateAnalyzerWeight, type Analyzer } from "@/features/settings/api";
import { InnerCard } from "@/features/settings/components/cards";

export function ScoringPanel() {
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

  const analyzersData = analyzersQuery.data;
  const [prevAnalyzersData, setPrevAnalyzersData] = React.useState(analyzersData);
  if (analyzersData !== prevAnalyzersData) {
    setPrevAnalyzersData(analyzersData);
    if (analyzersData) {
      const next: Record<number, number> = {};
      for (const a of analyzersData) next[a.id] = a.weight;
      setDrafts(next);
    }
  }

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

      <Stack spacing={1.25}>
        {analyzers.map((a) => {
          const draft = drafts[a.id] ?? a.weight;
          const isDirty = Number(draft.toFixed(1)) !== Number(a.weight.toFixed(1));
          const savingThis = updateMutation.isPending && updateMutation.variables?.id === a.id;

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
