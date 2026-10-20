import { useState } from "react";
import { Alert, Box, Button, Chip, FormControlLabel, InputAdornment, Skeleton, Stack, Switch, TextField, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import SearchOutlined from "@mui/icons-material/SearchOutlined";

import { EmptyList } from "@/features/settings/components/cards";
import { ConnectorTile } from "@/features/settings/components/ConnectorTile";
import type { Connector } from "@/features/settings/components/connectors";
import type { TestResult } from "@/features/settings/components/useConnectorTest";
import { filterConnectors, groupByCategory, statusCounts, type StatusFilter } from "@/features/settings/connectorFilter";
import { contrastRatio, flatten } from "@/shared/lib/contrast";
import { useMuted } from "@/features/settings/useMuted";

const CHIPS: { value: StatusFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "connected", label: "Connected" },
  { value: "incomplete", label: "Incomplete" },
  { value: "unhealthy", label: "Unhealthy" },
  { value: "disabled", label: "Disabled" },
];

// One column on a phone, three at the page width of a desktop; min() keeps a 280px track from overflowing a narrower container.
const GRID = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fill, minmax(min(280px, 100%), 1fr))",
  gap: 2,
  alignItems: "stretch",
  listStyle: "none",
  m: 0,
  p: 0,
} as const;

function SkeletonTile() {
  return (
    <Box
      component="li"
      data-testid="tile-skeleton"
      sx={{ listStyle: "none", p: 2, border: 1, borderColor: "divider", borderRadius: 2, display: "flex", flexDirection: "column", gap: 1.5 }}
    >
      <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
        <Skeleton variant="rounded" width={48} height={48} />
        <Box sx={{ flex: 1 }}>
          <Skeleton width="60%" />
          <Skeleton width="35%" />
        </Box>
      </Stack>
      <Skeleton variant="text" />
      <Skeleton variant="text" width="80%" />
      <Skeleton variant="rounded" height={32} sx={{ mt: 1 }} />
    </Box>
  );
}

export function ConnectorGallery({
  connectors,
  loadErrors,
  loading,
  error,
  onRetry,
  onConfigure,
}: {
  connectors: Connector[];
  loadErrors: Record<string, string>;
  loading: boolean;
  error: boolean;
  onRetry: () => void;
  onConfigure: (name: string) => void;
}) {
  const theme = useTheme();
  const muted = useMuted();
  // The selected pill is the text colour as a fill. Its label is whichever of white and black reads better on it, not paper:
  // in some themes (spring) text.primary and paper are both dark, which left the label at 1.6:1.
  const { common, background, text } = theme.palette;
  const fill = flatten(text.primary, background.paper);
  const pill = { fill, label: contrastRatio(fill, common.white) >= contrastRatio(fill, common.black) ? common.white : common.black };
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [grouped, setGrouped] = useState(false);
  // Test results live here, above the filter, so they survive a tile being filtered out or regrouped.
  const [results, setResults] = useState<Record<string, TestResult | null>>({});
  const setResult = (name: string, r: TestResult | null) => setResults((prev) => ({ ...prev, [name]: r }));

  if (loading) {
    return (
      <Box aria-busy="true">
        <Box component="ul" sx={GRID}>
          {Array.from({ length: 6 }, (_, i) => (
            <SkeletonTile key={i} />
          ))}
        </Box>
      </Box>
    );
  }
  if (error) {
    return (
      <Alert severity="error" action={<Button color="inherit" size="small" onClick={onRetry}>Retry</Button>}>
        Failed to load connectors.
      </Alert>
    );
  }

  const loadAlerts = Object.entries(loadErrors).map(([name, message]) => (
    <Alert key={name} severity="warning">
      Connector {name} failed to load: {message}
    </Alert>
  ));
  if (connectors.length === 0) {
    return (
      <Stack spacing={1.5}>
        {loadAlerts}
        <EmptyList message="No connectors discovered." />
      </Stack>
    );
  }

  const counts = statusCounts(connectors);
  const shown = filterConnectors(connectors, { q, status });
  const filtered = q.trim() !== "" || status !== "all";
  const tile = (c: Connector, level: 3 | 4) => (
    <ConnectorTile key={c.name} connector={c} headingLevel={level} testResult={results[c.name] ?? null} onTestResult={setResult} onConfigure={onConfigure} />
  );

  return (
    <Stack spacing={2.5}>
      {loadAlerts}
      <Stack direction="row" useFlexGap sx={{ alignItems: "center", flexWrap: "wrap", gap: 1.5 }}>
        <TextField
          type="search"
          size="small"
          placeholder="Search connectors"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          sx={{ width: { xs: "100%", sm: 260 } }}
          slotProps={{
            htmlInput: { "aria-label": "Search connectors" },
            input: { startAdornment: <InputAdornment position="start"><SearchOutlined fontSize="small" /></InputAdornment> },
          }}
        />
        <Stack direction="row" useFlexGap sx={{ flexWrap: "wrap", gap: 1 }}>
          {CHIPS.map((c) => {
            const selected = status === c.value;
            return (
              <Chip
                key={c.value}
                clickable
                aria-pressed={selected}
                onClick={() => setStatus(selected && c.value !== "all" ? "all" : c.value)}
                label={
                  <>
                    {c.label}{" "}
                    <Box component="span" sx={{ fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>{counts[c.value]}</Box>
                  </>
                }
                variant={selected ? "filled" : "outlined"}
                // &&&: some themes (spring) colour chips by nth-of-type with a rule of higher specificity than a plain sx.
                sx={{
                  "&&&": selected
                    ? { bgcolor: pill.fill, color: pill.label, "&:hover": { bgcolor: pill.fill } }
                    : { bgcolor: "transparent", color: "text.primary", borderColor: "divider" },
                }}
              />
            );
          })}
        </Stack>
      </Stack>

      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", minHeight: 32 }}>
        <Typography variant="caption" aria-live="polite" sx={{ color: muted }}>
          {filtered ? `Showing ${shown.length} of ${connectors.length} connectors` : `${connectors.length} connectors`}
        </Typography>
        <FormControlLabel
          sx={{ mr: 0 }}
          control={<Switch size="small" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />}
          label={<Typography variant="body2">Group by category</Typography>}
        />
      </Stack>

      {shown.length === 0 ? (
        <Stack spacing={1} sx={{ alignItems: "center" }}>
          <EmptyList message="No connectors match these filters." />
          <Button
            variant="outlined"
            size="small"
            onClick={() => {
              setQ("");
              setStatus("all");
            }}
            sx={{ color: "text.primary", borderColor: alpha(theme.palette.text.primary, 0.3) }}
          >
            Clear filters
          </Button>
        </Stack>
      ) : grouped ? (
        <Stack spacing={3}>
          {groupByCategory(shown).map((g) => (
            <Box key={g.category}>
              <Stack direction="row" spacing={1} sx={{ alignItems: "baseline", mb: 1.5 }}>
                <Typography variant="subtitle2" component="h3" sx={{ fontWeight: 600 }}>{g.category}</Typography>
                <Typography variant="caption" sx={{ color: muted }}>{g.items.length}</Typography>
              </Stack>
              <Box component="ul" sx={GRID}>
                {g.items.map((c) => tile(c, 4))}
              </Box>
            </Box>
          ))}
        </Stack>
      ) : (
        <Box component="ul" sx={GRID}>
          {shown.map((c) => tile(c, 3))}
        </Box>
      )}
    </Stack>
  );
}
