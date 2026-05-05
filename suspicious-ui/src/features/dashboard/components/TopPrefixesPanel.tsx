// src/features/dashboard/components/TopPrefixesPanel.tsx
import * as React from "react";
import { api } from "@/api/client";
import {
  Box,
  Chip,
  CircularProgress,
  Stack,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { alpha } from "@mui/material/styles";
import {
  EmojiEventsRounded,
  MilitaryTechRounded,
  SellOutlined,
  WorkspacePremiumRounded,
} from "@mui/icons-material";

import { SoftCard } from "./SoftCard";
import { useResultColors, useStatusColors } from "@/styles/colorStore";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type TopPrefixesType = "user" | "group";

// CATEGORY_CONFIG is built dynamically from the color store (see component)
// so it respects the user's preset (Standard / Colorblind-safe / Monochrome).
type CategoryKey = "safe" | "suspicious" | "dangerous" | "failure" | "inconclusive";

type CategoryConfig = {
  key: CategoryKey;
  label: string;
  color: string;
};

type TopPrefixApiItem = {
  prefix: string;
  total: number;
  safe: number;
  suspicious: number;
  dangerous: number;
  failure: number;
  inconclusive: number;
};

type TopPrefixesResponse = {
  type: TopPrefixesType;
  month?: string | null;
  year?: string | null;
  data: TopPrefixApiItem[];
};

type TopPrefixesPanelProps = {
  month?: string;
  year?: string;
  limit?: number;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function compactLabel(text: string, max = 14) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

// Rank badge visual config — gold/silver/bronze trophy aesthetics,
// not semantic status colors (intentionally stays hardcoded).
function getRankBadge(rank: number) {
  if (rank === 0) {
    return {
      icon: <WorkspacePremiumRounded sx={{ fontSize: 16 }} />,
      bg: "linear-gradient(135deg, #facc15, #f59e0b)",
      color: "#1f2937",
      ring: "0 0 0 4px rgba(250,204,21,0.18)",
    };
  }
  if (rank === 1) {
    return {
      icon: <MilitaryTechRounded sx={{ fontSize: 15 }} />,
      bg: "linear-gradient(135deg, #e5e7eb, #94a3b8)",
      color: "#0f172a",
      ring: "0 0 0 4px rgba(148,163,184,0.16)",
    };
  }
  if (rank === 2) {
    return {
      icon: <EmojiEventsRounded sx={{ fontSize: 15 }} />,
      bg: "linear-gradient(135deg, #f59e0b, #b45309)",
      color: "#fff",
      ring: "0 0 0 4px rgba(245,158,11,0.16)",
    };
  }
  return {
    icon: (
      <Box component="span" sx={{ fontSize: 12, fontWeight: 800 }}>
        {rank + 1}
      </Box>
    ),
    bg: "rgba(148,163,184,0.16)",
    color: "text.secondary",
    ring: "none",
  };
}

async function fetchTopPrefixes(params: {
  type: TopPrefixesType;
  month?: string;
  year?: string;
  limit?: number;
}): Promise<TopPrefixesResponse> {
  const response = await api.get<TopPrefixesResponse>("/stats/top-prefixes/", {
    params: {
      type: params.type,
      month: params.month,
      year: params.year,
      limit: params.limit ?? 5,
    },
  });
  return response.data;
}

// ---------------------------------------------------------------------------
// TopPrefixesPanel
// ---------------------------------------------------------------------------

export default function TopPrefixesPanel({
  month,
  year,
  limit = 5,
}: TopPrefixesPanelProps) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  // Build category config from the semantic color store so stacked bar
  // segments and legend dots respect the user's colorblind-safe preset.
  // "Failure" maps to statusColors.failure (processing error, not an
  // analysis result) — the other four map to resultColors.
  const resultColors = useResultColors();
  const statusColors  = useStatusColors();

  const CATEGORY_CONFIG = React.useMemo<CategoryConfig[]>(() => [
    { key: "safe",         label: "Safe",         color: resultColors.safe.main },
    { key: "suspicious",   label: "Suspicious",   color: resultColors.suspicious.main },
    { key: "dangerous",    label: "Dangerous",    color: resultColors.dangerous.main },
    { key: "failure",      label: "Failure",      color: statusColors.failure.main },
    { key: "inconclusive", label: "Inconclusive", color: resultColors.inconclusive.main },
  ], [resultColors, statusColors]);

  const [type, setType]     = React.useState<TopPrefixesType>("user");
  const [loading, setLoading] = React.useState(false);
  const [error, setError]   = React.useState<string | null>(null);
  const [rows, setRows]     = React.useState<TopPrefixApiItem[]>([]);

  React.useEffect(() => {
    let active = true;

    async function load() {
      try {
        setLoading(true);
        setError(null);
        const result = await fetchTopPrefixes({ type, month, year, limit });
        if (!active) return;
        setRows(result.data);
      } catch (err) {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load data");
        setRows([]);
      } finally {
        if (active) setLoading(false);
      }
    }

    load();
    return () => { active = false; };
  }, [type, month, year, limit]);

  // ── Theme-aware style tokens ─────────────────────────────────────────────

  const rowBorderColor = isDark
    ? "rgba(255,255,255,0.08)"
    : alpha(theme.palette.divider, 0.55);

  const rowBgTop = isDark
    ? "linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03))"
    : `linear-gradient(180deg, ${alpha("#fff", 0.85)}, ${alpha(theme.palette.grey[50], 0.9)})`;

  const rowBgRest = isDark
    ? "rgba(255,255,255,0.02)"
    : alpha(theme.palette.background.paper, 0.4);

  const rankBadgeBorder = isDark
    ? "1px solid rgba(255,255,255,0.10)"
    : `1px solid ${alpha(theme.palette.divider, 0.45)}`;

  // #1 rank chip uses theme primary (not a semantic result color)
  const chipBgTop  = isDark
    ? alpha(theme.palette.primary.main, 0.16)
    : alpha(theme.palette.primary.main, 0.12);
  const chipBgRest = isDark
    ? "rgba(148,163,184,.12)"
    : alpha(theme.palette.grey[300], 0.35);
  const chipBorder = isDark
    ? "1px solid rgba(255,255,255,.08)"
    : `1px solid ${alpha(theme.palette.divider, 0.5)}`;

  const stackedBarBg = isDark
    ? "rgba(148,163,184,0.10)"
    : alpha(theme.palette.grey[300], 0.35);

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <SoftCard
      title={`Top ${limit} Reporters`}
      icon={<SellOutlined />}
      right={
        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
          <ToggleButtonGroup
            size="small"
            exclusive
            value={type}
            onChange={(_, value: TopPrefixesType | null) => {
              if (value) setType(value);
            }}
          >
            <ToggleButton value="user">Users</ToggleButton>
            <ToggleButton value="group">Groups</ToggleButton>
          </ToggleButtonGroup>
          <Chip size="small" label={`Top ${limit}`} variant="outlined" />
        </Stack>
      }
      fillHeight
    >
      <Box sx={{ height: "100%", minHeight: 0, overflow: "auto" }}>
        {loading ? (
          <Stack sx={{ height: "100%", alignItems: "center", justifyContent: "center" }}>
            <CircularProgress size={24} />
          </Stack>
        ) : error ? (
          <Stack sx={{ height: "100%", alignItems: "center", justifyContent: "center" }}>
            <Typography color="error" variant="body2">{error}</Typography>
          </Stack>
        ) : rows.length === 0 ? (
          <Stack sx={{ height: "100%", alignItems: "center", justifyContent: "center" }}>
            <Typography color="text.secondary" variant="body2">
              No prefixes for this period
            </Typography>
          </Stack>
        ) : (
          <Stack spacing={1.25}>
            {rows.map((item, index) => {
              const total = item.total || 0;
              const badge = getRankBadge(index);

              return (
                <Box
                  key={item.prefix}
                  sx={{
                    borderRadius: 2.5,
                    px: 1.25,
                    py: 1,
                    border: `1px solid ${rowBorderColor}`,
                    background: index === 0 ? rowBgTop : rowBgRest,
                  }}
                >
                  {/* Row header: rank badge + prefix label + total chip */}
                  <Stack
                    direction="row"
                    spacing={2}
                    sx={{ mb: 0.75, alignItems: "center", justifyContent: "space-between" }}
                  >
                    <Stack
                      direction="row"
                      spacing={1}
                      sx={{ minWidth: 0, alignItems: "center" }}
                    >
                      <Box
                        sx={{
                          minWidth: 28,
                          width: 28,
                          height: 28,
                          borderRadius: 999,
                          display: "grid",
                          placeItems: "center",
                          color: badge.color,
                          background: badge.bg,
                          boxShadow: badge.ring,
                          border: rankBadgeBorder,
                          flexShrink: 0,
                        }}
                      >
                        {badge.icon}
                      </Box>

                      <Typography
                        variant="body2"
                        sx={{
                          fontWeight:
                            index === 0 ? 900 : index < 3 ? 800 : 700,
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          maxWidth: { xs: 140, md: 220 },
                        }}
                      >
                        {compactLabel(item.prefix)}
                      </Typography>
                    </Stack>

                    <Chip
                      size="small"
                      label={total.toLocaleString()}
                      sx={{
                        fontWeight: 800,
                        bgcolor: index === 0 ? chipBgTop : chipBgRest,
                        border: chipBorder,
                      }}
                    />
                  </Stack>

                  {/* Stacked bar — segment colors from the color store */}
                  <Box
                    sx={{
                      height: 16,
                      borderRadius: 999,
                      overflow: "hidden",
                      display: "flex",
                      bgcolor: stackedBarBg,
                      boxShadow: isDark
                        ? "inset 0 0 0 1px rgba(255,255,255,0.04)"
                        : `inset 0 0 0 1px ${alpha(theme.palette.divider, 0.2)}`,
                    }}
                  >
                    {CATEGORY_CONFIG.map((category) => {
                      const value = item[category.key] as number;
                      const width = total > 0 ? (value / total) * 100 : 0;
                      if (value <= 0) return null;

                      return (
                        <Box
                          key={category.key}
                          title={`${category.label}: ${value}`}
                          sx={{
                            width: `${width}%`,
                            minWidth: value > 0 ? 6 : 0,
                            bgcolor: category.color,
                            transition: "width .35s ease",
                          }}
                        />
                      );
                    })}
                  </Box>

                  {/* Legend */}
                  <Stack
                    direction="row"
                    spacing={1.5}
                    useFlexGap
                    sx={{ mt: 0.75, flexWrap: "wrap" }}
                  >
                    {CATEGORY_CONFIG.map((category) => {
                      const value = item[category.key] as number;
                      const pct =
                        total > 0 ? Math.round((value / total) * 100) : 0;
                      if (value <= 0) return null;

                      return (
                        <Typography
                          key={category.key}
                          variant="caption"
                          sx={{
                            color: "text.secondary",
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 0.5,
                          }}
                        >
                          <Box
                            sx={{
                              width: 7,
                              height: 7,
                              borderRadius: 999,
                              bgcolor: category.color,
                            }}
                          />
                          <Box component="span" sx={{ fontWeight: 700 }}>
                            {category.label}
                          </Box>
                          <Box component="span">
                            {value} · {pct}%
                          </Box>
                        </Typography>
                      );
                    })}
                  </Stack>
                </Box>
              );
            })}
          </Stack>
        )}
      </Box>
    </SoftCard>
  );
}