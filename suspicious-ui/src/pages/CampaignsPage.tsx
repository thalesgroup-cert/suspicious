// src/pages/CampaignsPage.tsx
import * as React from "react";
import {
  Alert,
  Box,
  Chip,
  CircularProgress,
  IconButton,
  Stack,
  Typography,
} from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { alpha } from "@mui/material/styles";
import {
  RefreshOutlined,
  CampaignOutlined,
  InsightsOutlined,
  BubbleChartOutlined,
  TimelineOutlined,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ScatterChart,
  Scatter,
  ZAxis,
  ReferenceArea,
  ReferenceLine,
  ComposedChart,
  Area,
  Cell,
} from "recharts";
import { Responsive, WidthProvider, type Layout } from "react-grid-layout/legacy";

import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";

import {
  getClassificationCounts,
  getMailVolume,
  getPca,
  type ClassificationCounts,
  type MailVolumeResponse,
  type PcaPoint,
  type PcaResponse,
} from "@/features/campaigns/api";

import { SoftCard } from "@/features/dashboard/components/SoftCard";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CLASS_COLORS: Record<string, string> = {
  SAFE: "#22C55E",
  UNWANTED: "#F59E0B",
  SUSPICIOUS: "#38BDF8",
  DANGEROUS: "#EF4444",
  UNKNOWN: "#94A3B8",
};

const PCA_LABELS = ["SAFE", "UNWANTED", "SUSPICIOUS", "DANGEROUS"];

const PANEL_KEYS = {
  CLASSIFICATION: "classification",
  PCA: "pca",
  VOLUME: "volume",
} as const;

const BREAKPOINTS = { lg: 1200, md: 900, sm: 600, xs: 0 };
const COLS = { lg: 12, md: 12, sm: 6, xs: 1 };
const ROW_HEIGHT = 32;

// Layout: classification (left, tall) + PCA (right, tall) on top row,
// volume (full width) on bottom row.
const DEFAULT_LAYOUTS: Partial<Record<string, Layout>> = {
  lg: [
    { i: PANEL_KEYS.CLASSIFICATION, x: 0,  y: 0,  w: 4,  h: 14, minW: 3, minH: 8 },
    { i: PANEL_KEYS.PCA,            x: 4,  y: 0,  w: 8,  h: 14, minW: 4, minH: 8 },
    { i: PANEL_KEYS.VOLUME,         x: 0,  y: 14, w: 12, h: 12, minW: 6, minH: 8 },
  ],
  md: [
    { i: PANEL_KEYS.CLASSIFICATION, x: 0,  y: 0,  w: 5,  h: 14, minW: 3, minH: 8 },
    { i: PANEL_KEYS.PCA,            x: 5,  y: 0,  w: 7,  h: 14, minW: 4, minH: 8 },
    { i: PANEL_KEYS.VOLUME,         x: 0,  y: 14, w: 12, h: 12, minW: 6, minH: 8 },
  ],
  sm: [
    { i: PANEL_KEYS.CLASSIFICATION, x: 0, y: 0,  w: 6, h: 14, minH: 8 },
    { i: PANEL_KEYS.PCA,            x: 0, y: 14, w: 6, h: 14, minH: 8 },
    { i: PANEL_KEYS.VOLUME,         x: 0, y: 28, w: 6, h: 12, minH: 8 },
  ],
  xs: [
    { i: PANEL_KEYS.CLASSIFICATION, x: 0, y: 0,  w: 1, h: 14, minH: 8 },
    { i: PANEL_KEYS.PCA,            x: 0, y: 14, w: 1, h: 14, minH: 8 },
    { i: PANEL_KEYS.VOLUME,         x: 0, y: 28, w: 1, h: 12, minH: 8 },
  ],
};

const STORAGE_KEY = "campaigns:layouts";

const ResponsiveGridLayout = WidthProvider(Responsive);

// ---------------------------------------------------------------------------
// Layout persistence
// ---------------------------------------------------------------------------

function loadLayouts(): Partial<Record<string, Layout>> {
  if (typeof window === "undefined") return DEFAULT_LAYOUTS;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_LAYOUTS;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed
      : DEFAULT_LAYOUTS;
  } catch {
    return DEFAULT_LAYOUTS;
  }
}

function saveLayouts(layouts: Partial<Record<string, Layout>>) {
  if (typeof window === "undefined") return;
  try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(layouts)); } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function compactLabel(text: string, max = 22) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function classColor(label: string) {
  return CLASS_COLORS[(label || "UNKNOWN").toUpperCase()] ?? CLASS_COLORS.UNKNOWN;
}

function normalizeLabel(label: string) {
  return (label || "UNKNOWN").toUpperCase();
}

function dateOnly(iso: string) {
  return iso ? iso.slice(0, 10) : "";
}

function toIndexMap(dates: string[]) {
  const map = new Map<string, number>();
  dates.forEach((d, i) => map.set(d, i));
  return map;
}

function computeCampaignRects(points: PcaPoint[]) {
  const map = new Map<
    string,
    { name: string; minX: number; maxX: number; minY: number; maxY: number }
  >();

  for (const p of points) {
    const refs = Array.isArray(p.sourceRefs) ? p.sourceRefs.filter(Boolean) : [];
    if (!refs.length) continue;
    const key = refs.slice().sort().join(" | ");
    const name = refs.length <= 3 ? refs.join(", ") : `${refs.slice(0, 3).join(", ")}…`;
    const current = map.get(key);
    if (!current) {
      map.set(key, { name, minX: p.x, maxX: p.x, minY: p.y, maxY: p.y });
    } else {
      current.minX = Math.min(current.minX, p.x);
      current.maxX = Math.max(current.maxX, p.x);
      current.minY = Math.min(current.minY, p.y);
      current.maxY = Math.max(current.maxY, p.y);
    }
  }

  return Array.from(map.values()).map((b, idx) => {
    const padX = Math.max(0.2, (b.maxX - b.minX) * 0.1);
    const padY = Math.max(0.2, (b.maxY - b.minY) * 0.1);
    return {
      id: idx, name: b.name,
      x1: b.minX - padX, x2: b.maxX + padX,
      y1: b.minY - padY, y2: b.maxY + padY,
    };
  });
}

// ---------------------------------------------------------------------------
// Drag handle + panel shell (mirrors DashboardPage)
// ---------------------------------------------------------------------------

function DragDots({ dotColor }: { dotColor: string }) {
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: "repeat(3, 5px)",
        gridTemplateRows: "repeat(2, 5px)",
        gap: "3px",
        pointerEvents: "none",
      }}
    >
      {Array.from({ length: 6 }).map((_, i) => (
        <Box key={i} sx={{ width: 4, height: 4, borderRadius: 99, backgroundColor: dotColor }} />
      ))}
    </Box>
  );
}

function DragHandle() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const dotColor = isDark ? "rgba(255,255,255,.38)" : alpha(theme.palette.divider, 0.9);

  return (
    <Box
      className="campaigns-drag-handle"
      title="Drag to move"
      sx={{
        flexShrink: 0,
        height: 22,
        mb: 0.5,
        borderRadius: "8px 8px 0 0",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        cursor: "grab",
        userSelect: "none",
        opacity: 0,
        transition: "opacity .18s ease, background .18s ease",
        background: isDark ? alpha("#fff", 0.04) : alpha(theme.palette.grey[400], 0.1),
        "&:active": {
          cursor: "grabbing",
          background: isDark ? alpha("#fff", 0.08) : alpha(theme.palette.grey[400], 0.18),
        },
      }}
    >
      <DragDots dotColor={dotColor} />
    </Box>
  );
}

const PanelShell = React.memo(function PanelShell({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <Box
      sx={{
        height: "100%",
        minHeight: 0,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        "& .react-resizable-handle": { opacity: 0, transition: "opacity .18s ease" },
        "&:hover .react-resizable-handle": { opacity: 1 },
      }}
    >
      <DragHandle />
      <Box sx={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
        {children}
      </Box>
    </Box>
  );
});

// ---------------------------------------------------------------------------
// Global CSS overrides for grid (mirrors DashboardPage.GridStyles)
// ---------------------------------------------------------------------------

function GridStyles() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const handleColor = isDark ? "rgba(255,255,255,.55)" : alpha(theme.palette.grey[500], 0.7);
  const handleBg = isDark
    ? "rgba(30,41,59,0.92)"
    : alpha(theme.palette.background.paper, 0.95);
  const handleBorder = isDark
    ? "1px solid rgba(255,255,255,.12)"
    : `1px solid ${alpha(theme.palette.divider, 0.7)}`;
  const placeholderBg = isDark
    ? "rgba(56,189,248,.14)"
    : alpha(theme.palette.primary.main, 0.08);
  const placeholderBorder = isDark
    ? "rgba(56,189,248,.45)"
    : alpha(theme.palette.primary.main, 0.4);

  return (
    <style>{`
      .react-resizable-handle {
        position: absolute;
        width: 20px;
        height: 20px;
        bottom: 4px;
        right: 4px;
        padding: 0;
        border-radius: 6px;
        background: ${handleBg};
        border: ${handleBorder};
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: se-resize;
        z-index: 10;
        transition: opacity .18s ease;
      }
      .react-resizable-handle::after {
        content: '';
        display: block;
        width: 8px;
        height: 8px;
        border-right: 2px solid ${handleColor};
        border-bottom: 2px solid ${handleColor};
        border-radius: 0 0 3px 0;
      }
      .react-resizable-handle-se {
        background-image: none !important;
        background-position: unset !important;
      }
      .react-grid-item.react-grid-placeholder {
        background: ${placeholderBg} !important;
        border: 2px dashed ${placeholderBorder} !important;
        border-radius: 12px !important;
        opacity: 1 !important;
      }
      .react-grid-item:hover .campaigns-drag-handle {
        opacity: 1 !important;
      }
      .react-grid-item:hover .react-resizable-handle {
        opacity: 1 !important;
      }
    `}</style>
  );
}

// ---------------------------------------------------------------------------
// Theme-aware tooltips
// ---------------------------------------------------------------------------

function ClassificationTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ value?: number; color?: string }>;
  label?: string;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  if (!active || !payload?.length) return null;

  const value = payload[0]?.value ?? 0;
  const color = payload[0]?.color ?? classColor(label || "UNKNOWN");

  return (
    <Box
      sx={{
        background: isDark ? "rgba(15,23,42,0.95)" : alpha(theme.palette.background.paper, 0.97),
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
        borderRadius: 2,
        px: 1.25,
        py: 1,
        backdropFilter: "blur(6px)",
        minWidth: 130,
      }}
    >
      <Typography sx={{ fontSize: 12, fontWeight: 700, color: "text.primary", mb: 0.5 }}>
        {label}
      </Typography>
      <Typography sx={{ fontSize: 12, fontWeight: 600, color }}>
        Value: {value}
      </Typography>
    </Box>
  );
}

function PcaTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ payload?: PcaPoint }>;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  if (!active || !payload?.length) return null;

  const point = payload[0]?.payload;
  if (!point) return null;

  const refs = Array.isArray(point.sourceRefs) ? point.sourceRefs : [];

  return (
    <Box
      sx={{
        background: isDark ? "rgba(15,23,42,0.96)" : alpha(theme.palette.background.paper, 0.97),
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
        borderRadius: 2,
        px: 1.25,
        py: 1,
        minWidth: 180,
        maxWidth: 260,
        backdropFilter: "blur(6px)",
      }}
    >
      <Typography sx={{ fontSize: 12, fontWeight: 800, color: "text.primary", mb: 0.5 }}>
        {point.label || "UNKNOWN"}
      </Typography>
      {point.suspicious_case_id ? (
        <Typography sx={{ fontSize: 12, color: "text.secondary", mb: 0.5 }}>
          Case: {point.suspicious_case_id}
        </Typography>
      ) : null}
      {refs.length ? (
        <Typography sx={{ fontSize: 12, color: isDark ? "#93C5FD" : theme.palette.primary.main, wordBreak: "break-word" }}>
          {refs.slice(0, 3).join(", ")}
          {refs.length > 3 ? "…" : ""}
        </Typography>
      ) : (
        <Typography sx={{ fontSize: 12, color: "text.disabled" }}>No campaign refs</Typography>
      )}
    </Box>
  );
}

function VolumeTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ dataKey?: string; name?: string; value?: number; color?: string }>;
  label?: string;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  if (!active || !payload?.length) return null;

  return (
    <Box
      sx={{
        background: isDark ? "rgba(15,23,42,0.95)" : alpha(theme.palette.background.paper, 0.97),
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
        borderRadius: 2,
        px: 1.5,
        py: 1,
        backdropFilter: "blur(6px)",
      }}
    >
      <Typography sx={{ fontSize: 12, fontWeight: 700, color: "text.primary", mb: 0.5 }}>
        {label}
      </Typography>
      {payload.map((p) => (
        <Typography key={p.dataKey} sx={{ fontSize: 12, fontWeight: 600, color: p.color }}>
          {p.name}: {p.value}
        </Typography>
      ))}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function CampaignsPage() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const [pcaLimit] = React.useState(1500);
  const [pcaFilter] = React.useState("");
  const [highlightCampaigns] = React.useState(true);
  const [visibleLabels, setVisibleLabels] = React.useState<string[]>([
    "SAFE", "UNWANTED", "SUSPICIOUS", "DANGEROUS",
  ]);

  const [layouts, setLayouts] = React.useState<Partial<Record<string, Layout>>>(() =>
    loadLayouts()
  );

  const countsQuery = useQuery<ClassificationCounts>({
    queryKey: ["campaigns", "counts"],
    queryFn: getClassificationCounts,
    retry: false,
  });

  const pcaQuery = useQuery<PcaResponse>({
    queryKey: ["campaigns", "pca", pcaLimit],
    queryFn: () => getPca(pcaLimit),
    retry: false,
  });

  const volumeQuery = useQuery<MailVolumeResponse>({
    queryKey: ["campaigns", "volume"],
    queryFn: getMailVolume,
    retry: false,
  });

  const toggleLabel = React.useCallback((label: string) => {
    setVisibleLabels((prev) =>
      prev.includes(label) ? prev.filter((x) => x !== label) : [...prev, label]
    );
  }, []);

  const handleLayoutsChange = React.useCallback(
    (_current: Layout, all: Partial<Record<string, Layout>>) => {
      setLayouts(all);
      saveLayouts(all);
    },
    []
  );

  const resetLayouts = React.useCallback(() => {
    setLayouts(DEFAULT_LAYOUTS);
    saveLayouts(DEFAULT_LAYOUTS);
  }, []);

  const loading = countsQuery.isLoading || pcaQuery.isLoading || volumeQuery.isLoading;

  if (loading) {
    return (
      <Box sx={{ minHeight: "50vh", display: "grid", placeItems: "center" }}>
        <CircularProgress size={26} />
      </Box>
    );
  }

  if (countsQuery.isError || pcaQuery.isError || volumeQuery.isError) {
    return (
      <Box sx={{ p: 2 }}>
        <Alert severity="error">
          Failed to load campaigns dashboard (API routes / permissions).
        </Alert>
      </Box>
    );
  }

  const counts = countsQuery.data ?? { SAFE: 0, UNWANTED: 0, DANGEROUS: 0 };
  const pca = pcaQuery.data ?? { points: [], explained_variance: [0, 0] as [number, number] };
  const volume = volumeQuery.data ?? { dates: [], non_danger: [], dangerous: [], campaigns: [] };

  const classBars = ["SAFE", "UNWANTED", "DANGEROUS"].map((k) => ({
    label: k,
    value: counts[k as keyof ClassificationCounts] ?? 0,
  }));

  const filter = pcaFilter.trim().toLowerCase();
  const allPoints = pca.points ?? [];

  const points = allPoints.filter((pt) => {
    const lbl = normalizeLabel(pt.label);
    const refs = (pt.sourceRefs ?? []).join(" ").toLowerCase();
    const passesText = !filter || lbl.toLowerCase().includes(filter) || refs.includes(filter);
    return passesText && visibleLabels.includes(lbl);
  });

  const byLabel = new Map<string, PcaPoint[]>();
  for (const pt of points) {
    const key = normalizeLabel(pt.label);
    const arr = byLabel.get(key) ?? [];
    arr.push(pt);
    byLabel.set(key, arr);
  }

  const scatterSeries = Array.from(byLabel.entries()).map(([label, pts]) => ({ label, pts }));
  const campaignRects = highlightCampaigns ? computeCampaignRects(points) : [];

  const chartData = volume.dates.map((d, i) => ({
    idx: i,
    date: d,
    label: new Date(`${d}T00:00:00Z`).toLocaleDateString(undefined, {
      month: "short",
      day: "2-digit",
    }),
    nonDanger: volume.non_danger[i] ?? 0,
    dangerous: volume.dangerous[i] ?? 0,
  }));

  const dateToIdx = toIndexMap(volume.dates);
  const campaignBands = (volume.campaigns ?? [])
    .map((c) => {
      const start = dateOnly(c.start);
      const end = dateOnly(c.end);
      const s = dateToIdx.get(start);
      const e = dateToIdx.get(end);
      if (s === undefined || e === undefined) return null;
      return { name: c.name, startIdx: Math.min(s, e), endIdx: Math.max(s, e) };
    })
    .filter(Boolean) as { name: string; startIdx: number; endIdx: number }[];

  // Chart axis tick color adapts to theme
  const tickStyle = { fontSize: 11, fill: theme.palette.text.secondary };
  const gridOpacity = isDark ? 0.25 : 0.4;
  const cursorFill = isDark ? "rgba(148,163,184,0.10)" : alpha(theme.palette.action.hover, 0.14);

  return (
    <Box sx={{ p: { xs: 1.5, md: 2 } }}>
      <GridStyles />

      {/* ---------------------------------------------------------------- */}
      {/* Page header                                                       */}
      {/* ---------------------------------------------------------------- */}
      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={1.5}
        justifyContent="space-between"
        sx={{ mb: 1.5 }}
      >
        <Stack spacing={0.2}>
          <Typography variant="h5" fontWeight={900} letterSpacing={-0.4}>
            Campaign Dashboard
          </Typography>
          <Typography color="text.secondary" fontSize={14}>
            Phishing campaigns visibility: classification, clusters, and volume over time.
          </Typography>
        </Stack>

        <Stack direction="row" spacing={1} alignItems="center">
          <Chip icon={<CampaignOutlined />} label="Live" variant="outlined" size="small" />
          <Box
            component="button"
            type="button"
            onClick={resetLayouts}
            sx={{
              border: 0,
              background: "transparent",
              color: "text.secondary",
              fontSize: 12,
              fontWeight: 700,
              cursor: "pointer",
              textDecoration: "underline",
            }}
          >
            Reset layout
          </Box>
          <IconButton
            aria-label="Refresh"
            onClick={() => {
              countsQuery.refetch();
              pcaQuery.refetch();
              volumeQuery.refetch();
            }}
            size="small"
            sx={{
              border: isDark
                ? "1px solid rgba(255,255,255,.10)"
                : `1px solid ${alpha(theme.palette.divider, 0.6)}`,
              borderRadius: 2,
            }}
          >
            <RefreshOutlined fontSize="small" />
          </IconButton>
        </Stack>
      </Stack>

      {/* ---------------------------------------------------------------- */}
      {/* Draggable / resizable grid                                        */}
      {/* ---------------------------------------------------------------- */}
      <ResponsiveGridLayout
        className="campaigns-layout"
        layouts={layouts}
        breakpoints={BREAKPOINTS}
        cols={COLS}
        rowHeight={ROW_HEIGHT}
        margin={[16, 16]}
        containerPadding={[0, 0]}
        compactType="vertical"
        preventCollision={false}
        isDraggable
        isResizable
        useCSSTransforms
        measureBeforeMount={false}
        draggableHandle=".campaigns-drag-handle"
        onLayoutChange={handleLayoutsChange}
      >
        {/* ── Classification repartition ─────────────────────────────── */}
        <Box
          key={PANEL_KEYS.CLASSIFICATION}
          sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}
        >
          <PanelShell>
            <SoftCard
              title="Classification repartition"
              icon={<InsightsOutlined />}
              right={<Chip size="small" label="Counts" variant="outlined" />}
              fillHeight
            >
              <Box sx={{ flex: 1, minHeight: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={classBars}>
                    <CartesianGrid strokeDasharray="3 3" opacity={gridOpacity} />
                    <XAxis dataKey="label" tick={tickStyle} />
                    <YAxis tick={tickStyle} />
                    <Tooltip
                      content={<ClassificationTooltip />}
                      cursor={{ fill: cursorFill }}
                    />
                    <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                      {classBars.map((entry) => (
                        <Cell
                          key={entry.label}
                          fill={CLASS_COLORS[entry.label] ?? CLASS_COLORS.UNKNOWN}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </Box>
            </SoftCard>
          </PanelShell>
        </Box>

        {/* ── Embeddings map (PCA) ───────────────────────────────────── */}
        <Box
          key={PANEL_KEYS.PCA}
          sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}
        >
          <PanelShell>
            <SoftCard
              title="Embeddings map (PCA)"
              icon={<BubbleChartOutlined />}
              right={
                <Chip
                  size="small"
                  label={`PC1 ${(pca.explained_variance?.[0] ?? 0).toFixed(2)} • PC2 ${(pca.explained_variance?.[1] ?? 0).toFixed(2)}`}
                  variant="outlined"
                />
              }
              fillHeight
            >
              {/* Label toggles */}
              <Stack direction="row" spacing={0.75} sx={{ flexWrap: "wrap", mb: 0.75, flexShrink: 0 }}>
                {PCA_LABELS.map((label) => {
                  const active = visibleLabels.includes(label);
                  return (
                    <Chip
                      key={label}
                      size="small"
                      clickable
                      onClick={() => toggleLabel(label)}
                      label={label}
                      variant={active ? "filled" : "outlined"}
                      sx={{
                        borderColor: classColor(label),
                        bgcolor: active ? classColor(label) : "transparent",
                        color: active ? "#fff" : "inherit",
                      }}
                    />
                  );
                })}
              </Stack>

              <Box sx={{ flex: 1, minHeight: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <ScatterChart margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" opacity={gridOpacity} />
                    <XAxis type="number" dataKey="x" name="PC1" tick={tickStyle} />
                    <YAxis type="number" dataKey="y" name="PC2" tick={tickStyle} />
                    <ZAxis type="number" range={[18]} />
                    <Tooltip
                      content={<PcaTooltip />}
                      cursor={{ stroke: isDark ? "#94A3B8" : alpha(theme.palette.divider, 0.8), strokeDasharray: "4 4" }}
                    />
                    {campaignRects.map((r) => (
                      <ReferenceArea
                        key={r.id}
                        x1={r.x1} x2={r.x2} y1={r.y1} y2={r.y2}
                        ifOverflow="extendDomain"
                        stroke={isDark ? "#94A3B8" : alpha(theme.palette.divider, 0.7)}
                        strokeOpacity={0.45}
                        fill={isDark ? "#94A3B8" : alpha(theme.palette.grey[400], 0.15)}
                        fillOpacity={0.05}
                        strokeDasharray="5 4"
                      />
                    ))}
                    {scatterSeries.map((s) => (
                      <Scatter
                        key={s.label}
                        name={s.label}
                        data={s.pts}
                        fill={classColor(s.label)}
                        isAnimationActive={false}
                        shape="circle"
                      />
                    ))}
                  </ScatterChart>
                </ResponsiveContainer>
              </Box>
            </SoftCard>
          </PanelShell>
        </Box>

        {/* ── Mail volume ────────────────────────────────────────────── */}
        <Box
          key={PANEL_KEYS.VOLUME}
          sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}
        >
          <PanelShell>
            <SoftCard
              title="Mail volume (last 15 days)"
              icon={<TimelineOutlined />}
              fillHeight
            >
              <Box sx={{ flex: 1, minHeight: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={chartData}>
                    <defs>
                      <linearGradient id="blueArea" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#3B82F6" stopOpacity={isDark ? 0.4 : 0.3} />
                        <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="redArea" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#EF4444" stopOpacity={isDark ? 0.5 : 0.35} />
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                      </linearGradient>
                    </defs>

                    <CartesianGrid strokeDasharray="3 3" opacity={gridOpacity} />
                    <XAxis dataKey="label" tick={tickStyle} />
                    <YAxis tick={tickStyle} />
                    <Tooltip
                      content={<VolumeTooltip />}
                      cursor={{ stroke: isDark ? "#94A3B8" : alpha(theme.palette.divider, 0.8), strokeWidth: 1, strokeDasharray: "4 4" }}
                    />

                    {campaignBands.map((b, i) => (
                      <ReferenceArea
                        key={i}
                        x1={chartData[b.startIdx]?.label}
                        x2={chartData[b.endIdx]?.label}
                        ifOverflow="extendDomain"
                        fill={isDark ? "rgba(255,255,255,0.04)" : alpha(theme.palette.primary.main, 0.05)}
                        fillOpacity={1}
                      />
                    ))}

                    {campaignBands.map((b, i) => (
                      <React.Fragment key={`line-${i}`}>
                        <ReferenceLine
                          x={chartData[b.startIdx]?.label}
                          stroke={isDark ? "rgba(255,255,255,.25)" : alpha(theme.palette.divider, 0.7)}
                          strokeDasharray="6 4"
                        />
                        <ReferenceLine
                          x={chartData[b.endIdx]?.label}
                          stroke={isDark ? "rgba(255,255,255,.25)" : alpha(theme.palette.divider, 0.7)}
                          strokeDasharray="6 4"
                        />
                      </React.Fragment>
                    ))}

                    <Area
                      type="monotone"
                      dataKey="nonDanger"
                      name="Safe/Unwanted"
                      stackId="1"
                      stroke="#3B82F6"
                      fill="url(#blueArea)"
                      fillOpacity={0.18}
                      strokeWidth={2}
                      dot={{ r: 2, strokeWidth: 0, fill: "#3B82F6" }}
                      activeDot={{ r: 5, fill: "#3B82F6" }}
                      isAnimationActive={false}
                    />
                    <Area
                      type="monotone"
                      dataKey="dangerous"
                      name="Dangerous"
                      stackId="1"
                      stroke="#EF4444"
                      fill="url(#redArea)"
                      fillOpacity={0.32}
                      strokeWidth={2}
                      dot={{ r: 2, strokeWidth: 0, fill: "#EF4444" }}
                      activeDot={{ r: 5, fill: "#EF4444" }}
                      isAnimationActive={false}
                    />
                  </ComposedChart>
                </ResponsiveContainer>
              </Box>

              {/* Campaign band chips */}
              {campaignBands.length ? (
                <Stack direction="row" spacing={0.75} sx={{ mt: 1, flexWrap: "wrap", flexShrink: 0 }}>
                  {campaignBands.slice(0, 6).map((b) => (
                    <Chip
                      key={b.name}
                      size="small"
                      label={compactLabel(
                        `${b.name}: ${volume.dates[b.startIdx]} → ${volume.dates[b.endIdx]}`,
                        28
                      )}
                      variant="outlined"
                    />
                  ))}
                  {campaignBands.length > 6 ? (
                    <Chip size="small" label={`+${campaignBands.length - 6} more`} variant="outlined" />
                  ) : null}
                </Stack>
              ) : (
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ mt: 1, fontSize: 13, flexShrink: 0 }}
                >
                  No campaign ranges returned.
                </Typography>
              )}
            </SoftCard>
          </PanelShell>
        </Box>
      </ResponsiveGridLayout>
    </Box>
  );
}