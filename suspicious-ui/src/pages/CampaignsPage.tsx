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
import { Skeleton } from "boneyard-js/react";
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
import {
  Responsive,
  WidthProvider,
  type Layout,
} from "react-grid-layout/legacy";

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

import {
  BREAKPOINTS,
  CLASS_COLORS,
  COLS,
  DEFAULT_LAYOUTS,
  PANEL_KEYS,
  PCA_LABELS,
  ROW_HEIGHT,
  classColor,
  compactLabel,
  computeCampaignRects,
  dateOnly,
  loadLayouts,
  normalizeLabel,
  saveLayouts,
  toIndexMap,
} from "@/features/campaigns/utils";

import { GridStyles, PanelShell } from "@/features/campaigns/components/grid";
import {
  ClassificationTooltip,
  PcaTooltip,
  VolumeTooltip,
} from "@/features/campaigns/components/tooltips";

const ResponsiveGridLayout = WidthProvider(Responsive);

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
    "SAFE",
    "UNWANTED",
    "SUSPICIOUS",
    "DANGEROUS",
  ]);

  const [layouts, setLayouts] = React.useState<Partial<Record<string, Layout>>>(
    () => loadLayouts(),
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
      prev.includes(label) ? prev.filter((x) => x !== label) : [...prev, label],
    );
  }, []);

  const handleLayoutsChange = React.useCallback(
    (_current: Layout, all: Partial<Record<string, Layout>>) => {
      setLayouts(all);
      saveLayouts(all);
    },
    [],
  );

  const resetLayouts = React.useCallback(() => {
    setLayouts(DEFAULT_LAYOUTS);
    saveLayouts(DEFAULT_LAYOUTS);
  }, []);

  const loading =
    countsQuery.isLoading || pcaQuery.isLoading || volumeQuery.isLoading;

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
  const pca = pcaQuery.data ?? {
    points: [],
    explained_variance: [0, 0] as [number, number],
  };
  const volume = volumeQuery.data ?? {
    dates: [],
    non_danger: [],
    dangerous: [],
    campaigns: [],
  };

  const classBars = ["SAFE", "UNWANTED", "DANGEROUS"].map((k) => ({
    label: k,
    value: counts[k as keyof ClassificationCounts] ?? 0,
  }));

  const filter = pcaFilter.trim().toLowerCase();
  const allPoints = pca.points ?? [];

  const points = allPoints.filter((pt) => {
    const lbl = normalizeLabel(pt.label);
    const refs = (pt.sourceRefs ?? []).join(" ").toLowerCase();
    const passesText =
      !filter || lbl.toLowerCase().includes(filter) || refs.includes(filter);
    return passesText && visibleLabels.includes(lbl);
  });

  const byLabel = new Map<string, PcaPoint[]>();
  for (const pt of points) {
    const key = normalizeLabel(pt.label);
    const arr = byLabel.get(key) ?? [];
    arr.push(pt);
    byLabel.set(key, arr);
  }

  const scatterSeries = Array.from(byLabel.entries()).map(([label, pts]) => ({
    label,
    pts,
  }));
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
  const cursorFill = isDark
    ? "rgba(148,163,184,0.10)"
    : alpha(theme.palette.action.hover, 0.14);

  return (
    <Skeleton
      name="campaigns-page"
      loading={countsQuery.isPending || pcaQuery.isPending || volumeQuery.isPending}
      animate="shimmer"
    >
    <Box sx={{ p: { xs: 1.5, md: 2 } }}>
      <GridStyles />

      {/* ---------------------------------------------------------------- */}
      {/* Page header                                                       */}
      {/* ---------------------------------------------------------------- */}
      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={1.5}
        sx={{ mb: 1.5, justifyContent: "space-between" }}
      >
        <Stack spacing={0.2}>
          <Typography variant="h5" sx={{ fontWeight: 900, letterSpacing: -0.4 }} >
            Campaign Dashboard
          </Typography>
          <Typography color="text.secondary" sx={{ fontSize: 14 }} >
            Phishing campaigns visibility: classification, clusters, and volume
            over time.
          </Typography>
        </Stack>

        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
          <Chip
            icon={<CampaignOutlined />}
            label="Live"
            variant="outlined"
            size="small"
          />
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
                    <CartesianGrid
                      strokeDasharray="3 3"
                      opacity={gridOpacity}
                    />
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
                          fill={
                            CLASS_COLORS[entry.label] ?? CLASS_COLORS.UNKNOWN
                          }
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
              <Stack
                direction="row"
                spacing={0.75}
                sx={{ flexWrap: "wrap", mb: 0.75, flexShrink: 0 }}
              >
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
                  <ScatterChart
                    margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      opacity={gridOpacity}
                    />
                    <XAxis
                      type="number"
                      dataKey="x"
                      name="PC1"
                      tick={tickStyle}
                    />
                    <YAxis
                      type="number"
                      dataKey="y"
                      name="PC2"
                      tick={tickStyle}
                    />
                    <ZAxis type="number" range={[0, 18]} />
                    <Tooltip
                      content={<PcaTooltip />}
                      cursor={{
                        stroke: isDark
                          ? "#94A3B8"
                          : alpha(theme.palette.divider, 0.8),
                        strokeDasharray: "4 4",
                      }}
                    />
                    {campaignRects.map((r) => (
                      <ReferenceArea
                        key={r.id}
                        x1={r.x1}
                        x2={r.x2}
                        y1={r.y1}
                        y2={r.y2}
                        ifOverflow="extendDomain"
                        stroke={
                          isDark ? "#94A3B8" : alpha(theme.palette.divider, 0.7)
                        }
                        strokeOpacity={0.45}
                        fill={
                          isDark
                            ? "#94A3B8"
                            : alpha(theme.palette.grey[400], 0.15)
                        }
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
                        <stop
                          offset="5%"
                          stopColor="#3B82F6"
                          stopOpacity={isDark ? 0.4 : 0.3}
                        />
                        <stop
                          offset="95%"
                          stopColor="#3B82F6"
                          stopOpacity={0}
                        />
                      </linearGradient>
                      <linearGradient id="redArea" x1="0" y1="0" x2="0" y2="1">
                        <stop
                          offset="5%"
                          stopColor="#EF4444"
                          stopOpacity={isDark ? 0.5 : 0.35}
                        />
                        <stop
                          offset="95%"
                          stopColor="#EF4444"
                          stopOpacity={0}
                        />
                      </linearGradient>
                    </defs>

                    <CartesianGrid
                      strokeDasharray="3 3"
                      opacity={gridOpacity}
                    />
                    <XAxis dataKey="label" tick={tickStyle} />
                    <YAxis tick={tickStyle} />
                    <Tooltip
                      content={<VolumeTooltip />}
                      cursor={{
                        stroke: isDark
                          ? "#94A3B8"
                          : alpha(theme.palette.divider, 0.8),
                        strokeWidth: 1,
                        strokeDasharray: "4 4",
                      }}
                    />

                    {campaignBands.map((b, i) => (
                      <ReferenceArea
                        key={i}
                        x1={chartData[b.startIdx]?.label}
                        x2={chartData[b.endIdx]?.label}
                        ifOverflow="extendDomain"
                        fill={
                          isDark
                            ? "rgba(255,255,255,0.04)"
                            : alpha(theme.palette.primary.main, 0.05)
                        }
                        fillOpacity={1}
                      />
                    ))}

                    {campaignBands.map((b, i) => (
                      <React.Fragment key={`line-${i}`}>
                        <ReferenceLine
                          x={chartData[b.startIdx]?.label}
                          stroke={
                            isDark
                              ? "rgba(255,255,255,.25)"
                              : alpha(theme.palette.divider, 0.7)
                          }
                          strokeDasharray="6 4"
                        />
                        <ReferenceLine
                          x={chartData[b.endIdx]?.label}
                          stroke={
                            isDark
                              ? "rgba(255,255,255,.25)"
                              : alpha(theme.palette.divider, 0.7)
                          }
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
                <Stack
                  direction="row"
                  spacing={0.75}
                  sx={{ mt: 1, flexWrap: "wrap", flexShrink: 0 }}
                >
                  {campaignBands.slice(0, 6).map((b) => (
                    <Chip
                      key={b.name}
                      size="small"
                      label={compactLabel(
                        `${b.name}: ${volume.dates[b.startIdx]} → ${volume.dates[b.endIdx]}`,
                        28,
                      )}
                      variant="outlined"
                    />
                  ))}
                  {campaignBands.length > 6 ? (
                    <Chip
                      size="small"
                      label={`+${campaignBands.length - 6} more`}
                      variant="outlined"
                    />
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
    </Skeleton>
  );
}
