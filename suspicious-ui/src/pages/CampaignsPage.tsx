import * as React from "react";
import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Grid,
  IconButton,
  InputAdornment,
  Slider,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import {
  RefreshOutlined,
  SearchOutlined,
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
} from "recharts";
import {
  getClassificationCounts,
  getMailVolume,
  getPca,
  type MailVolumeResponse,
  type PcaPoint,
} from "@/features/campaigns/api";
import { mockCounts, mockMailVolume, mockPca } from "@/features/campaigns/mock";

function GlassCard(props: React.PropsWithChildren<{ title: string; icon?: React.ReactNode; right?: React.ReactNode }>) {
  return (
    <Card
      sx={{
        borderRadius: 4,
        border: "1px solid rgba(255,255,255,.10)",
        background:
          "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
      }}
    >
      <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1.25 }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <Box
              sx={{
                width: 40,
                height: 40,
                borderRadius: 2.5,
                display: "grid",
                placeItems: "center",
                border: "1px solid rgba(255,255,255,.12)",
                background:
                  "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
              }}
            >
              {props.icon}
            </Box>
            <Typography fontWeight={950}>{props.title}</Typography>
          </Stack>
          {props.right}
        </Stack>
        <Divider sx={{ opacity: 0.25, mb: 2 }} />
        {props.children}
      </CardContent>
    </Card>
  );
}

function classColor(label: string) {
  const u = (label || "UNKNOWN").toUpperCase();
  if (u === "SAFE") return "rgba(34,197,94,.8)";
  if (u === "UNWANTED") return "rgba(250,204,21,.85)";
  if (u === "SUSPICIOUS") return "rgba(56,189,248,.85)";
  if (u === "DANGEROUS") return "rgba(239,68,68,.85)";
  return "rgba(148,163,184,.75)";
}

function normalizeLabel(label: string) {
  return (label || "UNKNOWN").toUpperCase();
}

function computeCampaignRects(points: PcaPoint[]) {
  // group by sourceRefs signature, compute bounding boxes (simple, readable)
  const map = new Map<string, { name: string; minX: number; maxX: number; minY: number; maxY: number }>();
  for (const p of points) {
    const refs = Array.isArray(p.sourceRefs) ? p.sourceRefs.filter(Boolean) : [];
    if (!refs.length) continue;
    const key = refs.slice().sort().join(" | ");
    const name = refs.length <= 3 ? refs.join(", ") : `${refs.slice(0, 3).join(", ")}…`;
    const cur = map.get(key);
    if (!cur) {
      map.set(key, { name, minX: p.x, maxX: p.x, minY: p.y, maxY: p.y });
    } else {
      cur.minX = Math.min(cur.minX, p.x);
      cur.maxX = Math.max(cur.maxX, p.x);
      cur.minY = Math.min(cur.minY, p.y);
      cur.maxY = Math.max(cur.maxY, p.y);
    }
  }

  // add padding so it looks like a “cluster highlight”
  return Array.from(map.values()).map((b, idx) => {
    const padX = Math.max(0.25, (b.maxX - b.minX) * 0.12);
    const padY = Math.max(0.25, (b.maxY - b.minY) * 0.12);
    return {
      id: idx,
      name: b.name,
      x1: b.minX - padX,
      x2: b.maxX + padX,
      y1: b.minY - padY,
      y2: b.maxY + padY,
    };
  });
}

function toIndexMap(dates: string[]) {
  const m = new Map<string, number>();
  dates.forEach((d, i) => m.set(d, i));
  return m;
}

function dateOnly(iso: string) {
  if (!iso) return "";
  return iso.slice(0, 10);
}

export default function CampaignsPage() {
  const useMock = import.meta.env.VITE_USE_MOCK_CAMPAIGNS === "true";

  const [pcaLimit, setPcaLimit] = React.useState(1500);
  const [pcaFilter, setPcaFilter] = React.useState("");
  const [highlightCampaigns, setHighlightCampaigns] = React.useState(true);

  const countsQuery = useQuery({
    queryKey: ["campaigns", "counts", useMock],
    queryFn: async () => (useMock ? mockCounts() : getClassificationCounts()),
    retry: false,
  });

  const pcaQuery = useQuery({
    queryKey: ["campaigns", "pca", pcaLimit, useMock],
    queryFn: async () => (useMock ? mockPca() : getPca(pcaLimit)),
    retry: false,
  });

  const volumeQuery = useQuery({
    queryKey: ["campaigns", "volume", useMock],
    queryFn: async () => (useMock ? mockMailVolume() : getMailVolume()),
    retry: false,
  });

  const loading = countsQuery.isLoading || pcaQuery.isLoading || volumeQuery.isLoading;

  if (loading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (countsQuery.isError || pcaQuery.isError || volumeQuery.isError) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Failed to load campaigns dashboard (API routes / permissions).</Alert>
      </Box>
    );
  }

  const counts = countsQuery.data ?? { SAFE: 0, UNWANTED: 0, DANGEROUS: 0 };
  const pca = pcaQuery.data ?? { points: [], explained_variance: [0, 0] as [number, number] };
  const volume: MailVolumeResponse =
    volumeQuery.data ?? { dates: [], non_danger: [], dangerous: [], campaigns: [] };

  const classBars = ["SAFE", "UNWANTED", "DANGEROUS"].map((k) => ({
    label: k,
    value: (counts as any)[k] ?? 0,
  }));

  const allPoints = pca.points ?? [];
  const filter = pcaFilter.trim().toLowerCase();
  const points = filter
    ? allPoints.filter((pt) => {
        const lbl = normalizeLabel(pt.label);
        const refs = (pt.sourceRefs ?? []).join(" ").toLowerCase();
        return lbl.toLowerCase().includes(filter) || refs.includes(filter);
      })
    : allPoints;

  const byLabel = new Map<string, PcaPoint[]>();
  for (const pt of points) {
    const k = normalizeLabel(pt.label);
    const arr = byLabel.get(k) ?? [];
    arr.push(pt);
    byLabel.set(k, arr);
  }

  const scatterSeries = Array.from(byLabel.entries()).map(([label, pts]) => ({
    label,
    pts,
  }));

  const campaignRects = highlightCampaigns ? computeCampaignRects(points) : [];

  // Mail volume chart data
  const chartData = volume.dates.map((d, i) => ({
    idx: i,
    date: d,
    label: new Date(d + "T00:00:00Z").toLocaleDateString(undefined, { month: "short", day: "2-digit" }),
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

  return (
    <Box sx={{ p: { xs: 2, md: 3 } }}>
      {/* Header */}
      <Stack direction={{ xs: "column", md: "row" }} spacing={2} justifyContent="space-between" sx={{ mb: 2 }}>
        <Stack spacing={0.3}>
          <Typography variant="h4" fontWeight={950} letterSpacing={-0.5}>
            Campaign Dashboard
          </Typography>
          <Typography color="text.secondary">
            Phishing campaigns visibility: classification, clusters, and volume over time.
          </Typography>
        </Stack>

        <Stack direction="row" spacing={1} alignItems="center">
          <Chip
            icon={<CampaignOutlined />}
            label={useMock ? "Mock mode" : "Live"}
            variant="outlined"
          />
          <IconButton
            aria-label="Refresh"
            onClick={() => {
              countsQuery.refetch();
              pcaQuery.refetch();
              volumeQuery.refetch();
            }}
            sx={{ border: "1px solid rgba(255,255,255,.10)", borderRadius: 2 }}
          >
            <RefreshOutlined />
          </IconButton>
        </Stack>
      </Stack>

      <Grid container spacing={2}>
        {/* Graph 1 */}
        <Grid item xs={12} md={5}>
          <GlassCard
            title="Classification repartition"
            icon={<InsightsOutlined />}
            right={<Chip size="small" label="Counts" variant="outlined" />}
          >
            <Box sx={{ height: 320 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={classBars}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
                  <XAxis dataKey="label" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="value" radius={[10, 10, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </Box>

            <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
              {classBars.map((b) => (
                <Chip key={b.label} size="small" label={`${b.label}: ${b.value}`} variant="outlined" />
              ))}
            </Stack>
          </GlassCard>
        </Grid>

        {/* Graph 2 */}
        <Grid item xs={12} md={7}>
          <GlassCard
            title={`Embeddings map (PCA)`}
            icon={<BubbleChartOutlined />}
            right={
              <Stack direction="row" spacing={1} alignItems="center">
                <Chip
                  size="small"
                  label={`PC1 ${(pca.explained_variance?.[0] ?? 0).toFixed(2)} • PC2 ${(pca.explained_variance?.[1] ?? 0).toFixed(2)}`}
                  variant="outlined"
                />
              </Stack>
            }
          >
            <Grid container spacing={2} sx={{ mb: 1 }}>
              <Grid item xs={12} md={7}>
                <TextField
                  fullWidth
                  label="Filter"
                  placeholder="e.g. dangerous, camp-a"
                  value={pcaFilter}
                  onChange={(e) => setPcaFilter(e.target.value)}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchOutlined fontSize="small" />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} md={5}>
                <Stack spacing={0.5}>
                  <Typography variant="caption" color="text.secondary">
                    Points limit: {pcaLimit}
                  </Typography>
                  <Slider
                    value={pcaLimit}
                    min={200}
                    max={3000}
                    step={100}
                    onChange={(_, v) => setPcaLimit(Number(v))}
                  />
                </Stack>
              </Grid>

              <Grid item xs={12}>
                <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                  <Chip
                    clickable
                    onClick={() => setHighlightCampaigns((v) => !v)}
                    label={highlightCampaigns ? "Campaign highlight: ON" : "Campaign highlight: OFF"}
                    variant="outlined"
                  />
                  <Chip size="small" label={`${points.length} point(s)`} variant="outlined" />
                </Stack>
              </Grid>
            </Grid>

            <Box sx={{ height: 420 }}>
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
                  <XAxis type="number" dataKey="x" name="PC1" />
                  <YAxis type="number" dataKey="y" name="PC2" />
                  <ZAxis type="number" range={[40]} />
                  <Tooltip
                    cursor={{ strokeDasharray: "3 3" }}
                    formatter={(value: any, name: any, ctx: any) => {
                      if (name === "x" || name === "y") return value;
                      return value;
                    }}
                    labelFormatter={() => ""}
                  />

                  {/* Campaign rectangles overlay (simple + readable) */}
                  {campaignRects.map((r) => (
                    <ReferenceArea
                      key={r.id}
                      x1={r.x1}
                      x2={r.x2}
                      y1={r.y1}
                      y2={r.y2}
                      ifOverflow="extendDomain"
                      strokeOpacity={0.9}
                      fillOpacity={0.08}
                      strokeDasharray="6 4"
                    />
                  ))}

                  {scatterSeries.map((s) => (
                    <Scatter
                      key={s.label}
                      name={s.label}
                      data={s.pts}
                      fill={classColor(s.label)}
                      isAnimationActive={false}
                    />
                  ))}
                </ScatterChart>
              </ResponsiveContainer>
            </Box>

            {campaignRects.length ? (
              <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
                {campaignRects.slice(0, 6).map((r) => (
                  <Chip key={r.id} size="small" label={r.name} variant="outlined" />
                ))}
                {campaignRects.length > 6 ? (
                  <Chip size="small" label={`+${campaignRects.length - 6} more`} variant="outlined" />
                ) : null}
              </Stack>
            ) : null}
          </GlassCard>
        </Grid>

        {/* Graph 3 */}
        <Grid item xs={12}>
          <GlassCard title="Mail volume (last 15 days)" icon={<TimelineOutlined />}>
            <Box sx={{ height: 380 }}>
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
                  <XAxis dataKey="label" />
                  <YAxis />
                  <Tooltip />

                  {/* Campaign bands */}
                  {campaignBands.map((b, i) => (
                    <ReferenceArea
                      key={i}
                      x1={chartData[b.startIdx]?.label}
                      x2={chartData[b.endIdx]?.label}
                      ifOverflow="extendDomain"
                      fillOpacity={0.12}
                    />
                  ))}

                  {/* Optional boundary lines */}
                  {campaignBands.map((b, i) => (
                    <React.Fragment key={`line-${i}`}>
                      <ReferenceLine x={chartData[b.startIdx]?.label} strokeDasharray="6 4" />
                      <ReferenceLine x={chartData[b.endIdx]?.label} strokeDasharray="6 4" />
                    </React.Fragment>
                  ))}

                  <Area
                    type="monotone"
                    dataKey="nonDanger"
                    name="Safe/Unwanted"
                    stackId="1"
                    fillOpacity={0.22}
                    strokeWidth={2}
                    isAnimationActive={false}
                  />
                  <Area
                    type="monotone"
                    dataKey="dangerous"
                    name="Dangerous"
                    stackId="1"
                    fillOpacity={0.24}
                    strokeWidth={2}
                    isAnimationActive={false}
                  />
                </ComposedChart>
              </ResponsiveContainer>
            </Box>

            {campaignBands.length ? (
              <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
                {campaignBands.map((b) => (
                  <Chip
                    key={b.name}
                    size="small"
                    label={`${b.name}: ${volume.dates[b.startIdx]} → ${volume.dates[b.endIdx]}`}
                    variant="outlined"
                  />
                ))}
              </Stack>
            ) : (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                No campaign ranges returned.
              </Typography>
            )}
          </GlassCard>
        </Grid>
      </Grid>
    </Box>
  );
}
