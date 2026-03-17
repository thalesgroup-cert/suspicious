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
  Cell,
} from "recharts";
import {
  getClassificationCounts,
  getMailVolume,
  getPca,
  type ClassificationCounts,
  type MailVolumeResponse,
  type PcaPoint,
  type PcaResponse,
} from "@/features/campaigns/api";

const CLASS_COLORS: Record<string, string> = {
  SAFE: "#22C55E",
  UNWANTED: "#F59E0B",
  SUSPICIOUS: "#38BDF8",
  DANGEROUS: "#EF4444",
  UNKNOWN: "#94A3B8",
};

const PCA_LABELS = ["SAFE", "UNWANTED", "SUSPICIOUS", "DANGEROUS"];

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
      map.set(key, {
        name,
        minX: p.x,
        maxX: p.x,
        minY: p.y,
        maxY: p.y,
      });
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
      id: idx,
      name: b.name,
      x1: b.minX - padX,
      x2: b.maxX + padX,
      y1: b.minY - padY,
      y2: b.maxY + padY,
    };
  });
}

function GlassCard(props: React.PropsWithChildren<{
  title: string;
  icon?: React.ReactNode;
  right?: React.ReactNode;
}>) {
  return (
    <Card
      sx={{
        borderRadius: 3,
        border: "1px solid rgba(255,255,255,.10)",
        background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
      }}
    >
      <CardContent sx={{ p: { xs: 1.5, md: 2 } }}>
        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
          <Stack direction="row" spacing={0.9} alignItems="center">
            <Box
              sx={{
                width: 34,
                height: 34,
                borderRadius: 2,
                display: "grid",
                placeItems: "center",
                border: "1px solid rgba(255,255,255,.12)",
                background:
                  "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                "& svg": { fontSize: 18 },
              }}
            >
              {props.icon}
            </Box>
            <Typography fontWeight={900} fontSize={15}>
              {props.title}
            </Typography>
          </Stack>
          {props.right}
        </Stack>

        <Divider sx={{ opacity: 0.25, mb: 1.5 }} />
        {props.children}
      </CardContent>
    </Card>
  );
}

function ClassificationTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ value?: number; color?: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;

  const value = payload[0]?.value ?? 0;
  const color = payload[0]?.color ?? classColor(label || "UNKNOWN");

  return (
    <Box
      sx={{
        background: "rgba(15,23,42,0.95)",
        border: "1px solid rgba(255,255,255,0.12)",
        borderRadius: 2,
        px: 1.25,
        py: 1,
        backdropFilter: "blur(6px)",
        minWidth: 130,
      }}
    >
      <Typography
        sx={{
          fontSize: 12,
          fontWeight: 700,
          color: "#E2E8F0",
          mb: 0.5,
        }}
      >
        {label}
      </Typography>

      <Typography
        sx={{
          fontSize: 12,
          fontWeight: 600,
          color,
        }}
      >
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
  if (!active || !payload?.length) return null;

  const point = payload[0]?.payload;
  if (!point) return null;

  const refs = Array.isArray(point.sourceRefs) ? point.sourceRefs : [];

  return (
    <Box
      sx={{
        background: "rgba(15,23,42,0.96)",
        border: "1px solid rgba(255,255,255,.12)",
        borderRadius: 2,
        px: 1.25,
        py: 1,
        minWidth: 180,
        maxWidth: 260,
        backdropFilter: "blur(6px)",
      }}
    >
      <Typography sx={{ fontSize: 12, fontWeight: 800, color: "#E2E8F0", mb: 0.5 }}>
        {point.label || "UNKNOWN"}
      </Typography>

      {point.suspicious_case_id ? (
        <Typography sx={{ fontSize: 12, color: "#CBD5E1", mb: 0.5 }}>
          Case: {point.suspicious_case_id}
        </Typography>
      ) : null}

      {refs.length ? (
        <Typography sx={{ fontSize: 12, color: "#93C5FD", wordBreak: "break-word" }}>
          {refs.slice(0, 3).join(", ")}
          {refs.length > 3 ? "…" : ""}
        </Typography>
      ) : (
        <Typography sx={{ fontSize: 12, color: "#94A3B8" }}>
          No campaign refs
        </Typography>
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
  if (!active || !payload?.length) return null;

  return (
    <Box
      sx={{
        background: "rgba(15,23,42,0.95)",
        border: "1px solid rgba(255,255,255,0.12)",
        borderRadius: 2,
        px: 1.5,
        py: 1,
        backdropFilter: "blur(6px)",
      }}
    >
      <Typography
        sx={{
          fontSize: 12,
          fontWeight: 700,
          color: "#E2E8F0",
          mb: 0.5,
        }}
      >
        {label}
      </Typography>

      {payload.map((p) => (
        <Typography
          key={p.dataKey}
          sx={{
            fontSize: 12,
            fontWeight: 600,
            color: p.color,
          }}
        >
          {p.name}: {p.value}
        </Typography>
      ))}
    </Box>
  );
}

export default function CampaignsPage() {
  const [pcaLimit, setPcaLimit] = React.useState(1500);
  const [pcaFilter, setPcaFilter] = React.useState("");
  const [highlightCampaigns, setHighlightCampaigns] = React.useState(true);
  const [visibleLabels, setVisibleLabels] = React.useState<string[]>([
    "SAFE",
    "UNWANTED",
    "SUSPICIOUS",
    "DANGEROUS",
  ]);

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

    const passesText =
      !filter || lbl.toLowerCase().includes(filter) || refs.includes(filter);

    const passesLabel = visibleLabels.includes(lbl);

    return passesText && passesLabel;
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

  return (
    <Box sx={{ p: { xs: 1.5, md: 2 } }}>
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
          <IconButton
            aria-label="Refresh"
            onClick={() => {
              countsQuery.refetch();
              pcaQuery.refetch();
              volumeQuery.refetch();
            }}
            size="small"
            sx={{ border: "1px solid rgba(255,255,255,.10)", borderRadius: 2 }}
          >
            <RefreshOutlined fontSize="small" />
          </IconButton>
        </Stack>
      </Stack>

      <Grid container spacing={2}>
        <Grid item xs={12} md={4.5}>
          <GlassCard
            title="Classification repartition"
            icon={<InsightsOutlined />}
            right={<Chip size="small" label="Counts" variant="outlined" />}
          >
            <Box sx={{ height: 370 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={classBars}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
                  <XAxis dataKey="label" tick={{ fontSize: 11 }} />
                  <YAxis tick={{ fontSize: 11 }} />
                  <Tooltip
                    content={<ClassificationTooltip />}
                    cursor={{ fill: "rgba(148,163,184,0.10)" }}
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
          </GlassCard>
        </Grid>

        <Grid item xs={12} md={7.5}>
          <GlassCard
            title="Embeddings map (PCA)"
            icon={<BubbleChartOutlined />}
            right={
              <Chip
                size="small"
                label={`PC1 ${(pca.explained_variance?.[0] ?? 0).toFixed(2)} • PC2 ${(pca.explained_variance?.[1] ?? 0).toFixed(2)}`}
                variant="outlined"
              />
            }
          >
            <Grid container spacing={1.25} sx={{ mb: 0.75 }}>
              <Grid item xs={12}>
                <Stack direction="row" spacing={0.75} sx={{ flexWrap: "wrap" }}>
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
              </Grid>
            </Grid>

            <Box sx={{ height: 340 }}>
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
                  <XAxis type="number" dataKey="x" name="PC1" tick={{ fontSize: 11 }} />
                  <YAxis type="number" dataKey="y" name="PC2" tick={{ fontSize: 11 }} />
                  <ZAxis type="number" range={[18]} />
                  <Tooltip
                    content={<PcaTooltip />}
                    cursor={{ stroke: "#94A3B8", strokeDasharray: "4 4" }}
                  />

                  {campaignRects.map((r) => (
                    <ReferenceArea
                      key={r.id}
                      x1={r.x1}
                      x2={r.x2}
                      y1={r.y1}
                      y2={r.y2}
                      ifOverflow="extendDomain"
                      stroke="#94A3B8"
                      strokeOpacity={0.45}
                      fill="#94A3B8"
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
          </GlassCard>
        </Grid>

        <Grid item xs={12}>
          <GlassCard title="Mail volume (last 15 days)" icon={<TimelineOutlined />}>
            <Box sx={{ height: 300 }}>
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={chartData}>
                  <defs>
                    <linearGradient id="blueArea" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                    </linearGradient>

                    <linearGradient id="redArea" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#EF4444" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>

                  <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
                  <XAxis dataKey="label" tick={{ fontSize: 11 }} />
                  <YAxis tick={{ fontSize: 11 }} />
                  <Tooltip
                    content={<VolumeTooltip />}
                    cursor={{
                      stroke: "#94A3B8",
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
                      fillOpacity={0.1}
                    />
                  ))}

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

            {campaignBands.length ? (
              <Stack direction="row" spacing={0.75} sx={{ mt: 1, flexWrap: "wrap" }}>
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
                  <Chip
                    size="small"
                    label={`+${campaignBands.length - 6} more`}
                    variant="outlined"
                  />
                ) : null}
              </Stack>
            ) : (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1, fontSize: 13 }}>
                No campaign ranges returned.
              </Typography>
            )}
          </GlassCard>
        </Grid>
      </Grid>
    </Box>
  );
}