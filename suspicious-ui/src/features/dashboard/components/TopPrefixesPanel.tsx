import * as React from "react";
import { api } from "@/api/client";
import {
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Stack,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";
import {
  SellOutlined,
  WorkspacePremiumRounded,
  MilitaryTechRounded,
  EmojiEventsRounded,
} from "@mui/icons-material";

type TopPrefixesType = "user" | "group";

const CATEGORY_CONFIG = [
  { key: "safe", label: "Safe", color: "#22c55e" },
  { key: "suspicious", label: "Suspicious", color: "#facc15" },
  { key: "dangerous", label: "Dangerous", color: "#ef4444" },
  { key: "failure", label: "Failure", color: "#64748b" },
  { key: "inconclusive", label: "Inconclusive", color: "#8b5cf6" },
] as const;

type CategoryKey = (typeof CATEGORY_CONFIG)[number]["key"];

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

function compactLabel(text: string, max = 14) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

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

function GlassCard(props: React.PropsWithChildren<{
  title: string;
  icon?: React.ReactNode;
  right?: React.ReactNode;
}>) {
  return (
    <Card
      sx={{
        height: "100%",
        borderRadius: 3,
        border: "1px solid rgba(255,255,255,.10)",
        background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
      }}
    >
      <CardContent
        sx={{
          height: "100%",
          p: { xs: 1.5, md: 2 },
          display: "flex",
          flexDirection: "column",
          minHeight: 0,
        }}
      >
        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1, flexShrink: 0 }}>
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

        <Divider sx={{ opacity: 0.25, mb: 1.5, flexShrink: 0 }} />
        <Box sx={{ flex: 1, minHeight: 0, overflow: "auto" }}>
          {props.children}
        </Box>
      </CardContent>
    </Card>
  );
}

export default function TopPrefixesPanel({
  month,
  year,
  limit = 5,
}: TopPrefixesPanelProps) {
  const [type, setType] = React.useState<TopPrefixesType>("user");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [rows, setRows] = React.useState<TopPrefixApiItem[]>([]);

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

    return () => {
      active = false;
    };
  }, [type, month, year, limit]);

  const chartData = rows.map((item, index) => ({
    prefix: item.prefix,
    shortLabel: `${index + 1}. ${compactLabel(item.prefix)}`,

    safe: item.safe,
    suspicious: item.suspicious,
    dangerous: item.dangerous,
    failure: item.failure,
    inconclusive: item.inconclusive,
  }));

  return (
    <GlassCard
      title={`Top ${limit} Reporters`}
      icon={<SellOutlined />}
      right={
        <Stack direction="row" spacing={1} alignItems="center">
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
    >
      <Box sx={{ height: "100%", minHeight: 0, overflow: "auto" }}>
        {loading ? (
          <Stack sx={{ height: "100%" }} alignItems="center" justifyContent="center">
            <CircularProgress size={24} />
          </Stack>
        ) : error ? (
          <Stack sx={{ height: "100%" }} alignItems="center" justifyContent="center">
            <Typography color="error" variant="body2">
              {error}
            </Typography>
          </Stack>
        ) : chartData.length === 0 ? (
          <Stack sx={{ height: "100%" }} alignItems="center" justifyContent="center">
            <Typography color="text.secondary" variant="body2">
              No prefixes for this period
            </Typography>
          </Stack>
        ) : (
        <>

          <Stack spacing={1.25}>
            {rows.map((item, index) => {
              const total = item.total || 0;

              return (
                <Box
                  key={item.prefix}
                  sx={{
                    borderRadius: 2.5,
                    px: 1.25,
                    py: 1,
                    border: "1px solid rgba(255,255,255,0.08)",
                    background:
                      index === 0
                        ? "linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03))"
                        : "rgba(255,255,255,0.02)",
                  }}
                >
                  <Stack
                    direction="row"
                    alignItems="center"
                    justifyContent="space-between"
                    spacing={2}
                    sx={{ mb: 0.75 }}
                  >
                    <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
                      {(() => {
                        const badge = getRankBadge(index);

                        return (
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
                              border: "1px solid rgba(255,255,255,0.10)",
                              flexShrink: 0,
                            }}
                          >
                            {badge.icon}
                          </Box>
                        );
                      })()}

                      <Typography
                        variant="body2"
                        sx={{
                          fontWeight: index === 0 ? 900 : index < 3 ? 800 : 700,
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          maxWidth: { xs: 140, md: 220 },
                        }}
                      >
                        {item.prefix}
                      </Typography>
                    </Stack>

                    <Chip
                      size="small"
                      label={total.toLocaleString()}
                      sx={{
                        fontWeight: 800,
                        bgcolor: index === 0 ? "rgba(56,189,248,.16)" : "rgba(148,163,184,.12)",
                        border: "1px solid rgba(255,255,255,.08)",
                      }}
                    />
                  </Stack>

                  <Box
                    sx={{
                      height: 16,
                      borderRadius: 999,
                      overflow: "hidden",
                      display: "flex",
                      bgcolor: "rgba(148,163,184,0.10)",
                      boxShadow: "inset 0 0 0 1px rgba(255,255,255,0.04)",
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
                            boxShadow:
                              index === 0 ? `inset 0 0 0 1px ${category.color}` : "none",
                          }}
                        />
                      );
                    })}
                  </Box>

                  <Stack
                    direction="row"
                    spacing={1.5}
                    useFlexGap
                    flexWrap="wrap"
                    sx={{ mt: 0.75 }}
                  >
                    {CATEGORY_CONFIG.map((category) => {
                      const value = item[category.key] as number;
                      const pct = total > 0 ? Math.round((value / total) * 100) : 0;

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
        </>
        )}
      </Box>
    </GlassCard>
  );
}