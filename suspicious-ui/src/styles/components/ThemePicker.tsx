// src/components/ThemePicker.tsx
import * as React from "react";
import { Box, Card, CardActionArea, Chip, Divider, Stack, Typography, useTheme } from "@mui/material";
import { themes, type ThemeName, getSeasonalThemeName } from "@/styles/themes";

type Props = {
  value: ThemeName;
  onChange: (t: ThemeName) => void;
};

type ThemeMeta = {
  label: string;
  description: string;
  group?: "Core" | "Seasonal" | "Classic";
};

const ORDER: ThemeName[] = [
  // Core
  "midnight",
  "graphite",
  "slate",
  "light",
  "paper",
  "highContrast",
  // Classic (old-style inspired)
  "sunrise",
  "valentine",
  "cyber",
  "theOne",
  // Seasonal
  "winter",
  "spring",
  "summer",
  "autumn",
];

const META: Partial<Record<ThemeName, ThemeMeta>> = {
  graphite: { label: "Graphite", description: "Neutral dark. Best for long sessions.", group: "Core" },
  midnight: { label: "Midnight", description: "Deep navy. Calm, blue-forward.", group: "Core" },
  slate: { label: "Slate", description: "Dark with a bit more separation.", group: "Core" },
  light: { label: "Light", description: "Clean professional light theme.", group: "Core" },
  paper: { label: "Paper", description: "Warm light theme for reviews and audit work.", group: "Core" },
  highContrast: { label: "High contrast", description: "Accessibility-oriented dark theme.", group: "Core" },

  sunrise: { label: "Sunrise", description: "Peach + coral. Warm, bright, friendly.", group: "Classic" },
  valentine: { label: "Valentine", description: "Pink + berry. Soft and bold accents.", group: "Classic" },
  cyber: { label: "Cyber", description: "Neon cyan/green on deep black.", group: "Classic" },
  theOne: { label: "The One", description: "Ivory + gold + charcoal. Premium feel.", group: "Classic" },
  metal: {
    label: "Metal",
    description: "Stealth HUD: CRT scanlines, alert red, terminal edges.",
  },

  winter: { label: "Winter", description: "Deep navy with icy highlights.", group: "Seasonal" },
  spring: { label: "Spring", description: "Fresh green with lilac accents.", group: "Seasonal" },
  summer: { label: "Summer", description: "Bright sky blue with sun amber.", group: "Seasonal" },
  autumn: { label: "Autumn", description: "Terracotta warmth with olive depth.", group: "Seasonal" },
};

function titleCase(key: string) {
  return key.replace(/([A-Z])/g, " $1").replace(/^./, (s) => s.toUpperCase());
}

function Swatch({ name }: { name: ThemeName }) {
  const t = themes[name];
  const bg = t.palette.background.default;
  const paper = t.palette.background.paper;
  const primary = t.palette.primary.main;
  const border = t.palette.mode === "dark" ? "rgba(229,231,235,.14)" : "rgba(11,18,32,.12)";

  return (
    <Box
      sx={{
        height: 44,
        borderRadius: 2,
        border: `1px solid ${border}`,
        overflow: "hidden",
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
      }}
    >
      <Box sx={{ bgcolor: bg }} />
      <Box sx={{ bgcolor: paper, position: "relative" }}>
        <Box
          sx={{
            position: "absolute",
            right: 8,
            top: 8,
            width: 10,
            height: 10,
            borderRadius: 999,
            bgcolor: primary,
          }}
        />
      </Box>
    </Box>
  );
}

function SectionHeader({ title }: { title: string }) {
  return (
    <Stack direction="row" alignItems="center" spacing={1} sx={{ mt: 0.5 }}>
      <Typography variant="subtitle2" color="text.secondary" sx={{ fontWeight: 750 }}>
        {title}
      </Typography>
      <Divider sx={{ flex: 1, opacity: 0.35 }} />
    </Stack>
  );
}

export function ThemePicker({ value, onChange }: Props) {
  const theme = useTheme();
  const seasonal = React.useMemo(() => getSeasonalThemeName(new Date()), []);

  // only keep keys that exist in themes (prevents stale names)
  const themeNames = React.useMemo(() => {
    const keys = new Set(Object.keys(themes) as ThemeName[]);
    const ordered = ORDER.filter((k) => keys.has(k));
    const rest = (Array.from(keys) as ThemeName[]).filter((k) => !ordered.includes(k));
    return [...ordered, ...rest];
  }, []);

  const grouped = React.useMemo(() => {
    const core: ThemeName[] = [];
    const classic: ThemeName[] = [];
    const seasonalList: ThemeName[] = [];
    const other: ThemeName[] = [];

    for (const n of themeNames) {
      const g = META[n]?.group;
      if (g === "Core") core.push(n);
      else if (g === "Classic") classic.push(n);
      else if (g === "Seasonal") seasonalList.push(n);
      else other.push(n);
    }
    return { core, classic, seasonal: seasonalList, other };
  }, [themeNames]);

  function CardItem({ name }: { name: ThemeName }) {
    const selected = name === value;
    const meta = META[name];
    const isSeasonPick = name === seasonal;

    return (
      <Card
        key={name}
        variant="outlined"
        sx={{
          borderRadius: 3,
          borderColor: selected ? theme.palette.primary.main : undefined,
          backgroundColor: selected
            ? theme.palette.mode === "dark"
              ? "rgba(255,255,255,.03)"
              : "rgba(11,18,32,.02)"
            : undefined,
        }}
      >
        <CardActionArea onClick={() => onChange(name)} sx={{ p: 1.25, borderRadius: 3 }}>
          <Stack spacing={1}>
            <Swatch name={name} />

            <Stack spacing={0.25}>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ minHeight: 22 }}>
                <Typography sx={{ fontWeight: 700, lineHeight: 1.1 }}>
                  {meta?.label ?? titleCase(name)}
                </Typography>

                {isSeasonPick ? (
                  <Chip
                    size="small"
                    label="Seasonal"
                    sx={{
                      height: 20,
                      "& .MuiChip-label": { px: 0.75, fontSize: 11.5, fontWeight: 700 },
                    }}
                  />
                ) : null}
              </Stack>

              <Typography variant="body2" color="text.secondary">
                {meta?.description ?? "Theme preset."}
              </Typography>
            </Stack>
          </Stack>
        </CardActionArea>
      </Card>
    );
  }

  const Grid: React.FC<React.PropsWithChildren> = ({ children }) => (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" },
        gap: 1.25,
      }}
    >
      {children}
    </Box>
  );

  return (
    <Stack spacing={1.25}>
      <Typography variant="subtitle2" color="text.secondary">
        Theme
      </Typography>

      {grouped.core.length ? (
        <>
          <SectionHeader title="Core" />
          <Grid>{grouped.core.map((n) => <CardItem key={n} name={n} />)}</Grid>
        </>
      ) : null}

      {grouped.classic.length ? (
        <>
          <SectionHeader title="Classic" />
          <Grid>{grouped.classic.map((n) => <CardItem key={n} name={n} />)}</Grid>
        </>
      ) : null}

      {grouped.seasonal.length ? (
        <>
          <SectionHeader title="Seasonal" />
          <Grid>{grouped.seasonal.map((n) => <CardItem key={n} name={n} />)}</Grid>
        </>
      ) : null}

      {grouped.other.length ? (
        <>
          <SectionHeader title="Other" />
          <Grid>{grouped.other.map((n) => <CardItem key={n} name={n} />)}</Grid>
        </>
      ) : null}
    </Stack>
  );
}
