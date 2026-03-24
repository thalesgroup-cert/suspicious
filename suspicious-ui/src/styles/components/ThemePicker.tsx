// src/styles/components/ThemePicker.tsx
import * as React from "react";
import {
  Box,
  Chip,
  Divider,
  Stack,
  Typography,
  useTheme,
} from "@mui/material";
import { alpha } from "@mui/material/styles";
import { CheckOutlined, AutoModeOutlined } from "@mui/icons-material";
import { themes, type ThemeName, getSeasonalThemeName } from "@/styles/themes";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Props = {
  value: ThemeName;
  onChange: (t: ThemeName) => void;
};

type ThemeMeta = {
  label: string;
  description: string;
  group: "Core" | "Seasonal" | "Classic" | "Special";
  emoji?: string;
};

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

const ORDER: ThemeName[] = [
  "midnight",
  "graphite",
  "slate",
  "light",
  "paper",
  "high_contrast",
  "sunrise",
  "valentine",
  "cyber",
  "the_one",
  "metal",
  "winter",
  "spring",
  "summer",
  "autumn",
  "future"
];

const META: Partial<Record<ThemeName, ThemeMeta>> = {
  graphite:      { label: "Graphite",      description: "Neutral dark. Best for long sessions.",         group: "Core",    emoji: "⬛" },
  midnight:      { label: "Midnight",      description: "Deep navy. Calm, blue-forward.",                group: "Core",    emoji: "🌙" },
  slate:         { label: "Slate",         description: "Dark with refined surface separation.",         group: "Core",    emoji: "🪨" },
  light:         { label: "Light",         description: "Clean professional light theme.",               group: "Core",    emoji: "☀️" },
  paper:         { label: "Paper",         description: "Warm light theme for reviews and audit work.",  group: "Core",    emoji: "📄" },
  high_contrast: { label: "High contrast", description: "Accessibility-oriented dark theme.",            group: "Core",    emoji: "🔳" },
  the_one:       { label: "The One",       description: "A new Theme ? Who decided that ?",        group: "Classic", emoji: "👆" },
  sunrise:       { label: "Sunrise",       description: "Peach + coral. Warm, bright, friendly.",        group: "Classic", emoji: "🌅" },
  valentine:     { label: "Valentine",     description: "Pink + berry. Soft and bold accents.",          group: "Classic", emoji: "💜" },
  cyber:         { label: "Cyber",         description: "Neon cyan/green on deep black.",                group: "Classic", emoji: "💻" },
  metal:         { label: "Metal",         description: "A Metal...Theme ? A 'solid' option...",       group: "Special", emoji: "📦" },
  winter:        { label: "Winter",        description: "Deep navy with icy highlights.",                group: "Seasonal", emoji: "❄️" },
  spring:        { label: "Spring",        description: "Fresh green with lilac accents.",               group: "Seasonal", emoji: "🌸" },
  summer:        { label: "Summer",        description: "Bright sky blue with sun amber.",               group: "Seasonal", emoji: "🌞" },
  autumn:        { label: "Autumn",        description: "Terracotta warmth with olive depth.",           group: "Seasonal", emoji: "🍂" },
  future:        { label: "Future",        description: "What the f..bzt ? A Visiteur du Futur theme...",   group: "Special", emoji: "🦊" },

};

const GROUP_ORDER = ["Core", "Classic", "Seasonal", "Special"] as const;
type GroupName = (typeof GROUP_ORDER)[number];

const GROUP_DESCRIPTIONS: Record<GroupName, string> = {
  Core:     "Everyday themes designed for long triage sessions.",
  Classic:  "Character-forward themes with distinctive personalities.",
  Seasonal: "Automatically applied based on the time of year.",
  Special:  "High-impact, purpose-built visual modes.",
};

function titleCase(key: string) {
  return key.replace(/_/g, " ").replace(/\b\w/g, (s) => s.toUpperCase());
}


function Swatch({ name, selected }: { name: ThemeName; selected: boolean }) {
  const t = themes[name];
  const p = t.palette;

  const bg        = p.background.default;
  const paper     = p.background.paper;
  const primary   = p.primary.main;
  const secondary = (p as any).secondary?.main ?? primary;
  const error     = p.error?.main ?? "#EF4444";
  const warning   = p.warning?.main ?? "#F59E0B";
  const success   = p.success?.main ?? "#22C55E";
  const info      = p.info?.main ?? primary;
  const textPri   = p.text.primary;
  const textSec   = p.text.secondary;
  const isDark    = p.mode === "dark";

  // Border between the two halves
  const splitBorder = isDark
    ? `1px solid ${alpha("#fff", 0.07)}`
    : `1px solid ${alpha("#000", 0.06)}`;

  return (
    <Box
      sx={{
        height: 72,
        borderRadius: "10px 10px 0 0",
        overflow: "hidden",
        position: "relative",
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gridTemplateRows: "1fr auto",
      }}
    >
      {/* ── Top-left: background ─────────────────────────────── */}
      <Box
        sx={{
          bgcolor: bg,
          position: "relative",
          borderRight: splitBorder,
          borderBottom: splitBorder,
          display: "flex",
          alignItems: "flex-end",
          pb: "6px",
          pl: "7px",
          gap: "4px",
        }}
      >
        {/* Fake nav dots */}
        {[alpha(textPri, 0.18), primary, secondary].map((c, i) => (
          <Box key={i} sx={{ width: 6, height: 6, borderRadius: 99, bgcolor: c }} />
        ))}
        {/* Faint scan-line hint for dark themes that use it */}
        {isDark && (
          <Box
            sx={{
              position: "absolute",
              inset: 0,
              background:
                "repeating-linear-gradient(0deg, rgba(255,255,255,.025), rgba(255,255,255,.025) 1px, transparent 1px, transparent 4px)",
              pointerEvents: "none",
            }}
          />
        )}
      </Box>

      {/* ── Top-right: paper surface ─────────────────────────── */}
      <Box
        sx={{
          bgcolor: paper,
          position: "relative",
          borderBottom: splitBorder,
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-end",
          justifyContent: "space-between",
          pr: "8px",
          pt: "8px",
          pb: "6px",
        }}
      >
        {/* Primary glow dot */}
        <Box
          sx={{
            width: 11,
            height: 11,
            borderRadius: 99,
            bgcolor: primary,
            boxShadow: `0 0 8px ${alpha(primary, isDark ? 0.7 : 0.45)}`,
          }}
        />
        {/* Info/secondary dot */}
        <Box
          sx={{
            width: 7,
            height: 7,
            borderRadius: 99,
            bgcolor: alpha(info, 0.65),
          }}
        />
      </Box>

      {/* ── Bottom-left: primary bar ─────────────────────────── */}
      <Box
        sx={{
          bgcolor: bg,
          borderRight: splitBorder,
          display: "flex",
          alignItems: "center",
          px: "7px",
          py: "5px",
          gap: "3px",
        }}
      >
        {/* Primary bar */}
        <Box
          sx={{
            flex: 1,
            height: 5,
            borderRadius: 99,
            bgcolor: primary,
            boxShadow: `0 0 6px ${alpha(primary, isDark ? 0.5 : 0.3)}`,
          }}
        />
        {/* Faint text line */}
        <Box sx={{ width: "28%", height: 3, borderRadius: 99, bgcolor: alpha(textSec, 0.3) }} />
      </Box>

      {/* ── Bottom-right: semantic accent strip ──────────────── */}
      <Box
        sx={{
          bgcolor: paper,
          display: "flex",
          alignItems: "center",
          justifyContent: "flex-end",
          px: "7px",
          py: "5px",
          gap: "3px",
        }}
      >
        {[success, warning, error].map((c, i) => (
          <Box
            key={i}
            sx={{
              width: 5,
              height: 5,
              borderRadius: 99,
              bgcolor: c,
              opacity: 0.85,
            }}
          />
        ))}
      </Box>

      {/* ── Selected overlay ─────────────────────────────────── */}
      {selected ? (
        <Box
          sx={{
            position: "absolute",
            inset: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: alpha(primary, 0.2),
            backdropFilter: "blur(1.5px)",
            zIndex: 2,
          }}
        >
          <Box
            sx={{
              width: 26,
              height: 26,
              borderRadius: 99,
              bgcolor: primary,
              display: "grid",
              placeItems: "center",
              boxShadow: `0 2px 14px ${alpha(primary, isDark ? 0.6 : 0.45)}`,
            }}
          >
            <CheckOutlined sx={{ fontSize: 15, color: isDark ? "#000" : "#fff" }} />
          </Box>
        </Box>
      ) : null}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// ThemeCard
// ---------------------------------------------------------------------------

function ThemeCard({
  name,
  selected,
  isSeasonPick,
  onClick,
}: {
  name: ThemeName;
  selected: boolean;
  isSeasonPick: boolean;
  onClick: () => void;
}) {
  const hostTheme = useTheme();
  const isDarkHost = hostTheme.palette.mode === "dark";
  const meta = META[name];
  const t = themes[name];
  const primary = t.palette.primary.main;

  return (
    <Box
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick(); }
      }}
      sx={{
        cursor: "pointer",
        borderRadius: 2.5,
        border: `1.5px solid ${
          selected
            ? alpha(primary, isDarkHost ? 0.7 : 0.65)
            : alpha(hostTheme.palette.divider, isDarkHost ? 0.22 : 0.65)
        }`,
        overflow: "hidden",
        outline: "none",
        transition: "all .16s ease",
        background: selected
          ? alpha(primary, isDarkHost ? 0.06 : 0.04)
          : isDarkHost ? alpha("#fff", 0.015) : alpha(hostTheme.palette.background.paper, 0.7),
        boxShadow: selected
          ? `0 0 0 3px ${alpha(primary, 0.15)}, 0 4px 16px ${alpha(primary, 0.12)}`
          : isDarkHost
          ? "0 2px 8px rgba(0,0,0,.22)"
          : "0 2px 6px rgba(15,23,42,.06)",
        "&:hover": {
          borderColor: selected
            ? alpha(primary, 0.82)
            : alpha(hostTheme.palette.primary.main, isDarkHost ? 0.4 : 0.42),
          boxShadow: selected
            ? `0 0 0 3px ${alpha(primary, 0.2)}, 0 6px 20px ${alpha(primary, 0.16)}`
            : isDarkHost
            ? "0 4px 14px rgba(0,0,0,.35)"
            : "0 4px 12px rgba(15,23,42,.10)",
          transform: "translateY(-1px)",
        },
        "&:focus-visible": {
          boxShadow: `0 0 0 3px ${alpha(hostTheme.palette.primary.main, 0.45)}`,
        },
      }}
    >
      {/* Swatch */}
      <Swatch name={name} selected={selected} />

      {/* Card body */}
      <Box
        sx={{
          px: 1.5,
          pt: 1.1,
          pb: 1.4,
          borderTop: `1px solid ${
            selected
              ? alpha(primary, isDarkHost ? 0.25 : 0.2)
              : alpha(hostTheme.palette.divider, isDarkHost ? 0.1 : 0.4)
          }`,
        }}
      >
        <Stack direction="row" spacing={0.6} alignItems="center" sx={{ mb: 0.35 }}>
          {meta?.emoji ? (
            <Typography sx={{ fontSize: 11, lineHeight: 1 }}>{meta.emoji}</Typography>
          ) : null}

          <Typography
            sx={{
              fontWeight: selected ? 950 : 800,
              fontSize: 13,
              lineHeight: 1.15,
              color: selected ? primary : "text.primary",
              transition: "color .15s",
              flex: 1,
              minWidth: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {meta?.label ?? titleCase(name)}
          </Typography>

          {isSeasonPick ? (
            <Chip
              size="small"
              icon={<AutoModeOutlined sx={{ fontSize: "10px !important" }} />}
              label="Now"
              sx={{
                height: 17,
                bgcolor: alpha("#A78BFA", isDarkHost ? 0.18 : 0.12),
                color: "#A78BFA",
                border: `1px solid ${alpha("#A78BFA", 0.3)}`,
                fontWeight: 800,
                "& .MuiChip-label": { px: 0.6, fontSize: 10 },
              }}
            />
          ) : null}
        </Stack>

        <Typography
          variant="body2"
          color="text.secondary"
          sx={{
            fontSize: 11,
            lineHeight: 1.4,
            display: "-webkit-box",
            WebkitLineClamp: 2,
            WebkitBoxOrient: "vertical",
            overflow: "hidden",
          }}
        >
          {meta?.description ?? "Theme preset."}
        </Typography>

        {/* Mini palette strip — real colors from the theme */}
        <Stack direction="row" spacing={0.4} sx={{ mt: 1 }}>
          {[
            t.palette.primary.main,
            (t.palette as any).secondary?.main,
            t.palette.info?.main,
            t.palette.success?.main,
            t.palette.warning?.main,
            t.palette.error?.main,
          ]
            .filter(Boolean)
            .slice(0, 6)
            .map((color, i) => (
              <Box
                key={i}
                sx={{
                  flex: 1,
                  height: 4,
                  borderRadius: 99,
                  bgcolor: color,
                  opacity: selected ? 0.9 : 0.65,
                  transition: "opacity .15s",
                }}
              />
            ))}
        </Stack>
      </Box>
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Group header
// ---------------------------------------------------------------------------

function GroupHeader({ title, description }: { title: string; description: string }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Stack spacing={0.25} sx={{ mt: 0.75 }}>
      <Stack direction="row" alignItems="center" spacing={1.25}>
        <Typography
          sx={{
            fontWeight: 950,
            fontSize: 11,
            letterSpacing: 0.8,
            textTransform: "uppercase",
            color: "text.secondary",
            whiteSpace: "nowrap",
          }}
        >
          {title}
        </Typography>
        <Divider sx={{ flex: 1, opacity: isDark ? 0.2 : 0.5 }} />
      </Stack>
      <Typography
        variant="caption"
        color="text.disabled"
        sx={{ fontSize: 11.5, pl: 0.25 }}
      >
        {description}
      </Typography>
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// ThemePicker
// ---------------------------------------------------------------------------

export function ThemePicker({ value, onChange }: Props) {
  const seasonal = React.useMemo(() => getSeasonalThemeName(new Date()), []);

  const grouped = React.useMemo(() => {
    const keys = new Set(Object.keys(themes) as ThemeName[]);
    const ordered = ORDER.filter((k) => keys.has(k));
    const rest = (Array.from(keys) as ThemeName[]).filter((k) => !ordered.includes(k));
    const all = [...ordered, ...rest];

    const result: Partial<Record<GroupName, ThemeName[]>> = {};
    for (const g of GROUP_ORDER) result[g] = [];
    for (const n of all) {
      const g = (META[n]?.group ?? "Special") as GroupName;
      result[g]!.push(n);
    }
    return result;
  }, []);

  return (
    <Stack spacing={2}>
      {GROUP_ORDER.map((group) => {
        const names = grouped[group];
        if (!names?.length) return null;

        return (
          <Stack key={group} spacing={1.25}>
            <GroupHeader title={group} description={GROUP_DESCRIPTIONS[group]} />

            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: {
                  xs: "1fr",
                  sm: "repeat(2, 1fr)",
                  md: "repeat(3, 1fr)",
                },
                gap: 1.25,
              }}
            >
              {names.map((name) => (
                <ThemeCard
                  key={name}
                  name={name}
                  selected={value === name}
                  isSeasonPick={name === seasonal}
                  onClick={() => onChange(name)}
                />
              ))}
            </Box>
          </Stack>
        );
      })}
    </Stack>
  );
}