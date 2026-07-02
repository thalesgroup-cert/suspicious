import * as React from "react";
import { Box, Button, Divider, IconButton, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  PersonOutlined,
  CasinoOutlined,
  ChevronLeft,
  ChevronRight,
  RestartAltOutlined,
} from "@mui/icons-material";
import { CaptionLabel, InnerCard } from "@/features/profile/components/cards";
import { UserAvatar } from "@/features/profile/components/UserAvatar";
import {
  AVATAR_STYLES,
  getStyleCategories,
  renderAvatarDataUri,
  type AvatarConfig,
} from "@/features/profile/avatar";
import { initials as initialsFn } from "@/features/profile/utils";

// DirtyBar lives in ProfilePage; the panel is controlled and the parent renders it.
export function AvatarPanel({
  style, seed, setStyle, setSeed,
  options, setOptions,
  firstName, lastName,
  dirtyBar,
}: {
  style: string; seed: string;
  setStyle: (s: string) => void; setSeed: (s: string) => void;
  options: Record<string, string[]>;
  setOptions: (o: Record<string, string[]>) => void;
  firstName?: string; lastName?: string;
  dirtyBar: React.ReactNode;
}) {
  const theme = useTheme();
  const config: AvatarConfig = { style, seed, options };
  const inits = initialsFn(firstName, lastName);
  const categories = getStyleCategories(style);

  return (
    <Stack spacing={2.5}>
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
        <Box sx={{
          width: 46, height: 46, borderRadius: 3, display: "grid", placeItems: "center",
          background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
          border: "1px solid rgba(56,189,248,.2)", "& svg": { fontSize: 22 },
        }}>
          <PersonOutlined />
        </Box>
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 950, letterSpacing: -0.2 }}>Avatar</Typography>
          <Typography variant="body2" color="text.secondary">
            Pick a style and randomize until you like it. Preview is instant — save to persist.
          </Typography>
        </Box>
      </Stack>

      <Divider sx={{ opacity: 0.25 }} />

      {dirtyBar}

      {/* Live preview + randomize */}
      <InnerCard sx={{ px: 2, py: 2, display: "flex", alignItems: "center", gap: 2 }}>
        <UserAvatar avatar={config} initials={inits} sx={{ width: 72, height: 72, fontSize: 26, fontWeight: 950 }} />
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography sx={{ fontWeight: 900, fontSize: 14 }}>{AVATAR_STYLES.find((s) => s.key === style)?.label ?? "Initials"}</Typography>
          <Typography variant="caption" color="text.secondary">seed: {seed || "—"}</Typography>
        </Box>
        <Button
          size="small" variant="outlined" startIcon={<CasinoOutlined />}
          onClick={() => setSeed(Math.random().toString(36).slice(2, 12))}
          sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2 }}
        >
          Randomize
        </Button>
      </InnerCard>

      {/* Style grid */}
      <Stack spacing={1}>
        <CaptionLabel>Style</CaptionLabel>
        <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(84px, 1fr))", gap: 1 }}>
          {AVATAR_STYLES.map((s) => {
            const selected = s.key === style;
            const preview = renderAvatarDataUri({ style: s.key, seed: seed || "preview" });
            return (
              <Box
                key={s.key}
                role="button"
                tabIndex={0}
                onClick={() => setStyle(s.key)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setStyle(s.key); }}
                sx={{
                  cursor: "pointer", borderRadius: 2.5, p: 1,
                  display: "flex", flexDirection: "column", alignItems: "center", gap: 0.5,
                  border: `1px solid ${selected ? theme.palette.primary.main : alpha(theme.palette.divider, 0.5)}`,
                  background: selected ? alpha(theme.palette.primary.main, 0.08) : "transparent",
                  transition: "all .15s ease",
                }}
              >
                <Box component="img" src={preview} alt={s.label} sx={{ width: 44, height: 44 }} />
                <Typography variant="caption" sx={{ fontWeight: selected ? 900 : 700, fontSize: 10.5 }}>{s.label}</Typography>
              </Box>
            );
          })}
        </Box>
      </Stack>

      {/* Categories — one carousel per enum option in the style's schema */}
      {categories.length > 0 && (
        <Stack spacing={1}>
          <CaptionLabel>Customize</CaptionLabel>
          <Stack spacing={0.5} sx={{ maxHeight: 320, overflowY: "auto", pr: 0.5 }}>
            {categories.map((cat) => {
              const current = options[cat.key]?.[0];
              const idx = current ? cat.values.indexOf(current) : -1;
              const move = (dir: 1 | -1) => {
                const base = idx < 0 ? (dir === 1 ? -1 : 0) : idx;
                const next = (base + dir + cat.values.length) % cat.values.length;
                setOptions({ ...options, [cat.key]: [cat.values[next]] });
              };
              const clear = () => {
                const rest = { ...options };
                delete rest[cat.key];
                setOptions(rest);
              };
              return (
                <Stack
                  key={cat.key}
                  direction="row"
                  spacing={1}
                  sx={{
                    alignItems: "center",
                    px: 1, py: 0.5, borderRadius: 2,
                    border: `1px solid ${alpha(theme.palette.divider, 0.4)}`,
                  }}
                >
                  <Typography sx={{ flex: 1, minWidth: 0, fontWeight: 800, fontSize: 12.5 }} noWrap>
                    {cat.label}
                  </Typography>
                  <IconButton size="small" aria-label={`${cat.label} previous option`} onClick={() => move(-1)}>
                    <ChevronLeft fontSize="small" />
                  </IconButton>
                  <Typography
                    sx={{ width: 96, textAlign: "center", fontSize: 11.5,
                          color: current ? "text.primary" : "text.disabled",
                          fontWeight: current ? 800 : 600 }}
                    noWrap
                  >
                    {current ?? "Auto"}
                  </Typography>
                  <IconButton size="small" aria-label={`${cat.label} next option`} onClick={() => move(1)}>
                    <ChevronRight fontSize="small" />
                  </IconButton>
                  <IconButton
                    size="small"
                    aria-label={`${cat.label} use random`}
                    onClick={clear}
                    disabled={!current}
                    sx={{ opacity: current ? 1 : 0.35 }}
                  >
                    <RestartAltOutlined fontSize="small" />
                  </IconButton>
                </Stack>
              );
            })}
          </Stack>
        </Stack>
      )}
    </Stack>
  );
}
