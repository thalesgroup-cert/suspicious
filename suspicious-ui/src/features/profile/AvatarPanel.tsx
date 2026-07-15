import * as React from "react";
import { Box, Button, Divider, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { PersonOutlined, CasinoOutlined } from "@mui/icons-material";
import { CaptionLabel, InnerCard } from "@/features/profile/components/cards";
import { UserAvatar } from "@/features/profile/components/UserAvatar";
import { ColorField } from "@/features/profile/components/ColorField";
import { EnumField } from "@/features/profile/components/EnumField";
import {
  AVATAR_STYLES,
  getStyleCategories,
  randomPaletteValue,
  randomSeed,
  renderAvatarDataUri,
  type AvatarConfig,
} from "@/features/profile/avatar";
import { initials as initialsFn } from "@/features/profile/utils";

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
  const inits = initialsFn(firstName, lastName);
  const isInitials = style === "initials";
  const effectiveSeed = isInitials ? inits : seed;
  const config: AvatarConfig = { style, seed: effectiveSeed, options };

  const categories = getStyleCategories(style);
  const styleOptionCats = categories.filter((c) => c.kind === "enum");
  const colorCats = categories.filter((c) => c.kind === "color" && c.key !== "backgroundColor");
  const backgroundCat = categories.find((c) => c.kind === "color" && c.key === "backgroundColor");

  const lockValue = (key: string, value: string) => setOptions({ ...options, [key]: [value] });
  const clearValue = (key: string) => {
    const rest = { ...options };
    delete rest[key];
    setOptions(rest);
  };

  const handleRandomize = () => {
    if (isInitials) {
      const next = { ...options };
      for (const cat of [...colorCats, ...(backgroundCat ? [backgroundCat] : [])]) {
        next[cat.key] = [randomPaletteValue(style, cat.key) ?? cat.values[0]];
      }
      setOptions(next);
    } else {
      setSeed(randomSeed());
    }
  };

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
            Build your avatar — pick a style, then dial in every color and detail.
          </Typography>
        </Box>
      </Stack>

      <Divider sx={{ opacity: 0.25 }} />

      <Stack direction={{ xs: "column", md: "row" }} spacing={2.5} sx={{ alignItems: "flex-start" }}>
        <Stack
          spacing={1.5}
          sx={{
            flex: { md: "0 0 220px" },
            width: { xs: "100%", md: 220 },
            position: { md: "sticky" },
            top: { md: 16 },
          }}
        >
          <InnerCard sx={{ p: 2.5, display: "flex", flexDirection: "column", alignItems: "center", gap: 1.25 }}>
            <UserAvatar avatar={config} initials={inits} sx={{ width: 96, height: 96, fontSize: 34, fontWeight: 950 }} />
            <Typography sx={{ fontWeight: 900, fontSize: 14, textAlign: "center" }}>
              {AVATAR_STYLES.find((s) => s.key === style)?.label ?? "Initials"}
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ textAlign: "center" }}>
              {isInitials ? "Always your initials" : `seed: ${seed || "—"}`}
            </Typography>
            <Button
              fullWidth size="small" variant="outlined" startIcon={<CasinoOutlined />}
              onClick={handleRandomize}
              sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2 }}
            >
              Randomize
            </Button>
          </InnerCard>
          {dirtyBar}
        </Stack>

        <Stack spacing={2.5} sx={{ flex: 1, minWidth: 0, width: "100%" }}>
          <Stack spacing={1}>
            <CaptionLabel>Style</CaptionLabel>
            <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(84px, 1fr))", gap: 1 }}>
              {AVATAR_STYLES.map((s) => {
                const selected = s.key === style;
                const preview = renderAvatarDataUri({
                  style: s.key,
                  seed: s.key === "initials" ? inits : (seed || "preview"),
                });
                return (
                  <Box
                    key={s.key}
                    role="button"
                    tabIndex={0}
                    onClick={() => setStyle(s.key)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setStyle(s.key);
                      }
                    }}
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

          {styleOptionCats.length > 0 && (
            <Stack spacing={1}>
              <CaptionLabel>Style options</CaptionLabel>
              <Stack spacing={1}>
                {styleOptionCats.map((cat) => (
                  <EnumField
                    key={cat.key}
                    label={cat.label}
                    values={cat.values}
                    value={options[cat.key]?.[0]}
                    onChange={(v) => lockValue(cat.key, v)}
                    onReset={() => clearValue(cat.key)}
                    renderThumb={(v) =>
                      renderAvatarDataUri({ style, seed: effectiveSeed, options: { ...options, [cat.key]: [v] } })
                    }
                  />
                ))}
              </Stack>
            </Stack>
          )}

          {colorCats.length > 0 && (
            <Stack spacing={1}>
              <CaptionLabel>Colors</CaptionLabel>
              <Stack spacing={1.5}>
                {colorCats.map((cat) => (
                  <ColorField
                    key={cat.key}
                    label={cat.label}
                    palette={cat.values}
                    value={options[cat.key]?.[0]}
                    onChange={(hex) => lockValue(cat.key, hex)}
                    onReset={() => clearValue(cat.key)}
                  />
                ))}
              </Stack>
            </Stack>
          )}

          {backgroundCat && (
            <Stack spacing={1}>
              <CaptionLabel>Background</CaptionLabel>
              <ColorField
                label={backgroundCat.label}
                palette={backgroundCat.values}
                value={options[backgroundCat.key]?.[0]}
                onChange={(hex) => lockValue(backgroundCat.key, hex)}
                onReset={() => clearValue(backgroundCat.key)}
              />
            </Stack>
          )}
        </Stack>
      </Stack>
    </Stack>
  );
}
