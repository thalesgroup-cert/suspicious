// src/features/profile/ColorSettingsPanel.tsx
//
// Appearance settings panel for semantic colors.
// Reads from colorStore (Zustand), persists to backend via React Query.
//
// Sync strategy:
//   • Preset switch       → immediate PATCH /api/profile/colors/
//   • Swatch drag/pick    → optimistic local update + debounced PATCH (800ms)
//   • "Reset" button      → POST /api/profile/colors/reset/
//   • On mount            → hydrateFromProfile() called by ProfilePage
//                           after ["profile"] query resolves

import * as React from "react";
import {
  Box,
  Button,
  Divider,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  RestoreOutlined,
  AccessibilityNewOutlined,
  PaletteOutlined,
  ContrastOutlined,
  CloudDoneOutlined,
} from "@mui/icons-material";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useSnackbar } from "notistack";

import {
  useColorStore,
  useResultColors,
  useStatusColors,
  RESULT_LABELS,
  STATUS_LABELS,
  PRESET_META,
  PRESETS,
  type ResultKey,
  type StatusKey,
  type PresetName,
} from "@/styles/colorStore";
import {
  updateSemanticColors,
  resetSemanticColors,
} from "@/features/profile/api";
import { ResultChip, StatusChip } from "@/features/profile/SemanticChips";

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

function InnerCard(props: React.PropsWithChildren<{ sx?: object }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  return (
    <Box
      sx={{
        borderRadius: 2.5,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.14 : 0.55)}`,
        background: isDark ? alpha("#fff", 0.025) : alpha(theme.palette.background.paper, 0.6),
        ...props.sx,
      }}
    >
      {props.children}
    </Box>
  );
}

function CaptionLabel({ children }: { children: React.ReactNode }) {
  return (
    <Typography
      variant="caption"
      color="text.disabled"
      sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.6, fontSize: 10.5, display: "block" }}
    >
      {children}
    </Typography>
  );
}

// ---------------------------------------------------------------------------
// PresetButton
// ---------------------------------------------------------------------------

const PRESET_ICONS: Record<PresetName, React.ReactNode> = {
  default:    <PaletteOutlined sx={{ fontSize: 16 }} />,
  colorblind: <AccessibilityNewOutlined sx={{ fontSize: 16 }} />,
  mono:       <ContrastOutlined sx={{ fontSize: 16 }} />,
  custom:     <PaletteOutlined sx={{ fontSize: 16 }} />,
};

function PresetButton({ name, active, onClick, loading }: {
  name: PresetName; active: boolean; onClick: () => void; loading?: boolean;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const p = theme.palette.primary.main;

  return (
    <Tooltip title={PRESET_META[name].description} placement="top" arrow>
      <Box
        role="button" tabIndex={0}
        onClick={loading ? undefined : onClick}
        onKeyDown={(e) => { if (!loading && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); onClick(); } }}
        sx={{
          flex: 1, px: 1.5, py: 1.25, borderRadius: 2.5,
          cursor: loading ? "wait" : "pointer", outline: "none",
          display: "flex", alignItems: "center", gap: 0.75,
          opacity: loading ? 0.6 : 1,
          border: `1.5px solid ${active ? alpha(p, isDark ? 0.7 : 0.6) : alpha(theme.palette.divider, isDark ? 0.22 : 0.65)}`,
          background: active ? alpha(p, isDark ? 0.1 : 0.07) : alpha(theme.palette.background.paper, isDark ? 0.03 : 0.6),
          boxShadow: active ? `0 0 0 3px ${alpha(p, 0.12)}` : "none",
          transition: "all .15s ease",
          "&:hover": { borderColor: alpha(p, isDark ? 0.4 : 0.35), background: alpha(p, isDark ? 0.07 : 0.05) },
          "&:focus-visible": { boxShadow: `0 0 0 3px ${alpha(p, 0.4)}` },
        }}
      >
        <Box sx={{ color: active ? p : "text.secondary" }}>{PRESET_ICONS[name]}</Box>
        <Typography sx={{ fontWeight: active ? 900 : 700, fontSize: 12.5, color: active ? p : "text.secondary", whiteSpace: "nowrap" }}>
          {PRESET_META[name].label}
        </Typography>
        {active && <Box sx={{ width: 6, height: 6, borderRadius: 99, bgcolor: p, ml: "auto", flexShrink: 0 }} />}
      </Box>
    </Tooltip>
  );
}

// ---------------------------------------------------------------------------
// ColorSwatch
// ---------------------------------------------------------------------------

function ColorSwatch({ color, label, onChange, saving }: {
  color: string; label: string; onChange: (hex: string) => void; saving?: boolean;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const inputRef = React.useRef<HTMLInputElement>(null);

  return (
    <Tooltip title={`${label} — ${color.toUpperCase()}${saving ? " (saving…)" : ""}`} placement="top" arrow>
      <Box
        onClick={() => inputRef.current?.click()}
        sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 0.75, cursor: "pointer", flex: 1, minWidth: 0, opacity: saving ? 0.65 : 1, transition: "opacity .2s" }}
      >
        <Box
          sx={{
            width: 36, height: 36, borderRadius: 2.5, bgcolor: color,
            border: `2px solid ${alpha(color, isDark ? 0.55 : 0.45)}`,
            boxShadow: `0 0 0 3px ${alpha(color, isDark ? 0.18 : 0.12)}`,
            position: "relative", overflow: "hidden", transition: "all .15s ease",
            "&:hover": { transform: "scale(1.1)", boxShadow: `0 0 0 4px ${alpha(color, 0.28)}` },
          }}
        >
          <Box
            ref={inputRef} component="input" type="color" value={color}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
            sx={{ position: "absolute", inset: 0, opacity: 0, cursor: "pointer", width: "100%", height: "100%", border: "none", padding: 0 }}
            aria-label={`Color picker for ${label}`}
          />
        </Box>
        <Typography variant="caption" sx={{ fontSize: 10.5, fontWeight: 700, textAlign: "center", color: "text.secondary", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", width: "100%", maxWidth: 64 }}>
          {label}
        </Typography>
      </Box>
    </Tooltip>
  );
}

// ---------------------------------------------------------------------------
// ColorGroup
// ---------------------------------------------------------------------------

function ColorGroup<K extends string>({ title, keys, labels, colors, onChange, saving }: {
  title: string; keys: K[]; labels: Record<K, string>;
  colors: Record<K, { main: string }>; onChange: (key: K, hex: string) => void; saving?: boolean;
}) {
  return (
    <Stack spacing={1.25}>
      <CaptionLabel>{title}</CaptionLabel>
      <InnerCard sx={{ px: 2, py: 1.75 }}>
        <Stack direction="row" spacing={1} useFlexGap sx={{ justifyContent: "space-between", flexWrap: "wrap" }}>
          {keys.map((key) => (
            <ColorSwatch key={key} color={colors[key].main} label={labels[key]} onChange={(hex) => onChange(key, hex)} saving={saving} />
          ))}
        </Stack>
      </InnerCard>
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// LivePreview
// ---------------------------------------------------------------------------

function LivePreview() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  return (
    <Stack spacing={1.25}>
      <CaptionLabel>Live preview</CaptionLabel>
      <InnerCard sx={{ px: 2, py: 1.75 }}>
        <Stack spacing={1.5}>
          <Stack>
            <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10.5, fontWeight: 600, mb: 0.75 }}>Analysis results</Typography>
            <Stack direction="row" spacing={0.75} useFlexGap sx={{ flexWrap: "wrap" }} >
              {(["safe", "suspicious", "dangerous", "inconclusive"] as ResultKey[]).map((k) => <ResultChip key={k} value={k} />)}
            </Stack>
          </Stack>
          <Divider sx={{ opacity: isDark ? 0.14 : 0.4 }} />
          <Stack>
            <Typography variant="caption" color="text.disabled" sx={{ fontSize: 10.5, fontWeight: 600, mb: 0.75 }}>Task / submission status</Typography>
            <Stack direction="row" spacing={0.75} useFlexGap sx={{ flexWrap: "wrap" }} >
              {(["done", "in_progress", "new", "failure", "challenged", "unknown"] as StatusKey[]).map((k) => <StatusChip key={k} value={k} />)}
            </Stack>
          </Stack>
        </Stack>
      </InnerCard>
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// ColorSettingsPanel — main export
// ---------------------------------------------------------------------------

export function ColorSettingsPanel() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const { enqueueSnackbar } = useSnackbar();
  const queryClient = useQueryClient();

  const { preset, applyPreset, setResultColor, setStatusColor } = useColorStore();
  const resultColors = useResultColors();
  const statusColors  = useStatusColors();

  const debounceRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const updateMutation = useMutation({
    mutationFn: updateSemanticColors,
    onSuccess: ({ profile }) => { queryClient.setQueryData(["profile"], profile); },
    onError: () => { enqueueSnackbar("Failed to sync colors — stored locally only.", { variant: "warning" }); },
  });

  const resetMutation = useMutation({
    mutationFn: resetSemanticColors,
    onSuccess: ({ profile }) => {
      queryClient.setQueryData(["profile"], profile);
      enqueueSnackbar("Colors reset to defaults.", { variant: "info" });
    },
    onError: () => { enqueueSnackbar("Reset failed.", { variant: "error" }); },
  });

  const isSaving = updateMutation.isPending || resetMutation.isPending;

  function handlePreset(name: Exclude<PresetName, "custom">) {
    applyPreset(name);
    updateMutation.mutate(
      { semantic_colors: PRESETS[name] },
      { onSuccess: () => { enqueueSnackbar(`Applied "${PRESET_META[name].label}" preset.`, { variant: "success" }); } }
    );
  }

  function handleResultColor(key: ResultKey, hex: string) {
    setResultColor(key, hex);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      updateMutation.mutate({ semantic_colors: { result: { [key]: { main: hex } } } });
    }, 800);
  }

  function handleStatusColor(key: StatusKey, hex: string) {
    setStatusColor(key, hex);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      updateMutation.mutate({ semantic_colors: { status: { [key]: { main: hex } } } });
    }, 800);
  }

  function handleReset() {
    useColorStore.getState().reset();
    resetMutation.mutate();
  }

  return (
    <Stack spacing={2.5}>

      {/* Header */}
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }} >
        <Box sx={{ width: 46, height: 46, borderRadius: 3, display: "grid", placeItems: "center", background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))", border: "1px solid rgba(56,189,248,.2)", "& svg": { fontSize: 22 } }}>
          <AccessibilityNewOutlined />
        </Box>
        <Box>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
            <Typography variant="h6" sx={{ fontWeight: 950, letterSpacing: -0.2 }} >Semantic colors</Typography>
            {isSaving ? (
              <Typography variant="caption" color="text.disabled" sx={{ fontSize: 11 }}>Saving…</Typography>
            ) : updateMutation.isSuccess ? (
              <Stack direction="row" spacing={0.4} sx={{ alignItems: "center" }} >
                <CloudDoneOutlined sx={{ fontSize: 13, color: "success.main" }} />
                <Typography variant="caption" sx={{ fontSize: 11, color: "success.main" }}>Synced</Typography>
              </Stack>
            ) : null}
          </Stack>
          <Typography variant="body2" color="text.secondary">
            Customize status and result colors. Changes sync across all your devices.
          </Typography>
        </Box>
      </Stack>

      <Divider sx={{ opacity: 0.25 }} />

      {/* Accessibility banner */}
      <InnerCard sx={{ px: 2, py: 1.25, borderColor: alpha("#56B4E9", isDark ? 0.3 : 0.4), background: alpha("#56B4E9", isDark ? 0.06 : 0.04) }}>
        <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12.5, lineHeight: 1.6 }}>
          <Box component="span" sx={{ fontWeight: 800, color: "#56B4E9" }}>Colorblind-safe</Box>{" "}
          uses the <strong>Okabe-Ito palette</strong> — distinguishable for protanopia, deuteranopia,
          and tritanopia. Color is never the <em>only</em> indicator: every chip also shows a distinct icon.
        </Typography>
      </InnerCard>

      {/* Presets */}
      <Stack spacing={1}>
        <CaptionLabel>Preset</CaptionLabel>
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
          {(["default", "colorblind", "mono"] as const).map((name) => (
            <PresetButton key={name} name={name} active={preset === name} loading={isSaving} onClick={() => handlePreset(name)} />
          ))}
          {preset === "custom" && <PresetButton name="custom" active loading={isSaving} onClick={() => {}} />}
        </Stack>
      </Stack>

      {/* Preview */}
      <LivePreview />

      {/* Color pickers */}
      <ColorGroup
        title="Analysis result colors"
        keys={["safe", "suspicious", "dangerous", "inconclusive"] as ResultKey[]}
        labels={RESULT_LABELS} colors={resultColors}
        onChange={handleResultColor} saving={isSaving}
      />

      <ColorGroup
        title="Task / submission status colors"
        keys={["done", "in_progress", "new", "failure", "challenged", "unknown"] as StatusKey[]}
        labels={STATUS_LABELS} colors={statusColors}
        onChange={handleStatusColor} saving={isSaving}
      />

      {/* Reset */}
      <Stack direction="row" sx={{ justifyContent: "flex-end" }} >
        <Button size="small" startIcon={<RestoreOutlined />} disabled={isSaving} onClick={handleReset}
          sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2, color: "text.secondary" }}>
          {resetMutation.isPending ? "Resetting…" : "Reset to defaults"}
        </Button>
      </Stack>

    </Stack>
  );
}