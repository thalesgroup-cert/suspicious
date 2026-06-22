import * as React from "react";
import {
  Alert,
  Avatar,
  Box,
  Button,
  CardContent,
  CircularProgress,
  Collapse,
  Divider,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  Switch,
  Typography,
  Chip,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  TuneOutlined,
  PaletteOutlined,
  MailOutlined,
  ShieldOutlined,
  AutoModeOutlined,
  CheckCircleOutlined,
  NotificationsOutlined,
  NotificationsActiveOutlined,
  DoneOutlined,
  RestoreOutlined,
  DisplaySettingsOutlined,
  PersonOutlined,
  SaveOutlined,
  CircleOutlined,
  AccessibilityNewOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { useSnackbar } from "notistack";

import { ThemePicker } from "@/styles/components/ThemePicker";
import { getMe, type Me } from "@/api/auth";
import {
  getProfile,
  updateAppearance,
  updatePreferences,
  type UserProfile,
} from "@/features/profile/api";
import { useThemeMode } from "@/styles/ThemeStore";
import type { ThemeName } from "@/styles/themes";
import { useHudModes } from "@/shared/hooks/useHudModes";
import { useColorStore, useResultColors, useStatusColors } from "@/styles/colorStore";
import { ColorSettingsPanel } from "@/features/profile/ColorSettingsPanel";

import {
  CaptionLabel,
  InnerCard,
  NavIcon,
  SoftCard,
} from "@/features/profile/components/cards";
import {
  apiErrorText,
  initials,
  readLocalProfile,
  writeLocalProfile,
} from "@/features/profile/utils";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Section = "preferences" | "appearance" | "colors";

// ---------------------------------------------------------------------------
// ToggleRow
// ---------------------------------------------------------------------------

function ToggleRow({
  icon, title, subtitle, checked, onChange, accentColor,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  accentColor?: string;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const color = accentColor ?? theme.palette.primary.main;

  return (
    <InnerCard sx={{
      px: 2, py: 1.75, display: "flex", alignItems: "center", gap: 2,
      borderColor: checked ? alpha(color, isDark ? 0.35 : 0.4) : undefined,
      background: checked ? alpha(color, isDark ? 0.06 : 0.04) : undefined,
      transition: "all .2s ease",
    }}>
      <Box sx={{
        width: 40, height: 40, borderRadius: 2.5,
        display: "grid", placeItems: "center", flexShrink: 0,
        background: checked ? alpha(color, 0.12) : alpha(theme.palette.action.hover, 0.5),
        border: `1px solid ${checked ? alpha(color, 0.28) : alpha(theme.palette.divider, isDark ? 0.14 : 0.5)}`,
        transition: "all .2s ease",
        "& svg": { fontSize: 20, color: checked ? color : theme.palette.text.secondary, transition: "color .2s ease" },
      }}>
        {icon}
      </Box>

      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography sx={{ fontWeight: 900, fontSize: 14 }} >{title}</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12.5 }}>
          {subtitle}
        </Typography>
      </Box>

      <Stack direction="row" spacing={1} sx={{ flexShrink: 0, alignItems: "center" }}>
        <Chip
          size="small"
          label={checked ? "On" : "Off"}
          sx={{
            fontWeight: 900, fontSize: 11, height: 22,
            bgcolor: checked ? alpha(color, 0.12) : alpha(theme.palette.action.hover, 0.6),
            color: checked ? color : "text.secondary",
            border: `1px solid ${checked ? alpha(color, 0.3) : alpha(theme.palette.divider, 0.4)}`,
            transition: "all .2s ease",
          }}
        />
        <Switch
          checked={checked}
          onChange={(_, v) => onChange(v)}
          sx={{
            "& .MuiSwitch-switchBase.Mui-checked": { color },
            "& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track": { bgcolor: color },
          }}
        />
      </Stack>
    </InnerCard>
  );
}

// ---------------------------------------------------------------------------
// DirtyBar
// ---------------------------------------------------------------------------

function DirtyBar({
  dirty, saving, onSave, onReset, label = "Unsaved changes",
}: {
  dirty: boolean; saving: boolean;
  onSave: () => void; onReset?: () => void; label?: string;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  return (
    <Collapse in={dirty}>
      <InnerCard sx={{
        px: 2, py: 1.25, display: "flex", alignItems: "center", gap: 1.5,
        borderColor: alpha(theme.palette.warning.main, 0.4),
        background: alpha(theme.palette.warning.main, isDark ? 0.06 : 0.04),
      }}>
        <Box sx={{
          width: 8, height: 8, borderRadius: 99, flexShrink: 0,
          bgcolor: theme.palette.warning.main,
          boxShadow: `0 0 8px ${alpha(theme.palette.warning.main, 0.6)}`,
        }} />
        <Typography variant="body2" sx={{ flex: 1, color: "text.secondary", fontWeight: 700 }}>{label}</Typography>
        {onReset ? (
          <Button size="small" startIcon={<RestoreOutlined />} onClick={onReset}
            sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2 }}>
            Reset
          </Button>
        ) : null}
        <Button
          size="small" variant="contained"
          startIcon={saving ? <CircularProgress size={13} color="inherit" /> : <SaveOutlined />}
          disabled={saving} onClick={onSave}
          sx={{ textTransform: "none", fontWeight: 900, borderRadius: 2 }}
        >
          {saving ? "Saving…" : "Save changes"}
        </Button>
      </InnerCard>
    </Collapse>
  );
}

// ---------------------------------------------------------------------------
// PreferencesPanel
// ---------------------------------------------------------------------------

function PreferencesPanel({
  wantsAck, setWantsAck, wantsResults, setWantsResults,
  dirty, saving, onSave, onReset,
}: {
  wantsAck: boolean; setWantsAck: (v: boolean) => void;
  wantsResults: boolean; setWantsResults: (v: boolean) => void;
  dirty: boolean; saving: boolean; onSave: () => void; onReset: () => void;
}) {
  // Use semantic store colors so notification toggles follow the user's
  // colorblind-safe preset — inconclusive blue for "info/ack", done green for "results".
  const resultColors = useResultColors();
  const statusColors  = useStatusColors();

  return (
    <Stack spacing={2}>
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }} >
        <Box sx={{
          width: 46, height: 46, borderRadius: 3, display: "grid", placeItems: "center",
          background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
          border: "1px solid rgba(56,189,248,.2)", "& svg": { fontSize: 22 },
        }}>
          <TuneOutlined />
        </Box>
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 950, letterSpacing: -0.2 }} >Preferences</Typography>
          <Typography variant="body2" color="text.secondary">
            Control communications related to your submissions.
          </Typography>
        </Box>
      </Stack>

      <Divider sx={{ opacity: 0.25 }} />

      {/* Save bar — top */}
      <DirtyBar dirty={dirty} saving={saving} onSave={onSave} onReset={onReset} label="Unsaved preference changes" />

      <Stack spacing={1}>
        <CaptionLabel>Email notifications</CaptionLabel>
        <ToggleRow
          icon={<NotificationsOutlined />}
          title="Acknowledgements"
          subtitle="Receive a confirmation when your report is received and queued."
          checked={wantsAck} onChange={setWantsAck}
          accentColor={statusColors.done.main}
        />
        <ToggleRow
          icon={<NotificationsActiveOutlined />}
          title="Analysis results"
          subtitle="Receive outcome updates when analysis is complete."
          checked={wantsResults} onChange={setWantsResults}
          accentColor={statusColors.done.main}
        />
      </Stack>

      {!dirty ? (
        <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }} >
          <DoneOutlined sx={{ fontSize: 15, color: "success.main" }} />
          <Typography variant="caption" color="text.secondary">Preferences are up to date.</Typography>
        </Stack>
      ) : null}
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// AppearancePanel
// ---------------------------------------------------------------------------

function AppearancePanel({
  pickedTheme, setPickedTheme, autoSeasonal, setAutoSeasonal,
  themeName, dirty, saving, onSave, onReset,
}: {
  pickedTheme: ThemeName; setPickedTheme: (t: ThemeName) => void;
  autoSeasonal: boolean; setAutoSeasonal: (v: boolean) => void;
  themeName: ThemeName; dirty: boolean; saving: boolean;
  onSave: () => void; onReset: () => void;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  // Pull semantic colors so accent chips follow the user's preset.
  const statusColors = useStatusColors();

  return (
    <Stack spacing={2.5}>
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }} >
        <Box sx={{
          width: 46, height: 46, borderRadius: 3, display: "grid", placeItems: "center",
          background: "linear-gradient(135deg, rgba(120,119,198,.2), rgba(56,189,248,.12))",
          border: "1px solid rgba(120,119,198,.25)", "& svg": { fontSize: 22 },
        }}>
          <PaletteOutlined />
        </Box>
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 950, letterSpacing: -0.2 }} >Appearance</Typography>
          <Typography variant="body2" color="text.secondary">
            Pick a theme. Preview is instant — save to persist across sessions.
          </Typography>
        </Box>
      </Stack>

      <Divider sx={{ opacity: 0.25 }} />

      {/* Save bar — top */}
      <DirtyBar
        dirty={dirty} saving={saving} onSave={onSave} onReset={onReset}
        label="Unsaved appearance changes — save to persist across sessions"
      />

      {/* Active theme status */}
      <InnerCard sx={{ px: 2, py: 1.25 }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }} >
          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700 }}>Active theme:</Typography>
          <Chip
            size="small" label={themeName} variant="outlined"
            sx={{ height: 20, "& .MuiChip-label": { px: 0.9, fontSize: 11, fontWeight: 900 } }}
          />
          {autoSeasonal ? (
            <Chip
              size="small"
              icon={<AutoModeOutlined sx={{ fontSize: "12px !important" }} />}
              label="seasonal" color="secondary" variant="outlined"
              sx={{ height: 20, "& .MuiChip-label": { px: 0.75, fontSize: 11 } }}
            />
          ) : null}
          {dirty ? (
            <Chip
              size="small" label="unsaved"
              sx={{
                height: 20,
                bgcolor: alpha(theme.palette.warning.main, 0.12),
                color: "warning.main",
                border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                fontWeight: 800,
                "& .MuiChip-label": { px: 0.75, fontSize: 11 },
              }}
            />
          ) : (
            <Chip
              size="small"
              icon={<DoneOutlined sx={{ fontSize: "12px !important" }} />}
              label="saved"
              sx={{
                height: 20, bgcolor: alpha(statusColors.done.main, 0.1), color: statusColors.done.main,
                border: `1px solid ${alpha(statusColors.done.main, 0.25)}`,
                fontWeight: 800, "& .MuiChip-label": { px: 0.75, fontSize: 11 },
              }}
            />
          )}
        </Stack>
      </InnerCard>

      {/* Seasonal */}
      <Stack spacing={1}>
        <CaptionLabel>Automatic</CaptionLabel>
        <ToggleRow
          icon={<AutoModeOutlined />}
          title="Seasonal themes"
          subtitle="Automatically apply a theme based on the time of year."
          checked={autoSeasonal} onChange={setAutoSeasonal} accentColor="#A78BFA"
        />
        {autoSeasonal ? (
          <Alert severity="info" sx={{ borderRadius: 2.5 }}>
            Seasonal is enabled — the active theme is automatic. Saving updates your preferred
            manual theme for when seasonal is disabled.
          </Alert>
        ) : null}
      </Stack>

      {/* Theme picker */}
      <Stack spacing={1}>
        <CaptionLabel>Manual theme</CaptionLabel>
        <ThemePicker value={pickedTheme} onChange={setPickedTheme} />
      </Stack>

      {/* Bottom save bar */}
      <DirtyBar dirty={dirty} saving={saving} onSave={onSave} onReset={onReset} label="Unsaved appearance changes" />

      {!dirty ? (
        <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }} >
          <DoneOutlined sx={{ fontSize: 15, color: "success.main" }} />
          <Typography variant="caption" color="text.secondary">Appearance is up to date.</Typography>
        </Stack>
      ) : null}
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// ColorsPanel — wraps ColorSettingsPanel (no extra state needed here,
// ColorSettingsPanel owns its own mutations via useColorStore)
// ---------------------------------------------------------------------------

function ColorsPanel() {
  return <ColorSettingsPanel />;
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ProfilePage() {
  const queryClient = useQueryClient();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const { enqueueSnackbar } = useSnackbar();

  const { themeName, setThemeName, autoSeasonal, setAutoSeasonal } = useThemeMode();
  const { pixel, setPixel, alert, setAlert } = useHudModes();

  // Color store — hydrated from server profile on load
  const hydrateFromProfile = useColorStore((s) => s.hydrateFromProfile);
  const pageStatusColors   = useStatusColors();   // for hero "All saved" chip

  const [section, setSection] = React.useState<Section>("preferences");

  // ── Queries ──────────────────────────────────────────────────────────────

  const meQuery = useQuery<Me>({ queryKey: ["me"], queryFn: getMe, retry: false });
  const me = meQuery.data;

  const profileQuery = useQuery<UserProfile>({
    queryKey: ["profile"],
    queryFn: getProfile,
    enabled: !!me,
    retry: false,
  });

  // ── Hydrate color store from server profile ──────────────────────────────
  // Primary hydration: auth.ts → hydrateColorsFromServer() fires on getMe()
  //   and login(), so colors are set before this page even mounts.
  // Secondary hydration (here): re-syncs when the full profile query resolves,
  //   which catches color changes saved from another device or tab.
  React.useEffect(() => {
    const p = profileQuery.data;
    if (!p?.semantic_colors) return;
    hydrateFromProfile(p.semantic_colors);
  }, [profileQuery.data, hydrateFromProfile]);

  // ── Local state ──────────────────────────────────────────────────────────

  const [wantsAck,     setWantsAck]     = React.useState(false);
  const [wantsResults, setWantsResults] = React.useState(false);
  const [pickedTheme,  setPickedTheme]  = React.useState<ThemeName>(
    (readLocalProfile()?.theme as ThemeName) ?? ("light" as ThemeName)
  );

  // Sync form state from the fetched server profile — adjusted during render
  // when the data reference changes, instead of in an effect.
  // prev starts as undefined (not profileData): on a remount with a warm query
  // cache, data is already present on the first render, and seeding prev with
  // it would skip the sync and leave the toggles at their useState defaults.
  const profileData = profileQuery.data;
  const [prevProfileData, setPrevProfileData] =
    React.useState<UserProfile | undefined>(undefined);
  if (profileData !== prevProfileData) {
    setPrevProfileData(profileData);
    if (profileData) {
      setWantsAck(!!profileData.wants_acknowledgement);
      setWantsResults(!!profileData.wants_results);
      const t = (profileData.theme as ThemeName) ?? ("light" as ThemeName);
      setPickedTheme(t);
      setAutoSeasonal(!!profileData.auto_seasonal);
      if (!profileData.auto_seasonal) setThemeName(t);
    }
  }

  // One-time hydration of local form state from localStorage (render-time).
  const [localHydrated, setLocalHydrated] = React.useState(false);
  if (!localHydrated) {
    setLocalHydrated(true);
    const lp = readLocalProfile();
    if (lp) {
      if (typeof lp.wants_acknowledgement === "boolean") setWantsAck(lp.wants_acknowledgement);
      if (typeof lp.wants_results === "boolean") setWantsResults(lp.wants_results);
      if (lp.theme) setPickedTheme(lp.theme as ThemeName);
    }
  }

  // Side effects from the stored theme (theme store + query cache) must run in
  // an effect, not during render.
  React.useEffect(() => {
    const lp = readLocalProfile();
    if (lp?.theme) {
      const t = lp.theme as ThemeName;
      setThemeName(t);
      queryClient.setQueryData<UserProfile>(["profile"], (prev) => ({
        ...(prev ?? profileQuery.data as UserProfile),
        theme: t,
      }));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Live theme preview
  React.useEffect(() => {
    if (!pickedTheme || autoSeasonal) return;
    setThemeName(pickedTheme);
    writeLocalProfile({ theme: pickedTheme });
  }, [pickedTheme, setThemeName, autoSeasonal]);

  // ── Mutations ────────────────────────────────────────────────────────────

  const prefMutation = useMutation({
    mutationFn: updatePreferences,
    onSuccess: (updated) => {
      queryClient.setQueryData(["profile"], updated);
      enqueueSnackbar("Preferences saved.", { variant: "success" });
    },
    onError: (err) =>
      enqueueSnackbar(`Preferences API failed — ${apiErrorText(err)}`, { variant: "warning" }),
  });

  const appearanceMutation = useMutation({
    mutationFn: updateAppearance,
    onSuccess: (updated) => {
      queryClient.setQueryData(["profile"], updated);
      enqueueSnackbar("Appearance saved.", { variant: "success" });
    },
    onError: (err) =>
      enqueueSnackbar(`Appearance API failed — ${apiErrorText(err)}`, { variant: "warning" }),
  });

  // ── Dirty detection ──────────────────────────────────────────────────────

  const baseProfile = profileQuery.data;

  const prefsDirty =
    wantsAck !== !!baseProfile?.wants_acknowledgement ||
    wantsResults !== !!baseProfile?.wants_results;

  const themeDirty =
    pickedTheme !== ((baseProfile?.theme as ThemeName) ?? pickedTheme) ||
    autoSeasonal !== !!baseProfile?.auto_seasonal;

  // ── Save / reset ─────────────────────────────────────────────────────────

  function savePreferences() {
    writeLocalProfile({ wants_acknowledgement: wantsAck, wants_results: wantsResults });
    queryClient.setQueryData<UserProfile>(["profile"], (prev) => ({
      ...(prev ?? baseProfile as UserProfile),
      wants_acknowledgement: wantsAck,
      wants_results: wantsResults,
    }));
    prefMutation.mutate({ wants_acknowledgement: wantsAck, wants_results: wantsResults });
  }

  function resetPreferences() {
    setWantsAck(!!baseProfile?.wants_acknowledgement);
    setWantsResults(!!baseProfile?.wants_results);
  }

  function saveAppearance() {
    writeLocalProfile({ theme: pickedTheme, auto_seasonal: autoSeasonal } as any);
    queryClient.setQueryData<UserProfile>(["profile"], (prev) => ({
      ...(prev ?? baseProfile as UserProfile),
      theme: pickedTheme,
      auto_seasonal: autoSeasonal,
    }));
    appearanceMutation.mutate({ theme: pickedTheme, auto_seasonal: autoSeasonal });
  }

  function resetAppearance() {
    const t = (baseProfile?.theme as ThemeName) ?? pickedTheme;
    setPickedTheme(t);
    setAutoSeasonal(!!baseProfile?.auto_seasonal);
  }

  // ── Auth guard ────────────────────────────────────────────────────────────

  if (meQuery.isLoading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me) {
    return <Box sx={{ p: 3 }}><Alert severity="error">Not authenticated.</Alert></Box>;
  }

  // ── Derived ───────────────────────────────────────────────────────────────

  const groups     = (me as any)?.groups ?? [];
  const isElevated = groups.includes("CISO") || groups.includes("CERT");
  const scope      = (me as any)?.ciso_scope;
  const displayName = [me.first_name, me.last_name].filter(Boolean).join(" ") || me.username;

  // Nav items — drives both sidebar and dirty-dot logic
  const NAV = [
    {
      key: "preferences" as Section,
      label: "Preferences",
      sub: "Notifications and feedback",
      icon: <TuneOutlined />,
      dirty: prefsDirty,
    },
    {
      key: "appearance" as Section,
      label: "Appearance",
      sub: "Theme and UI style",
      icon: <PaletteOutlined />,
      dirty: themeDirty,
    },
    {
      key: "colors" as Section,
      label: "Customize colors",
      sub: "Status and result indicators",
      icon: <AccessibilityNewOutlined />,
      dirty: false, // ColorSettingsPanel manages its own mutation state
    },
  ] as const;

  const anyDirty = prefsDirty || themeDirty;

  return (
    <Skeleton
      name="profile-page"
      loading={meQuery.isPending || profileQuery.isPending}
      animate="shimmer"
    >
    <Box sx={{ p: { xs: 1.5, md: 2.5 }, maxWidth: 1180, mx: "auto" }}>

      {/* ── Hero header ───────────────────────────────────────────────────── */}
      <SoftCard
        sx={{
          mb: 2.5,
          overflow: "hidden",
          background: isDark
            ? `radial-gradient(800px 260px at 5% 0%, ${alpha("#4FB3FF", 0.11)}, transparent 60%),
               radial-gradient(600px 220px at 95% 40%, ${alpha("#7C3AED", 0.09)}, transparent 60%),
               linear-gradient(180deg, ${alpha("#fff", 0.03)}, ${alpha("#fff", 0.02)})`
            : `radial-gradient(800px 260px at 5% 0%, ${alpha("#3B82F6", 0.08)}, transparent 60%),
               radial-gradient(600px 220px at 95% 40%, ${alpha("#7C3AED", 0.06)}, transparent 60%),
               linear-gradient(180deg, ${alpha("#fff", 0.92)}, ${alpha(theme.palette.grey[50], 0.98)})`,
        }}
      >
        <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
          <Stack
            direction={{ xs: "column", md: "row" }}
            spacing={2.5}
            sx={{ alignItems: { md: "center" }, justifyContent: "space-between" }}
>
            {/* Identity */}
            <Stack direction="row" spacing={2.25} sx={{ minWidth: 0, alignItems: "center" }}>
              {/* Avatar with gradient ring */}
              <Box sx={{ position: "relative", flexShrink: 0 }}>
                <Box sx={{
                  position: "absolute", inset: -2, borderRadius: "50%",
                  background: isDark
                    ? "linear-gradient(135deg, rgba(56,189,248,.6), rgba(120,119,198,.5))"
                    : "linear-gradient(135deg, rgba(59,130,246,.5), rgba(124,58,237,.4))",
                  zIndex: 0,
                }} />
                <Avatar sx={{
                  width: 62, height: 62, fontWeight: 950, fontSize: 22,
                  position: "relative", zIndex: 1,
                  bgcolor: isDark ? alpha("#fff", 0.07) : alpha(theme.palette.primary.main, 0.08),
                  color: "text.primary",
                  border: `2px solid ${isDark ? alpha("#0f172a", 0.9) : alpha("#fff", 0.9)}`,
                }}>
                  {initials(me.first_name, me.last_name)}
                </Avatar>
              </Box>

              <Box sx={{ minWidth: 0 }}>
                <Typography variant="h4" noWrap sx={{ lineHeight: 1.15, fontWeight: 950, letterSpacing: -0.6 }}>
                  {displayName}
                </Typography>
                <Stack direction="row" spacing={0.75} sx={{ mt: 1, flexWrap: "wrap" }}>
                  {me.email ? (
                    <Chip size="small" icon={<MailOutlined />} label={me.email} variant="outlined"
                      sx={{ height: 24, "& .MuiChip-label": { fontSize: 12 } }} />
                  ) : null}
                  {isElevated ? (
                    <Chip size="small" icon={<ShieldOutlined />} label="Elevated" variant="outlined" color="primary"
                      sx={{ height: 24, "& .MuiChip-label": { fontSize: 12 } }} />
                  ) : (
                    <Chip size="small" label="Standard" variant="outlined"
                      sx={{ height: 24, "& .MuiChip-label": { fontSize: 12 } }} />
                  )}
                  {scope ? (
                    <Chip size="small" label={`Scope: ${scope}`} variant="outlined"
                      sx={{ height: 24, "& .MuiChip-label": { fontSize: 12 } }} />
                  ) : null}
                </Stack>
              </Box>
            </Stack>

            {/* Account info + global save status */}
            <Stack spacing={0.4} sx={{ flexShrink: 0, alignItems: { xs: "flex-start", md: "flex-end" } }}>
              <Typography variant="caption" color="text.disabled"
                sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, fontSize: 10 }}>
                Account
              </Typography>
              <Typography sx={{ fontWeight: 900, fontSize: 14 }} >{me.username}</Typography>
              <Stack direction="row" spacing={0.5}>
                {anyDirty ? (
                  <Chip size="small" label="Unsaved changes" sx={{
                    height: 20,
                    bgcolor: alpha(theme.palette.warning.main, 0.12),
                    color: "warning.main",
                    border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                    fontWeight: 800, "& .MuiChip-label": { px: 0.9, fontSize: 11 },
                  }} />
                ) : (
                  <Chip
                    size="small"
                    icon={<CheckCircleOutlined sx={{ fontSize: "13px !important" }} />}
                    label="All saved"
                    sx={{
                      height: 20, bgcolor: alpha(pageStatusColors.done.main, 0.1), color: pageStatusColors.done.main,
                      border: `1px solid ${alpha(pageStatusColors.done.main, 0.25)}`,
                      fontWeight: 800, "& .MuiChip-label": { px: 0.9, fontSize: 11 },
                    }}
                  />
                )}
              </Stack>
            </Stack>
          </Stack>
        </CardContent>
      </SoftCard>

      {/* ── Main grid ────────────────────────────────────────────────────── */}
      <Box sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", md: "280px 1fr" },
        gap: 2,
        alignItems: "start",
      }}>

        {/* ── Sidebar nav ───────────────────────────────────────────────── */}
        <SoftCard sx={{ position: { md: "sticky" }, top: { md: 16 }, overflow: "hidden" }}>
          <CardContent sx={{ p: 1.5 }}>
            {/* Identity mini */}
            <Stack direction="row" spacing={1.25} sx={{ px: 1, py: 1, mb: 0.5, alignItems: "center" }}>
              <Box sx={{
                width: 42, height: 42, borderRadius: 3, display: "grid", placeItems: "center",
                border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
                background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                "& svg": { fontSize: 22 },
              }}>
                <PersonOutlined />
              </Box>
              <Box sx={{ minWidth: 0 }}>
                <Typography sx={{ fontWeight: 950, fontSize: 14 }} >My profile</Typography>
                <Typography variant="caption" color="text.secondary" noWrap>{me.username}</Typography>
              </Box>
            </Stack>

            <Divider sx={{ opacity: isDark ? 0.18 : 0.45, my: 1 }} />

            <List dense disablePadding>
              {NAV.map((item) => {
                const isActive = section === item.key;
                return (
                  <ListItemButton
                    key={item.key}
                    selected={isActive}
                    onClick={() => setSection(item.key)}
                    sx={{
                      borderRadius: 2.5, mx: 0.25, my: 0.35, py: 1, px: 1.25,
                      transition: "all .15s ease",
                      "&.Mui-selected": {
                        background: alpha(theme.palette.primary.main, isDark ? 0.12 : 0.08),
                        "&:hover": { background: alpha(theme.palette.primary.main, isDark ? 0.16 : 0.11) },
                      },
                    }}
                  >
                    <NavIcon icon={item.icon} isDark={isDark} />
                    <ListItemText
                      primary={
                        <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }} >
                          <span>{item.label}</span>
                          {item.dirty ? (
                            <Box sx={{ width: 6, height: 6, borderRadius: 99, bgcolor: "warning.main", flexShrink: 0 }} />
                          ) : null}
                        </Stack>
                      }
                      secondary={item.sub}
                      sx={{ ml: 1.25 }}
                      slotProps={{
                        primary: {
                          sx: {
                            fontWeight: isActive ? 950 : 800,
                            fontSize: 13.5,
                            color: isActive ? "primary.main" : undefined,
                          },
                        },
                        secondary: {
                          sx: { display: { xs: "none", md: "block" }, fontSize: 11, mt: 0.15 },
                        },
                      }}
                    />
                  </ListItemButton>
                );
              })}
            </List>

            <Divider sx={{ opacity: isDark ? 0.18 : 0.45, my: 1 }} />

            <Typography variant="caption" color="text.disabled" sx={{ px: 1.5, display: "block", fontSize: 11 }}>
              Theme preview applies instantly. Save to persist across sessions.
            </Typography>
          </CardContent>
        </SoftCard>

        {/* ── Content panel ─────────────────────────────────────────────── */}
        <SoftCard>
          <CardContent sx={{ p: { xs: 2, md: 3 } }}>
            {section === "preferences" ? (
              <PreferencesPanel
                wantsAck={wantsAck} setWantsAck={setWantsAck}
                wantsResults={wantsResults} setWantsResults={setWantsResults}
                dirty={prefsDirty} saving={prefMutation.isPending}
                onSave={savePreferences} onReset={resetPreferences}
              />
            ) : section === "appearance" ? (
              <AppearancePanel
                pickedTheme={pickedTheme} setPickedTheme={setPickedTheme}
                autoSeasonal={autoSeasonal} setAutoSeasonal={setAutoSeasonal}
                themeName={themeName}
                dirty={themeDirty} saving={appearanceMutation.isPending}
                onSave={saveAppearance} onReset={resetAppearance}
              />
            ) : (
              <ColorsPanel />
            )}
          </CardContent>
        </SoftCard>
      </Box>
    </Box>
    </Skeleton>
  );
}