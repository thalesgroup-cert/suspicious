// src/pages/ProfilePage.tsx
import * as React from "react";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Divider,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Stack,
  Switch,
  Typography,
  Chip,
  useTheme,
  FormControlLabel,
} from "@mui/material";
import {
  PersonOutline,
  TuneOutlined,
  PaletteOutlined,
  SaveOutlined,
  MailOutline,
  ShieldOutlined,
  CheckCircleOutlined,
  ErrorOutlineOutlined,
  AutoModeOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ThemePicker } from "@/styles/components/ThemePicker";
import { getMe, type Me } from "@/api/auth";
import { getProfile, updateAppearance, updatePreferences, type UserProfile } from "@/features/profile/api";
import { useThemeMode } from "@/styles/themeStore";
import type { ThemeName } from "@/styles/themes";
import { useHudModes } from "@/shared/hooks/useHudModes";

type Section = "preferences" | "appearance";

function initials(first?: string, last?: string) {
  const f = (first ?? "").trim()[0] ?? "";
  const l = (last ?? "").trim()[0] ?? "";
  return (f + l).toUpperCase() || "U";
}

const LOCAL_PROFILE_KEY = "suspicious.profile.local";

function readLocalProfile(): Partial<UserProfile> | null {
  try {
    const raw = localStorage.getItem(LOCAL_PROFILE_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function writeLocalProfile(patch: Partial<UserProfile>) {
  try {
    const prev = readLocalProfile() ?? {};
    const next = { ...prev, ...patch };
    localStorage.setItem(LOCAL_PROFILE_KEY, JSON.stringify(next));
  } catch {
    // ignore
  }
}

function apiErrorText(err: unknown) {
  const anyErr = err as any;
  const status = anyErr?.response?.status;
  const data = anyErr?.response?.data;
  const msg =
    anyErr?.message ||
    data?.detail ||
    data?.error ||
    (typeof data === "string" ? data : null) ||
    "Request failed";
  return status ? `${status}: ${msg}` : String(msg);
}

function SurfaceCard(props: React.PropsWithChildren<{ sx?: any }>) {
  const theme = useTheme();
  return (
    <Card
      sx={{
        borderRadius: 4,
        border: `1px solid ${theme.palette.mode === "dark" ? "rgba(229,231,235,.12)" : "rgba(11,18,32,.10)"}`,
        backgroundColor: theme.palette.mode === "dark" ? "rgba(255,255,255,.02)" : "rgba(255,255,255,1)",
        boxShadow: "none",
        ...props.sx,
      }}
    >
      {props.children}
    </Card>
  );
}

export default function ProfilePage() {
  const queryClient = useQueryClient();
  const muiTheme = useTheme();

  // updated: theme store now exposes autoSeasonal controls
  const { themeName, setThemeName, isDarkMode, autoSeasonal, setAutoSeasonal } = useThemeMode();
  const { pixel, setPixel, alert, setAlert } = useHudModes();

  const [section, setSection] = React.useState<Section>("preferences");

  const useMockMe = import.meta.env.VITE_USE_MOCK_ME === "true";

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
    enabled: !useMockMe,
  });

  const me: Me | undefined = useMockMe
    ? ({
        id: 1,
        username: "mockuser",
        email: "mockuser@example.com",
        first_name: "Mock",
        last_name: "User",
        groups: ["CISO", "CERT"],
        ciso_scope: "EU",
      } as any)
    : meQuery.data;

  const profileQuery = useQuery<UserProfile>({
    queryKey: ["profile"],
    queryFn: getProfile,
    enabled: !!me && !useMockMe,
    retry: false,
    initialData: {
      wants_acknowledgement: false,
      wants_results: false,
      theme: (readLocalProfile()?.theme as ThemeName) ?? ("graphite" as ThemeName),
    },
  });

  const [wantsAck, setWantsAck] = React.useState(false);
  const [wantsResults, setWantsResults] = React.useState(false);
  const [pickedTheme, setPickedTheme] = React.useState<ThemeName>(
    (readLocalProfile()?.theme as ThemeName) ?? ("graphite" as ThemeName)
  );

  const [localBanner, setLocalBanner] = React.useState<
    | { kind: "success"; text: string }
    | { kind: "error"; text: string }
    | null
  >(null);

  React.useEffect(() => {
    const p = profileQuery.data;
    if (!p) return;

    setWantsAck(!!p.wants_acknowledgement);
    setWantsResults(!!p.wants_results);

    const t = (p.theme as ThemeName) ?? ("graphite" as ThemeName);
    setPickedTheme(t);

    // apply theme immediately (note: theme store may override if autoSeasonal is ON)
    setThemeName(t);
  }, [profileQuery.data, setThemeName]);

  React.useEffect(() => {
    const lp = readLocalProfile();
    if (!lp) return;

    if (typeof lp.wants_acknowledgement === "boolean") setWantsAck(lp.wants_acknowledgement);
    if (typeof lp.wants_results === "boolean") setWantsResults(lp.wants_results);

    if (lp.theme) {
      const t = lp.theme as ThemeName;
      setPickedTheme(t);
      setThemeName(t);
      queryClient.setQueryData<UserProfile>(["profile"], (prev) => ({
        ...(prev ?? (profileQuery.data as UserProfile)),
        theme: t,
      }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const prefMutation = useMutation({
    mutationFn: updatePreferences,
    onSuccess: (updated) => {
      queryClient.setQueryData(["profile"], updated);
      setLocalBanner({ kind: "success", text: "Preferences saved." });
    },
  });

  const appearanceMutation = useMutation({
    mutationFn: updateAppearance,
    onSuccess: (updated) => {
      queryClient.setQueryData(["profile"], updated);
      setLocalBanner({ kind: "success", text: "Appearance saved." });
    },
  });

  const savingPrefs = prefMutation.isPending;
  const savingTheme = appearanceMutation.isPending;

  if (!useMockMe && meQuery.isLoading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Not authenticated.</Alert>
      </Box>
    );
  }

  const groups = (me as any)?.groups ?? [];
  const isElevated = groups.includes("CISO") || groups.includes("CERT");
  const scope = (me as any)?.ciso_scope;

  const displayName = [me.first_name, me.last_name].filter(Boolean).join(" ") || me.username;

  const baseProfile = profileQuery.data;

  const prefsDirty = wantsAck !== !!baseProfile?.wants_acknowledgement || wantsResults !== !!baseProfile?.wants_results;

  // If seasonal is ON, appearance changes are still allowed, but the active theme is seasonal.
  // themeDirty should compare against stored preference (pickedTheme) vs baseProfile theme.
  const themeDirty = pickedTheme !== ((baseProfile?.theme as ThemeName) ?? pickedTheme);

  const savePreferences = () => {
    setLocalBanner(null);

    writeLocalProfile({ wants_acknowledgement: wantsAck, wants_results: wantsResults });
    queryClient.setQueryData<UserProfile>(["profile"], (prev) => ({
      ...(prev ?? (baseProfile as UserProfile)),
      wants_acknowledgement: wantsAck,
      wants_results: wantsResults,
    }));

    if (useMockMe) {
      setLocalBanner({ kind: "success", text: "Preferences saved locally (mock mode)." });
      return;
    }

    prefMutation.mutate({ wants_acknowledgement: wantsAck, wants_results: wantsResults });
  };

  const saveAppearance = () => {
    setLocalBanner(null);

    writeLocalProfile({ theme: pickedTheme });
    queryClient.setQueryData<UserProfile>(["profile"], (prev) => ({
      ...(prev ?? (baseProfile as UserProfile)),
      theme: pickedTheme,
    }));

    if (useMockMe) {
      setLocalBanner({ kind: "success", text: "Theme saved locally (mock mode)." });
      return;
    }

    appearanceMutation.mutate({ theme: pickedTheme } as any);
  };

  // Preview immediately when autoSeasonal is OFF.
  React.useEffect(() => {
    if (!pickedTheme) return;
    if (autoSeasonal) return; // seasonal overrides preview
    setThemeName(pickedTheme);
    writeLocalProfile({ theme: pickedTheme });
  }, [pickedTheme, setThemeName, autoSeasonal]);

  return (
    <Box sx={{ p: { xs: 2, md: 3 }, maxWidth: 1180, mx: "auto" }}>
      <SurfaceCard
        sx={{
          mb: 2,
          overflow: "hidden",
          background: isDarkMode
            ? "radial-gradient(900px 280px at 10% 0%, rgba(79,179,255,.14), transparent 60%)," +
              "radial-gradient(900px 260px at 90% 30%, rgba(91,140,255,.10), transparent 60%)," +
              "linear-gradient(180deg, rgba(255,255,255,.03), rgba(255,255,255,.015))"
            : "radial-gradient(900px 280px at 10% 0%, rgba(31,94,255,.10), transparent 60%)," +
              "radial-gradient(900px 260px at 90% 30%, rgba(15,118,110,.07), transparent 60%)," +
              "linear-gradient(180deg, rgba(255,255,255,1), rgba(255,255,255,1))",
        }}
      >
        <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
          <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "center" }}>
            <Stack direction="row" spacing={2} alignItems="center" sx={{ flex: 1, minWidth: 0 }}>
              <Avatar
                sx={{
                  width: 56,
                  height: 56,
                  fontWeight: 850,
                  bgcolor: isDarkMode ? "rgba(255,255,255,.08)" : "rgba(11,18,32,.06)",
                  color: muiTheme.palette.text.primary,
                  border: `1px solid ${isDarkMode ? "rgba(229,231,235,.14)" : "rgba(11,18,32,.12)"}`,
                }}
              >
                {initials(me.first_name, me.last_name)}
              </Avatar>

              <Box sx={{ minWidth: 0 }}>
                <Typography variant="h4" sx={{ fontWeight: 800, letterSpacing: -0.4 }} noWrap>
                  {displayName}
                </Typography>

                <Stack direction="row" spacing={1} sx={{ mt: 0.9, flexWrap: "wrap" }}>
                  <Chip size="small" icon={<PersonOutline />} label={me.username} variant="outlined" />
                  {me.email ? <Chip size="small" icon={<MailOutline />} label={me.email} variant="outlined" /> : null}
                  {isElevated ? (
                    <Chip size="small" icon={<ShieldOutlined />} label="Elevated" variant="outlined" />
                  ) : (
                    <Chip size="small" label="Standard" variant="outlined" />
                  )}
                  {scope ? <Chip size="small" label={`Scope: ${scope}`} variant="outlined" /> : null}
                  <Chip size="small" label={useMockMe ? "Mock auth" : "Live auth"} variant="outlined" />
                </Stack>
              </Box>
            </Stack>

            <Stack direction="row" spacing={1}>
              <Button
                variant={section === "preferences" ? "contained" : "outlined"}
                startIcon={<TuneOutlined />}
                onClick={() => setSection("preferences")}
              >
                Preferences
              </Button>
              <Button
                variant={section === "appearance" ? "contained" : "outlined"}
                startIcon={<PaletteOutlined />}
                onClick={() => setSection("appearance")}
              >
                Appearance
              </Button>
            </Stack>
          </Stack>
        </CardContent>
      </SurfaceCard>

      {localBanner ? (
        <Alert
          severity={localBanner.kind === "success" ? "success" : "error"}
          icon={localBanner.kind === "success" ? <CheckCircleOutlined /> : <ErrorOutlineOutlined />}
          sx={{ mb: 2 }}
        >
          {localBanner.text}
        </Alert>
      ) : null}

      {appearanceMutation.isError ? (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Appearance API failed — using local theme. ({apiErrorText(appearanceMutation.error)})
        </Alert>
      ) : null}

      {prefMutation.isError ? (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Preferences API failed — using local settings. ({apiErrorText(prefMutation.error)})
        </Alert>
      ) : null}

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "1fr", md: "320px 1fr" },
          gap: 2,
          alignItems: "start",
        }}
      >
        <SurfaceCard>
          <CardContent sx={{ p: 1.25 }}>
            <Typography variant="subtitle2" color="text.secondary" sx={{ px: 1.25, pt: 0.75 }}>
              Profile Settings
            </Typography>

            <List dense sx={{ mt: 0.5 }}>
              <ListItemButton
                selected={section === "preferences"}
                onClick={() => setSection("preferences")}
                sx={{
                  borderRadius: 3,
                  "&.Mui-selected": { bgcolor: isDarkMode ? "rgba(255,255,255,.05)" : "rgba(11,18,32,.04)" },
                }}
              >
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <TuneOutlined />
                </ListItemIcon>
                <ListItemText primary="Preferences" secondary="Notifications and feedback" />
              </ListItemButton>

              <ListItemButton
                selected={section === "appearance"}
                onClick={() => setSection("appearance")}
                sx={{
                  borderRadius: 3,
                  "&.Mui-selected": { bgcolor: isDarkMode ? "rgba(255,255,255,.05)" : "rgba(11,18,32,.04)" },
                }}
              >
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <PaletteOutlined />
                </ListItemIcon>
                <ListItemText primary="Appearance" secondary="Theme and UI style" />
              </ListItemButton>
            </List>

            <Divider sx={{ my: 1.25, opacity: 0.25 }} />

            <Typography variant="caption" color="text.secondary" sx={{ px: 1.25, display: "block" }}>
              Theme preview applies instantly (unless Seasonal is enabled).
            </Typography>
          </CardContent>
        </SurfaceCard>

        <SurfaceCard>
          <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
            {section === "preferences" ? (
              <Stack spacing={2}>
                <Stack spacing={0.5}>
                  <Typography variant="h5" sx={{ fontWeight: 800, letterSpacing: -0.2 }}>
                    Preferences
                  </Typography>
                  <Typography color="text.secondary">Control communications related to your submissions.</Typography>
                </Stack>

                <Divider sx={{ opacity: 0.25 }} />

                <Box
                  sx={{
                    borderRadius: 3,
                    border: `1px solid ${isDarkMode ? "rgba(229,231,235,.12)" : "rgba(11,18,32,.10)"}`,
                    p: 2,
                    backgroundColor: isDarkMode ? "rgba(255,255,255,.02)" : "rgba(11,18,32,.02)",
                  }}
                >
                  <Stack spacing={1.75}>
                    <Stack direction="row" alignItems="center" justifyContent="space-between">
                      <Box sx={{ pr: 2 }}>
                        <Typography sx={{ fontWeight: 700 }}>Acknowledgements</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Receive a confirmation when your report is received.
                        </Typography>
                      </Box>
                      <Switch checked={wantsAck} onChange={(_, v) => setWantsAck(v)} />
                    </Stack>

                    <Stack direction="row" alignItems="center" justifyContent="space-between">
                      <Box sx={{ pr: 2 }}>
                        <Typography sx={{ fontWeight: 700 }}>Results</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Receive outcome updates when analysis is complete.
                        </Typography>
                      </Box>
                      <Switch checked={wantsResults} onChange={(_, v) => setWantsResults(v)} />
                    </Stack>
                  </Stack>
                </Box>

                <Stack direction="row" justifyContent="space-between" alignItems="center">
                  <Typography variant="caption" color="text.secondary">
                    {prefsDirty ? "Unsaved changes" : "Up to date"}
                  </Typography>

                  <Button
                    variant="contained"
                    startIcon={<SaveOutlined />}
                    disabled={!prefsDirty || savingPrefs}
                    onClick={savePreferences}
                  >
                    {savingPrefs ? "Saving…" : useMockMe ? "Save (local)" : "Save changes"}
                  </Button>
                </Stack>
              </Stack>
            ) : (
              <Stack spacing={2}>
                <Stack spacing={0.5}>
                  <Typography variant="h5" sx={{ fontWeight: 800, letterSpacing: -0.2 }}>
                    Appearance
                  </Typography>
                  <Typography color="text.secondary">
                    Pick a theme for your working environment. Preview is instant.
                  </Typography>
                </Stack>

                <Divider sx={{ opacity: 0.25 }} />

                {/* Seasonal toggle (new) */}
                <Box
                  sx={{
                    borderRadius: 3,
                    border: `1px solid ${isDarkMode ? "rgba(229,231,235,.12)" : "rgba(11,18,32,.10)"}`,
                    p: 2,
                    backgroundColor: isDarkMode ? "rgba(255,255,255,.02)" : "rgba(11,18,32,.02)",
                  }}
                >
                  <FormControlLabel
                    control={
                      <Switch
                        checked={autoSeasonal}
                        onChange={(_, v) => {
                          setAutoSeasonal(v);
                          setLocalBanner({
                            kind: "success",
                            text: v ? "Seasonal themes enabled." : "Seasonal themes disabled.",
                          });
                        }}
                      />
                    }
                    label={
                      <Stack direction="row" spacing={1} alignItems="center">
                        <AutoModeOutlined fontSize="small" />
                        <Box>
                          <Typography sx={{ fontWeight: 700, lineHeight: 1.1 }}>Seasonal themes</Typography>
                          <Typography variant="body2" color="text.secondary">
                            Automatically apply a theme based on the time of year.
                          </Typography>
                        </Box>
                      </Stack>
                    }
                    sx={{ m: 0, alignItems: "flex-start" }}
                  />
                </Box>

                {/* Theme picker (controlled) */}
                <ThemePicker value={pickedTheme} onChange={setPickedTheme} />

                <Divider sx={{ opacity: 0.25 }} />

                <Stack direction="row" justifyContent="space-between" alignItems="center">
                  <Typography variant="caption" color="text.secondary">
                    Active theme: <b>{themeName}</b>
                    {autoSeasonal ? " • seasonal" : ""}
                    {(!autoSeasonal && themeDirty) || (autoSeasonal && themeDirty) ? " • unsaved preference" : " • saved"}
                  </Typography>

                  <Button
                    variant="contained"
                    startIcon={<SaveOutlined />}
                    disabled={!themeDirty || savingTheme}
                    onClick={saveAppearance}
                  >
                    {savingTheme ? "Saving…" : useMockMe ? "Save (local)" : "Save changes"}
                  </Button>
                </Stack>
                <Stack direction="row" spacing={2} sx={{ flexWrap: "wrap" }}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Typography variant="body2" color="text.secondary">Pixel background</Typography>
                    <Switch checked={pixel} onChange={(_, v) => setPixel(v)} />
                  </Stack>

                  <Stack direction="row" spacing={1} alignItems="center">
                    <Typography variant="body2" color="text.secondary">ALERT mode</Typography>
                    <Switch checked={alert} onChange={(_, v) => setAlert(v)} />
                  </Stack>
                </Stack>

                {autoSeasonal ? (
                  <Alert severity="info">
                    Seasonal is enabled: the active theme is automatic. Saving updates your preferred manual theme for when
                    Seasonal is disabled.
                  </Alert>
                ) : null}
              </Stack>
            )}
          </CardContent>
        </SurfaceCard>
      </Box>

      <Box sx={{ mt: 2 }}>
        <Typography variant="caption" color="text.secondary">
          Signed in as {me.username}
        </Typography>
      </Box>
    </Box>
  );
}
