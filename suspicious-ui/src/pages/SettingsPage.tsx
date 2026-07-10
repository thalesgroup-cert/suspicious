import * as React from "react";
import {
  Alert,
  Box,
  Button,
  CardContent,
  CircularProgress,
  Divider,
  Grid,
  IconButton,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { RefreshOutlined, SettingsOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";

import { getMe, type Me } from "@/api/auth";
import { getProfile } from "@/features/profile/api";
import { UserAvatar } from "@/features/profile/components/UserAvatar";
import { NavIcon, SoftCard } from "@/features/settings/components/cards";
import { SECTIONS, SectionContent, type SectionKey } from "@/features/settings/components/sections";

export default function SettingsPage() {
  const qc = useQueryClient();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const meQuery = useQuery<Me>({ queryKey: ["me"], queryFn: getMe, retry: false });
  const me = meQuery.data;

  const profileQuery = useQuery({
    queryKey: ["profile"],
    queryFn: getProfile,
    enabled: !!me,
    retry: false,
  });
  const groups = me?.groups ?? [];
  const isAllowed = groups.includes("Admin") || groups.includes("CERT");

  const [active, setActive] = React.useState<SectionKey>("domains_allow");
  const activeMeta = SECTIONS.find((s) => s.key === active)!;

  if (meQuery.isLoading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me || !isAllowed) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Not authorized (Admin / CERT only).</Alert>
      </Box>
    );
  }

  return (
    <Skeleton
      name="settings-page"
      loading={meQuery.isPending}
      animate="shimmer"
    >
    <Box sx={{ p: { xs: 1.5, md: 2.5 } }}>
      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={1.5}
        sx={{ mb: 2.5, justifyContent: "space-between" }}
      >
        <Stack spacing={0.4}>
          <Stack direction="row" spacing={1.25} sx={{ alignItems: "center" }} >
            <UserAvatar
              avatar={profileQuery.data?.avatar}
              initials={(me.username?.[0] ?? "U").toUpperCase()}
              sx={{ width: 46, height: 46, fontWeight: 950 }}
            />
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 950, letterSpacing: -0.5 }} >
                Settings
              </Typography>
              <Typography color="text.secondary">
                Manage blocklists, feeder state, and analyzer scoring.
              </Typography>
            </Box>
          </Stack>
        </Stack>

        <Tooltip title="Refresh all settings">
          <IconButton
            aria-label="Refresh all"
            onClick={() => qc.invalidateQueries({ queryKey: ["settings"] })}
            sx={{
              alignSelf: { xs: "flex-start", md: "center" },
              border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
              borderRadius: 2,
            }}
          >
            <RefreshOutlined />
          </IconButton>
        </Tooltip>
      </Stack>

      <Grid container spacing={2} sx={{ alignItems: "flex-start" }} >
        <Grid size={{ xs: 12, md: 3.5, lg: 3 }}>
          <SoftCard sx={{ overflow: "hidden", position: { md: "sticky" }, top: { md: 16 } }}>
            <CardContent sx={{ p: 1.5 }}>
              <Stack direction="row" spacing={1.25} sx={{ px: 1, py: 1, mb: 0.5, alignItems: "center" }}>
                <Box
                  sx={{
                    width: 42,
                    height: 42,
                    borderRadius: 3,
                    display: "grid",
                    placeItems: "center",
                    border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
                    background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                    "& svg": { fontSize: 22 },
                  }}
                >
                  <SettingsOutlined />
                </Box>
                <Box sx={{ minWidth: 0 }}>
                  <Typography sx={{ fontWeight: 950, fontSize: 14 }} >Admin console</Typography>
                  <Typography variant="caption" color="text.secondary" noWrap>{me.username}</Typography>
                </Box>
              </Stack>

              <Divider sx={{ opacity: isDark ? 0.18 : 0.45, my: 1 }} />

              <List dense disablePadding>
                {SECTIONS.map((s) => {
                  const isActive = active === s.key;
                  return (
                    <ListItemButton
                      key={s.key}
                      selected={isActive}
                      onClick={() => setActive(s.key)}
                      sx={{
                        borderRadius: 2.5,
                        mx: 0.25,
                        my: 0.35,
                        py: 1,
                        px: 1.25,
                        transition: "all .15s ease",
                        "&.Mui-selected": {
                          background: alpha(theme.palette.primary.main, isDark ? 0.12 : 0.08),
                          "&:hover": {
                            background: alpha(theme.palette.primary.main, isDark ? 0.16 : 0.11),
                          },
                        },
                      }}
                    >
                      <NavIcon icon={s.icon} isDark={isDark} />
                      <ListItemText
                        primary={s.title}
                        secondary={s.subtitle}
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
            </CardContent>
          </SoftCard>
        </Grid>

        <Grid size={{ xs: 12, md: 8.5, lg: 9 }}>
          <SoftCard>
            <CardContent sx={{ p: { xs: 2, md: 3 } }}>
              <Stack
                direction={{ xs: "column", sm: "row" }}
                spacing={1.25}
                sx={{ mb: 2.5, justifyContent: "space-between", alignItems: { sm: "center" } }}
              >
                <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }} >
                  <Box
                    sx={{
                      width: 46,
                      height: 46,
                      borderRadius: 3,
                      display: "grid",
                      placeItems: "center",
                      border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
                      background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                      "& svg": { fontSize: 22 },
                      flexShrink: 0,
                    }}
                  >
                    {activeMeta.icon}
                  </Box>
                  <Box>
                    <Typography variant="h6" sx={{ fontWeight: 950, letterSpacing: -0.2 }} >
                      {activeMeta.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {activeMeta.subtitle}
                    </Typography>
                  </Box>
                </Stack>

                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<RefreshOutlined />}
                  onClick={() =>
                    qc.invalidateQueries({
                      queryKey: active === "connectors" ? ["connectors"] : ["settings", "list", active],
                    })
                  }
                  sx={{ borderRadius: 2.5, textTransform: "none", fontWeight: 900, flexShrink: 0 }}
                >
                  Refresh
                </Button>
              </Stack>

              <Divider sx={{ opacity: isDark ? 0.18 : 0.45, mb: 2.5 }} />

              <SectionContent section={activeMeta} />
            </CardContent>
          </SoftCard>
        </Grid>
      </Grid>
    </Box>
    </Skeleton>
  );
}
