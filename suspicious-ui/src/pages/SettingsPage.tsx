import { Alert, Box, Button, CardContent, CircularProgress, Divider, Grid, Stack, Typography } from "@mui/material";
import { RefreshOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Navigate, useNavigate, useParams } from "react-router";
import { Skeleton } from "boneyard-js/react";

import { getMe, type Me } from "@/api/auth";
import { SoftCard } from "@/features/settings/components/cards";
import { SettingsNav } from "@/features/settings/components/SettingsNav";
import { StatusStrip } from "@/features/settings/components/StatusStrip";
import { SECTIONS, SectionContent, parseSection } from "@/features/settings/components/sections";
import { UnsavedProvider, useUnsavedKeys } from "@/features/settings/unsaved";

// Query roots the header Refresh covers: lists and scoring live under "settings", the feeder health chip under "feeder".
const REFRESH_ROOTS = new Set(["settings", "connectors", "connector-config", "connector-deliveries", "feeder"]);

function SettingsBody() {
  const qc = useQueryClient();
  const theme = useTheme();
  const navigate = useNavigate();
  const unsaved = useUnsavedKeys();
  const { section } = useParams();

  const meQuery = useQuery<Me>({ queryKey: ["me"], queryFn: getMe, retry: false });
  const me = meQuery.data;
  const groups = me?.groups ?? [];
  const isAllowed = groups.includes("Admin") || groups.includes("CERT");

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

  const active = parseSection(section);
  // Bare /settings redirects too, so the first nav item is a real URL and clicking it is not a navigation.
  if (active === null) {
    return <Navigate to={`/settings/${SECTIONS[0].key}`} replace />;
  }
  const activeMeta = SECTIONS.find((s) => s.key === active)!;

  return (
    <Skeleton name="settings-page" loading={meQuery.isPending} animate="shimmer">
      <Box sx={{ p: { xs: 1.5, md: 2.5 } }}>
        <Stack
          direction={{ xs: "column", md: "row" }}
          spacing={1.5}
          sx={{ mb: 2, justifyContent: "space-between", alignItems: { md: "center" } }}
        >
          <Box>
            <Typography variant="pageTitle" component="h1">
              Settings
            </Typography>
            <Typography color="text.secondary">
              Manage detection lists, access, the email feeder, analyzer scoring and connectors.
            </Typography>
          </Box>
          <Button
            variant="outlined"
            startIcon={<RefreshOutlined />}
            onClick={() =>
              qc.invalidateQueries({
                predicate: (q) => REFRESH_ROOTS.has(String(q.queryKey[0])),
              })
            }
            sx={{ alignSelf: { xs: "flex-start", md: "center" } }}
          >
            Refresh
          </Button>
        </Stack>

        <StatusStrip />

        <Grid container spacing={2} sx={{ alignItems: "flex-start" }}>
          <Grid size={{ xs: 12, md: 3.5, lg: 3 }}>
            <SettingsNav
              active={activeMeta.key}
              unsaved={unsaved}
              onNavigate={(key) => navigate(`/settings/${key}`)}
            />
          </Grid>

          <Grid size={{ xs: 12, md: 8.5, lg: 9 }}>
            <SoftCard>
              <CardContent sx={{ p: { xs: 2, md: 3 } }}>
                <Stack direction="row" spacing={1.5} sx={{ mb: 2.5, alignItems: "center" }}>
                  <Box
                    sx={{
                      width: 46,
                      height: 46,
                      borderRadius: 3,
                      display: "grid",
                      placeItems: "center",
                      border: `1px solid ${theme.palette.divider}`,
                      background: alpha(theme.palette.primary.main, 0.1),
                      "& svg": { fontSize: 22 },
                      flexShrink: 0,
                    }}
                  >
                    {activeMeta.icon}
                  </Box>
                  <Box>
                    <Typography variant="h6" component="h2">
                      {activeMeta.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {activeMeta.subtitle}
                    </Typography>
                  </Box>
                </Stack>

                <Divider sx={{ mb: 2.5 }} />

                <SectionContent section={activeMeta} />
              </CardContent>
            </SoftCard>
          </Grid>
        </Grid>
      </Box>
    </Skeleton>
  );
}

export default function SettingsPage() {
  return (
    <UnsavedProvider>
      <SettingsBody />
    </UnsavedProvider>
  );
}
