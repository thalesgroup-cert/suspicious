import { Box, Chip, Stack, Switch, Typography } from "@mui/material";
import { PowerSettingsNewOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSnackbar } from "notistack";

import { getFeederStatus, setFeederStatus } from "@/features/settings/api";
import FeederHealthBadge from "@/shared/components/FeederHealthBadge";
import { InnerCard } from "@/features/settings/components/cards";

export function FeederPanel() {
  const qc = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const statusQuery = useQuery({
    queryKey: ["settings", "email_feeder"],
    queryFn: getFeederStatus,
    retry: false,
  });

  const toggleMutation = useMutation({
    mutationFn: (enabled: boolean) => setFeederStatus(enabled),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["settings", "email_feeder"] });
      enqueueSnackbar(
        res.enabled ? "Email feeder enabled." : "Email feeder disabled.",
        { variant: res.enabled ? "success" : "info" }
      );
    },
    onError: () => enqueueSnackbar("Failed to update feeder status.", { variant: "error" }),
  });

  const enabled = statusQuery.data?.enabled ?? false;
  const pending = statusQuery.isLoading || toggleMutation.isPending;

  return (
    <Stack spacing={2}>
      <InnerCard sx={{ p: 0, overflow: "hidden" }}>
        <Box
          sx={{
            height: 4,
            background: enabled
              ? "linear-gradient(90deg, #22C55E, #16A34A)"
              : alpha(theme.palette.divider, 0.4),
            transition: "background .4s ease",
          }}
        />

        <Stack
          direction={{ xs: "column", sm: "row" }}
          spacing={2}
          sx={{ p: 2.5, alignItems: { sm: "center" }, justifyContent: "space-between" }}
        >
          <Stack direction="row" spacing={1.75} sx={{ alignItems: "center" }} >
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 3,
                display: "grid",
                placeItems: "center",
                background: enabled
                  ? alpha("#22C55E", 0.12)
                  : alpha(theme.palette.action.hover, 0.5),
                border: `1px solid ${enabled ? alpha("#22C55E", 0.3) : alpha(theme.palette.divider, isDark ? 0.18 : 0.5)}`,
                transition: "all .3s ease",
                "& svg": { fontSize: 24, color: enabled ? "#22C55E" : undefined, transition: "color .3s ease" },
              }}
            >
              <PowerSettingsNewOutlined />
            </Box>

            <Box>
              <Typography sx={{ fontWeight: 950, fontSize: 15 }} >Email feeder</Typography>
              <Typography variant="body2" color="text.secondary">
                Automatically ingest suspicious emails and create cases.
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1.5} sx={{ alignItems: "center", flexWrap: "wrap" }} >
            <FeederHealthBadge />
            <Chip
              size="small"
              label={pending ? "…" : enabled ? "Running" : "Stopped"}
              sx={{
                fontWeight: 900,
                bgcolor: enabled
                  ? alpha("#22C55E", 0.12)
                  : alpha(theme.palette.action.hover, 0.6),
                color: enabled ? "#22C55E" : "text.secondary",
                border: `1px solid ${enabled ? alpha("#22C55E", 0.3) : alpha(theme.palette.divider, 0.4)}`,
                transition: "all .3s ease",
              }}
            />
            <Switch
              checked={enabled}
              onChange={(e) => toggleMutation.mutate(e.target.checked)}
              disabled={pending}
              color="success"
            />
          </Stack>
        </Stack>
      </InnerCard>

      <InnerCard sx={{ p: 2 }}>
        <Typography variant="body2" color="text.secondary" sx={{ fontSize: 13 }}>
          When enabled, the feeder polls the configured mailbox and automatically creates
          new analysis cases for each suspicious message. Disabling it will stop ingestion
          immediately — existing cases are unaffected.
        </Typography>
      </InnerCard>
    </Stack>
  );
}
