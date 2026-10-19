import * as React from "react";
import { Box, Chip, Stack, Switch, Typography } from "@mui/material";
import { PowerSettingsNewOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSnackbar } from "notistack";

import { getFeederStatus, setFeederStatus } from "@/features/settings/api";
import FeederHealthBadge from "@/shared/components/FeederHealthBadge";
import { InnerCard } from "@/features/settings/components/cards";
import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";
import { readableOnTint } from "@/shared/lib/contrast";
import { useResultColors } from "@/styles/colorStore";

export function FeederPanel() {
  const qc = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const safe = useResultColors().safe.main;
  const [confirmOff, setConfirmOff] = React.useState(false);
  const switchInput = React.useRef<HTMLInputElement>(null);
  const refocus = React.useRef(false);

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

  // The switch is disabled while the request runs, which drops focus to <body>; give it back once it settles.
  React.useEffect(() => {
    if (!pending && refocus.current) {
      refocus.current = false;
      switchInput.current?.focus();
    }
  }, [pending]);
  // Text on the 12% tint must stay readable on either page background; the raw brand colour does not in light mode.
  const onTint = readableOnTint(safe, safe, 0.12, [theme.palette.background.paper, theme.palette.background.default]);

  return (
    <Stack spacing={2}>
      <InnerCard sx={{ p: 0, overflow: "hidden" }}>
        <Box
          sx={{
            height: 4,
            background: enabled ? safe : alpha(theme.palette.divider, 0.4),
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
                // action.hover is already translucent: alpha() on it would replace its alpha and paint a solid dark block.
                background: enabled
                  ? alpha(safe, 0.12)
                  : theme.palette.action.hover,
                border: `1px solid ${enabled ? alpha(safe, 0.3) : alpha(theme.palette.divider, isDark ? 0.18 : 0.5)}`,
                transition: "all .3s ease",
                "& svg": { fontSize: 24, color: enabled ? onTint : undefined, transition: "color .3s ease" },
              }}
            >
              <PowerSettingsNewOutlined />
            </Box>

            <Box>
              <Typography sx={{ fontWeight: 700, fontSize: 15 }} >Email feeder</Typography>
              <Typography variant="body2" color="text.secondary">
                Automatically ingest suspicious emails and create cases.
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1.5} sx={{ alignItems: "center", flexWrap: "wrap" }} >
            <FeederHealthBadge />
            {/* Text, not just colour: the state must read without seeing the tint. */}
            <Chip
              size="small"
              label={statusQuery.isLoading ? "…" : enabled ? "Enabled" : "Disabled"}
              sx={{
                fontWeight: 700,
                bgcolor: enabled
                  ? alpha(safe, 0.12)
                  : theme.palette.action.hover,
                color: enabled ? onTint : "text.secondary",
                border: `1px solid ${enabled ? alpha(safe, 0.3) : alpha(theme.palette.divider, 0.4)}`,
                transition: "all .3s ease",
              }}
            />
            <Switch
              checked={enabled}
              onChange={(e) => (e.target.checked ? toggleMutation.mutate(true) : setConfirmOff(true))}
              disabled={pending}
              color="success"
              slotProps={{ input: { "aria-label": "Email feeder", ref: switchInput } }}
            />
          </Stack>
        </Stack>
      </InnerCard>

      <InnerCard sx={{ p: 2 }}>
        <Typography variant="body2" color="text.secondary" sx={{ fontSize: 13 }}>
          When enabled, the feeder polls the configured mailbox and automatically creates
          new analysis cases for each suspicious message. Disabling it will stop ingestion
          immediately. Existing cases are unaffected.
        </Typography>
      </InnerCard>

      <ConfirmDialog
        open={confirmOff}
        title="Turn off the email feeder?"
        body="The feeder stops ingesting mail immediately. Existing cases are unaffected."
        confirmLabel="Turn off"
        destructive
        onConfirm={() => {
          setConfirmOff(false);
          refocus.current = true;
          toggleMutation.mutate(false);
        }}
        onCancel={() => setConfirmOff(false)}
      />
    </Stack>
  );
}
