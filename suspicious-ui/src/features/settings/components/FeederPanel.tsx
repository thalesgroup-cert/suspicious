import * as React from "react";
import { Box, Stack, Switch, Typography } from "@mui/material";
import { PowerSettingsNewOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSnackbar } from "notistack";

import { getFeederStatus, setFeederStatus } from "@/features/settings/api";
import { feederHealthStatus, useFeederHealth } from "@/features/settings/useFeederHealth";
import { relativeTime } from "@/features/settings/connectorConfig";
import { FactList, type Fact } from "@/features/settings/components/FactList";
import { StatusLabel } from "@/features/settings/components/StatusLabel";
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

  const healthQuery = useFeederHealth();
  const health = healthQuery.data;
  const healthLabel = feederHealthStatus(healthQuery);

  // Only what the payload carries: an unreachable feeder is reported with zeroed counters that are not real readings.
  const facts: Fact[] = [];
  const polled = health?.last_successful_poll ? new Date(health.last_successful_poll * 1000) : null;
  // An absurd epoch gives an Invalid Date whose toISOString throws; leave the row out instead.
  if (polled && Number.isFinite(polled.getTime())) {
    const d = polled;
    facts.push({
      key: "Last poll",
      value: (
        <time dateTime={d.toISOString()} title={d.toLocaleString()}>
          {relativeTime(d.toISOString(), new Date())}
        </time>
      ),
    });
  }
  if (health?.online) {
    if (typeof health.emails_processed_total === "number") facts.push({ key: "Emails processed", value: health.emails_processed_total });
    if (typeof health.errors_total === "number") facts.push({ key: "Errors", value: health.errors_total });
  }
  if (!health?.online && health?.error) facts.push({ key: "Reason", value: health.error });

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
          direction="row"
          spacing={2}
          sx={{ p: 2.5, pb: 1.5, alignItems: "center", justifyContent: "space-between" }}
        >
          <Stack direction="row" spacing={1.75} sx={{ alignItems: "center", minWidth: 0 }} >
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

          <Switch
            checked={enabled}
            onChange={(e) => (e.target.checked ? toggleMutation.mutate(true) : setConfirmOff(true))}
            disabled={pending}
            color="success"
            sx={{ flexShrink: 0 }}
            slotProps={{ input: { "aria-label": "Email feeder", ref: switchInput } }}
          />
        </Stack>

        <Stack direction="row" sx={{ px: 2.5, pb: 2, columnGap: 3, rowGap: 0.5, flexWrap: "wrap" }}>
          <StatusLabel
            tone={statusQuery.isLoading ? "neutral" : enabled ? "ok" : "neutral"}
            label={statusQuery.isLoading ? "Loading" : enabled ? "Enabled" : "Disabled"}
          />
          <StatusLabel tone={healthLabel.tone} label={healthLabel.label} />
        </Stack>

        {facts.length > 0 && (
          <Box sx={{ px: 2.5, borderTop: 1, borderColor: "divider" }}>
            <FactList items={facts} />
          </Box>
        )}

        <Typography variant="body2" color="text.secondary" sx={{ px: 2.5, py: 2, borderTop: 1, borderColor: "divider" }}>
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
