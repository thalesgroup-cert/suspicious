import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Box, Button, CircularProgress, IconButton, Stack, Switch, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import CheckCircle from "@mui/icons-material/CheckCircle";
import CloseOutlined from "@mui/icons-material/CloseOutlined";
import ErrorOutlined from "@mui/icons-material/ErrorOutlined";
import { useSnackbar } from "notistack";

import { relativeTime } from "@/features/settings/connectorConfig";
import { cleanDescription } from "@/features/settings/labels";
import { useAccent } from "@/features/settings/useAccent";
import { useMuted } from "@/features/settings/useMuted";
import { visuallyHidden } from "@/features/settings/components/a11y";
import { ConnectorMark } from "@/features/settings/components/ConnectorMark";
import { StatusLabel, connectorStatus } from "@/features/settings/components/StatusLabel";
import { setConnectorEnabled, type Connector } from "@/features/settings/components/connectors";
import { useConnectorTest } from "@/features/settings/components/useConnectorTest";
import { useToneColor } from "@/features/settings/components/useToneColor";

const CLAMP = { display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" } as const;

/**
 * A flat card (divider border, no shadow). The body is not a click target: the controls live in the footer, so nothing is nested
 * inside a clickable surface (Carbon tile guidance).
 */
export function ConnectorTile({
  connector,
  headingLevel = 3,
  onConfigure,
}: {
  connector: Connector;
  /** 3 when the grid sits straight under the section heading, 4 under a category heading. */
  headingLevel?: 3 | 4;
  onConfigure: (name: string) => void;
}) {
  const theme = useTheme();
  const accent = useAccent();
  const muted = useMuted();
  const toneColor = useToneColor();
  const queryClient = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  const { name } = connector;
  const status = connectorStatus(connector);
  const test = useConnectorTest(name);

  const toggle = useMutation({
    mutationFn: (enabled: boolean) => setConnectorEnabled(name, enabled),
    onSuccess: (c) => {
      queryClient.invalidateQueries({ queryKey: ["connectors"] });
      enqueueSnackbar(c.enabled ? `${c.name} enabled.` : `${c.name} disabled.`, { variant: c.enabled ? "success" : "info" });
    },
    onError: () => enqueueSnackbar("Failed to update connector.", { variant: "error" }),
  });

  const description = cleanDescription(connector.description ?? "");
  const since = relativeTime(connector.last_health_at, new Date());
  const border = theme.palette.divider;

  return (
    <Box component="li" sx={{ listStyle: "none", display: "flex", minWidth: 0 }}>
      <Box
        sx={{
          flex: 1,
          minWidth: 0,
          display: "flex",
          flexDirection: "column",
          gap: 1.5,
          p: 2,
          bgcolor: "background.paper",
          border: 1,
          borderColor: border,
          borderRadius: 2,
          transition: "transform 0.18s ease, border-color 0.18s ease",
          "&:focus-within": { borderColor: alpha(theme.palette.text.primary, 0.32) },
          // The lift is a transform, which the global reduced-motion rule (transition duration only) would not stop, so it is gated here.
          "@media (hover: hover) and (prefers-reduced-motion: no-preference)": {
            "&:hover": { transform: "translateY(-2px)", borderColor: alpha(theme.palette.text.primary, 0.32) },
          },
        }}
      >
        <Box data-tile-body sx={{ display: "flex", flexDirection: "column", gap: 1.5, minWidth: 0 }}>
          <Stack direction="row" spacing={2} sx={{ alignItems: "center", minWidth: 0 }}>
            <ConnectorMark name={name} size={48} tone={status.tone} />
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="subtitle1" component={`h${headingLevel}`} sx={{ fontWeight: 600, lineHeight: 1.3, overflowWrap: "anywhere" }}>
                {name}
              </Typography>
              <Typography variant="caption" sx={{ display: "block", color: muted }}>
                {connector.category || "Other"}
              </Typography>
            </Box>
          </Stack>
          <Typography variant="body2" sx={{ ...CLAMP, color: muted, lineHeight: 1.5, minHeight: "3em" }}>
            {description}
          </Typography>
          <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", columnGap: 1, flexWrap: "wrap" }}>
            <StatusLabel size="small" tone={status.tone} label={status.label} />
            {since !== "not checked yet" && (
              <Typography variant="caption" sx={{ color: muted }}>
                Checked {since}
              </Typography>
            )}
          </Stack>
        </Box>

        {/* The wrapper is always present so a screen reader sees the status block being added to a live region. */}
        <Box aria-live="polite">
          {test.result && (
            <Stack
              role="status"
              direction="row"
              spacing={1}
              sx={{ alignItems: "flex-start", p: 1, border: 1, borderColor: border, borderRadius: 1, bgcolor: alpha(theme.palette.text.primary, 0.03) }}
            >
              <ResultIcon ok={test.result.ok} color={toneColor(test.result.ok ? "ok" : "danger", 3)} />
              <Typography
                variant="caption"
                title={test.result.text}
                sx={{ flex: 1, minWidth: 0, overflowWrap: "anywhere", WebkitLineClamp: 4, WebkitBoxOrient: "vertical", display: "-webkit-box", overflow: "hidden" }}
              >
                Tested the saved configuration: {test.result.text}
              </Typography>
              <IconButton size="small" aria-label={`Dismiss test result for ${name}`} onClick={test.dismiss} sx={{ m: -0.5 }}>
                <CloseOutlined sx={{ fontSize: 16 }} />
              </IconButton>
            </Stack>
          )}
        </Box>

        <Stack direction="row" spacing={1} sx={{ mt: "auto", pt: 1.5, borderTop: 1, borderColor: border, alignItems: "center" }}>
          <Switch
            size="small"
            checked={connector.enabled}
            disabled={toggle.isPending}
            onChange={(e) => toggle.mutate(e.target.checked)}
            slotProps={{ input: { "aria-label": `Enable ${name}` } }}
          />
          <Box sx={{ flex: 1 }} />
          <Button
            size="small"
            variant="outlined"
            // aria-disabled, not disabled: the button keeps focus while the request runs.
            aria-disabled={test.pending}
            onClick={() => !test.pending && test.run()}
            startIcon={test.pending ? <CircularProgress size={14} color="inherit" /> : undefined}
            sx={{ color: "text.primary", borderColor: border, "&:hover": { borderColor: accent.mark } }}
          >
            {test.pending ? "Testing..." : "Test"}
            <Box component="span" sx={visuallyHidden}>{" "}{name}</Box>
          </Button>
          <Button size="small" variant="contained" disableElevation data-configure={name} onClick={() => onConfigure(name)}>
            Configure
            <Box component="span" sx={visuallyHidden}>{" "}{name}</Box>
          </Button>
        </Stack>
      </Box>
    </Box>
  );
}

function ResultIcon({ ok, color }: { ok: boolean; color: string }) {
  const Icon = ok ? CheckCircle : ErrorOutlined;
  return <Icon aria-hidden sx={{ fontSize: 16, mt: "2px", color, flexShrink: 0 }} />;
}
