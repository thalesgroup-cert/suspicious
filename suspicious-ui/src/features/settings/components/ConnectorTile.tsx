import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Box, Button, CircularProgress, IconButton, Stack, Switch, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import CheckCircle from "@mui/icons-material/CheckCircle";
import CloseOutlined from "@mui/icons-material/CloseOutlined";
import ErrorOutlined from "@mui/icons-material/ErrorOutlined";
import ExpandMore from "@mui/icons-material/ExpandMore";
import { useSnackbar } from "notistack";

import { relativeTime } from "@/features/settings/connectorConfig";
import { cleanDescription } from "@/features/settings/labels";
import { useAccent } from "@/features/settings/useAccent";
import { useMuted } from "@/features/settings/useMuted";
import { visuallyHidden } from "@/features/settings/components/a11y";
import { ConnectorMark } from "@/features/settings/components/ConnectorMark";
import { StatusLabel, connectorStatus } from "@/features/settings/components/StatusLabel";
import { setConnectorEnabled, type Connector } from "@/features/settings/components/connectors";
import { useConnectorTest, type TestResult } from "@/features/settings/components/useConnectorTest";
import { useToneColor } from "@/features/settings/components/useToneColor";

const CLAMP = { display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" } as const;

/**
 * A flat card (divider border, no shadow). The body is not a click target: the controls live in the footer, so nothing is nested
 * inside a clickable surface (Carbon tile guidance).
 */
export function ConnectorTile({
  connector,
  headingLevel = 3,
  testResult,
  onTestResult,
  onConfigure,
}: {
  connector: Connector;
  /** Held by the gallery, not here: a filter or the grouping can unmount this tile while its result is still wanted. */
  testResult: TestResult | null;
  onTestResult: (name: string, result: TestResult | null) => void;
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
  const test = useConnectorTest(name, { result: testResult, set: (r) => onTestResult(name, r) });

  const toggle = useMutation({
    mutationFn: (enabled: boolean) => setConnectorEnabled(name, enabled),
    onSuccess: (c) => {
      queryClient.invalidateQueries({ queryKey: ["connectors"] });
      // The investigation page decides whether to offer "Push to TheHive" from this cache.
      queryClient.invalidateQueries({ queryKey: ["enabledConnectors"] });
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

        {/* The one live region of the tile: always mounted and empty until a result arrives, so a screen reader hears it fill. */}
        <Box role="status">
          {test.result && <ResultBlock name={name} result={test.result} onDismiss={test.dismiss} />}
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

// Long enough that the four-line clamp is likely to cut it; the full text is always in the DOM and the button only lifts the clamp.
const LONG_RESULT = 150;

function ResultBlock({ name, result, onDismiss }: { name: string; result: TestResult; onDismiss: () => void }) {
  const theme = useTheme();
  const toneColor = useToneColor();
  const [expanded, setExpanded] = useState(false);
  const text = `Tested the saved configuration: ${result.text}`;
  return (
    <Box sx={{ p: 1, border: 1, borderColor: "divider", borderRadius: 1, bgcolor: alpha(theme.palette.text.primary, 0.03) }}>
      <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start" }}>
        <ResultIcon ok={result.ok} color={toneColor(result.ok ? "ok" : "danger", 3)} />
        <Typography
          variant="caption"
          sx={{
            flex: 1,
            minWidth: 0,
            overflowWrap: "anywhere",
            display: "-webkit-box",
            WebkitBoxOrient: "vertical",
            WebkitLineClamp: expanded ? "none" : 4,
            overflow: expanded ? "visible" : "hidden",
          }}
        >
          {text}
        </Typography>
        <IconButton size="small" aria-label={`Dismiss test result for ${name}`} onClick={onDismiss} sx={{ m: -0.5 }}>
          <CloseOutlined sx={{ fontSize: 16 }} />
        </IconButton>
      </Stack>
      {text.length > LONG_RESULT && (
        <Button
          size="small"
          variant="text"
          aria-expanded={expanded}
          onClick={() => setExpanded((v) => !v)}
          endIcon={<ExpandMore sx={{ transform: expanded ? "rotate(180deg)" : "none" }} />}
          sx={{ mt: 0.5, ml: 3, p: 0, minWidth: 0, color: "text.primary", textDecoration: "underline" }}
        >
          Show full result
          <Box component="span" sx={visuallyHidden}>{" "}for {name}</Box>
        </Button>
      )}
    </Box>
  );
}

function ResultIcon({ ok, color }: { ok: boolean; color: string }) {
  const Icon = ok ? CheckCircle : ErrorOutlined;
  return <Icon aria-hidden sx={{ fontSize: 16, mt: "2px", color, flexShrink: 0 }} />;
}
