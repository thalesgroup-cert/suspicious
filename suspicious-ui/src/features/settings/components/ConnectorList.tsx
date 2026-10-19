import { useEffect, useRef } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert, Box, List, ListItem, ListItemButton, Stack, Switch, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { useSnackbar } from "notistack";

import { EmptyList } from "@/features/settings/components/cards";
import { ConnectorLogo } from "@/features/settings/components/ConnectorLogo";
import { StatusLabel, connectorStatus } from "@/features/settings/components/StatusLabel";
import { setConnectorEnabled, type Connector } from "@/features/settings/components/connectors";
import { cleanDescription } from "@/features/settings/labels";

export function ConnectorList({
  connectors,
  loadErrors,
  selected,
  onSelect,
  focusRow = null,
}: {
  connectors: Connector[];
  loadErrors: Record<string, string>;
  selected: string | null;
  onSelect: (name: string) => void;
  /** On a phone the list replaces the detail: Back hands focus to the row that was open. */
  focusRow?: string | null;
}) {
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focusRow) root.current?.querySelector<HTMLElement>(`[data-connector="${CSS.escape(focusRow)}"]`)?.focus();
    // Once, when the list comes back; later renders must not pull focus again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const queryClient = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();

  const toggle = useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) =>
      setConnectorEnabled(name, enabled),
    onSuccess: (connector) => {
      queryClient.invalidateQueries({ queryKey: ["connectors"] });
      enqueueSnackbar(
        connector.enabled ? `${connector.name} enabled.` : `${connector.name} disabled.`,
        { variant: connector.enabled ? "success" : "info" },
      );
    },
    onError: () => enqueueSnackbar("Failed to update connector.", { variant: "error" }),
  });

  const errorEntries = Object.entries(loadErrors);
  const loadAlerts = errorEntries.map(([name, message]) => (
    <Alert key={name} severity="warning">
      Connector {name} failed to load: {message}
    </Alert>
  ));

  if (connectors.length === 0) {
    return (
      <Stack spacing={1.5}>
        {loadAlerts}
        <EmptyList message="No connectors discovered." />
      </Stack>
    );
  }

  const byCategory = new Map<string, Connector[]>();
  for (const c of connectors) {
    const key = c.category || "Other";
    byCategory.set(key, [...(byCategory.get(key) ?? []), c]);
  }
  const categories = [...byCategory.keys()].sort((a, b) => a.localeCompare(b));

  return (
    <Stack spacing={2} ref={root}>
      {loadAlerts}
      {categories.map((category) => (
        <Box key={category}>
          <Typography variant="overline" color="text.secondary" sx={{ display: "block", mb: 0.5, px: 1 }}>
            {category}
          </Typography>
          <List disablePadding>
            {(byCategory.get(category) ?? []).map((connector) => {
              const isSelected = selected === connector.name;
              const status = connectorStatus(connector);
              const description = cleanDescription(connector.description);
              return (
                // The switch sits beside the row button, not inside it: a control nested in a button is invalid and unreliable for assistive tech.
                <ListItem
                  key={connector.name}
                  disablePadding
                  sx={{ mb: 0.5 }}
                  secondaryAction={
                    <Switch
                      size="small"
                      checked={connector.enabled}
                      disabled={toggle.isPending}
                      onChange={(e) => toggle.mutate({ name: connector.name, enabled: e.target.checked })}
                      slotProps={{ input: { "aria-label": `Enable ${connector.name}` } }}
                    />
                  }
                >
                  <ListItemButton
                    selected={isSelected}
                    data-connector={connector.name}
                    aria-current={isSelected ? "true" : undefined}
                    onClick={() => onSelect(connector.name)}
                    sx={{
                      alignItems: "flex-start",
                      gap: 1.5,
                      borderRadius: 2,
                      py: 1,
                      pl: 1,
                      // Room for the switch, which is positioned over the row end.
                      pr: 8,
                      "&.Mui-selected": {
                        background: alpha(theme.palette.primary.main, isDark ? 0.16 : 0.08),
                        "&:hover": { background: alpha(theme.palette.primary.main, isDark ? 0.2 : 0.12) },
                      },
                    }}
                  >
                    <ConnectorLogo name={connector.name} size={40} />
                    <Box sx={{ minWidth: 0, flex: 1 }}>
                      <Typography variant="subtitle2" component="span" sx={{ display: "block", overflowWrap: "anywhere" }}>
                        {connector.name}
                      </Typography>
                      {description && (
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{
                            display: "-webkit-box",
                            WebkitLineClamp: 2,
                            WebkitBoxOrient: "vertical",
                            overflow: "hidden",
                          }}
                        >
                          {description}
                        </Typography>
                      )}
                      <Box sx={{ mt: 0.5 }}>
                        <StatusLabel size="small" tone={status.tone} label={status.label} />
                      </Box>
                    </Box>
                  </ListItemButton>
                </ListItem>
              );
            })}
          </List>
        </Box>
      ))}
    </Stack>
  );
}
