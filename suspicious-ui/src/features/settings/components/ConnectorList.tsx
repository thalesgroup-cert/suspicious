import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  Switch,
  Typography,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { useSnackbar } from "notistack";

import { useResultColors } from "@/styles/colorStore";
import { EmptyList, NavIcon } from "@/features/settings/components/cards";
import {
  CONNECTOR_ICONS,
  DEFAULT_CONNECTOR_ICON,
} from "@/features/settings/components/connectorIcons";
import { getConnectorStatusColor } from "@/features/settings/components/connectorColors";
import { setConnectorEnabled, type Connector } from "@/features/settings/components/connectors";

export function ConnectorList({
  connectors,
  loadErrors,
  selected,
  onSelect,
}: {
  connectors: Connector[];
  loadErrors: Record<string, string>;
  selected: string | null;
  onSelect: (name: string) => void;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const queryClient = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  const resultColors = useResultColors();

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

  if (connectors.length === 0) {
    return (
      <Stack spacing={1.5}>
        {errorEntries.map(([name, message]) => (
          <Alert key={name} severity="warning">
            Connector {name} failed to load: {message}
          </Alert>
        ))}
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
    <Stack spacing={1.5}>
      {errorEntries.map(([name, message]) => (
        <Alert key={name} severity="warning">
          Connector {name} failed to load: {message}
        </Alert>
      ))}
      {categories.map((category) => (
        <Box key={category}>
          <Typography
            variant="overline"
            color="text.secondary"
            sx={{ display: "block", mb: 0.5, px: 1, letterSpacing: "0.08em", fontSize: 11 }}
          >
            {category}
          </Typography>
          <List dense disablePadding>
            {(byCategory.get(category) ?? []).map((connector) => {
              const isSelected = selected === connector.name;
              const Icon = CONNECTOR_ICONS[connector.name] ?? DEFAULT_CONNECTOR_ICON;
              const dotColor = getConnectorStatusColor(connector.status, resultColors);
              return (
                <ListItemButton
                  key={connector.name}
                  selected={isSelected}
                  onClick={() => onSelect(connector.name)}
                  sx={{
                    borderRadius: 2.5,
                    mb: 0.5,
                    py: 0.75,
                    px: 1,
                    "&.Mui-selected": {
                      background: alpha(theme.palette.primary.main, isDark ? 0.12 : 0.08),
                      "&:hover": {
                        background: alpha(theme.palette.primary.main, isDark ? 0.16 : 0.11),
                      },
                    },
                  }}
                >
                  <NavIcon icon={<Icon fontSize="small" />} isDark={isDark} />
                  <ListItemText
                    primary={connector.name}
                    sx={{ ml: 1.25 }}
                    slotProps={{
                      primary: { sx: { fontWeight: isSelected ? 950 : 800, fontSize: 13.5 } },
                    }}
                  />
                  <Box
                    aria-label={`${connector.name} status: ${connector.status}`}
                    sx={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: dotColor,
                      flexShrink: 0,
                      mr: 1,
                    }}
                  />
                  <Switch
                    size="small"
                    checked={connector.enabled}
                    disabled={toggle.isPending}
                    onChange={(e) => {
                      e.stopPropagation();
                      toggle.mutate({ name: connector.name, enabled: e.target.checked });
                    }}
                    onClick={(e) => e.stopPropagation()}
                    slotProps={{ input: { "aria-label": `Enable ${connector.name}` } }}
                  />
                </ListItemButton>
              );
            })}
          </List>
        </Box>
      ))}
    </Stack>
  );
}
