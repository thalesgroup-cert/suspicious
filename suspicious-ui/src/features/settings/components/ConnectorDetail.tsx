import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  IconButton,
  Stack,
  Typography,
} from "@mui/material";
import { useTheme } from "@mui/material/styles";
import ArrowBackOutlined from "@mui/icons-material/ArrowBackOutlined";

import { Badge } from "@/shared/components/Badge";
import { useResultColors } from "@/styles/colorStore";
import { InnerCard, NavIcon } from "@/features/settings/components/cards";
import { ConfigFieldInput } from "@/features/settings/components/configFieldHelpers";
import {
  dottedGet,
  dottedSet,
  stripUnchangedSecrets,
} from "@/features/settings/components/configHelpers";
import {
  getConnectorStatusColor,
  getDeliveryStatusColor,
} from "@/features/settings/components/connectorColors";
import {
  CONNECTOR_ICONS,
  DEFAULT_CONNECTOR_ICON,
} from "@/features/settings/components/connectorIcons";
import {
  type Connector,
  getConnectorConfig,
  listDeliveries,
  putConnectorConfig,
  testConnector,
} from "@/features/settings/components/connectors";

const STATUS_LABEL: Record<Connector["status"], string> = {
  connected: "Connected",
  partial: "Incomplete",
  disabled: "Disabled",
};

export function ConnectorDetail({
  connector,
  onBack,
}: {
  connector: Connector;
  onBack?: () => void;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const queryClient = useQueryClient();
  const resultColors = useResultColors();
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const configQuery = useQuery({
    queryKey: ["connector-config", connector.name],
    queryFn: () => getConnectorConfig(connector.name),
  });

  const deliveriesQuery = useQuery({
    queryKey: ["connector-deliveries", connector.name],
    queryFn: () => listDeliveries(connector.name, 5),
  });

  const save = useMutation({
    mutationFn: (config: Record<string, unknown>) => putConnectorConfig(connector.name, config),
    onSuccess: () => {
      setDraft(null);
      setSaveError(null);
      queryClient.invalidateQueries({ queryKey: ["connector-config", connector.name] });
      queryClient.invalidateQueries({ queryKey: ["connectors"] });
    },
    onError: (err: unknown) => {
      const e = err as { response?: { data?: { errors?: Record<string, string> } } };
      const errs = e.response?.data?.errors;
      setSaveError(
        errs
          ? Object.entries(errs).map(([k, v]) => `${k}: ${v}`).join("; ")
          : "Failed to save configuration.",
      );
    },
  });

  const test = useMutation({
    mutationFn: () => testConnector(connector.name),
    onSuccess: (result) =>
      setTestResult(result.ok ? `OK — ${result.detail}` : `Failed — ${result.detail}`),
  });

  const config = draft ?? configQuery.data ?? {};
  const secretKeys = connector.config_schema
    .filter((f) => f.type === "secret")
    .map((f) => f.key);

  const Icon = CONNECTOR_ICONS[connector.name] ?? DEFAULT_CONNECTOR_ICON;
  const deliveries = deliveriesQuery.data ?? [];

  return (
    <InnerCard sx={{ p: { xs: 2, md: 2.5 } }}>
      <Stack direction="row" spacing={1.25} sx={{ alignItems: "flex-start", mb: 2 }}>
        {onBack && (
          <IconButton size="small" aria-label="Back to connector list" onClick={onBack}>
            <ArrowBackOutlined fontSize="small" />
          </IconButton>
        )}
        <NavIcon icon={<Icon fontSize="small" />} isDark={isDark} />
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
            <Typography variant="h6" sx={{ fontWeight: 950 }}>
              {connector.name}
            </Typography>
            <Chip size="small" label={connector.version} variant="outlined" />
            <Badge
              label={STATUS_LABEL[connector.status]}
              color={getConnectorStatusColor(connector.status, resultColors)}
            />
            {connector.last_health_ok !== null && (
              <Badge
                label={connector.last_health_ok ? "Healthy" : "Unhealthy"}
                color={connector.last_health_ok ? resultColors.safe.main : resultColors.dangerous.main}
              />
            )}
          </Stack>
          <Typography variant="body2" color="text.secondary">
            {connector.description}
          </Typography>
        </Box>
      </Stack>

      <Typography variant="overline" color="text.secondary" sx={{ display: "block", mb: 1 }}>
        Configuration
      </Typography>
      {configQuery.isError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load configuration.
        </Alert>
      )}
      {configQuery.isLoading && <CircularProgress size={18} sx={{ mb: 2, display: "block" }} />}
      {!configQuery.isLoading && !configQuery.isError && (
        <>
          <Stack spacing={1.5} sx={{ mb: 2 }}>
            {connector.config_schema.map((field) => (
              <ConfigFieldInput
                key={field.key}
                field={field}
                value={dottedGet(config, field.key)}
                onChange={(value) => {
                  const next = structuredClone(config);
                  dottedSet(next, field.key, value);
                  setDraft(next);
                }}
              />
            ))}
          </Stack>

          <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
            <Button
              size="small"
              variant="contained"
              disabled={!draft || save.isPending}
              onClick={() => draft && save.mutate(stripUnchangedSecrets(draft, secretKeys))}
            >
              Save
            </Button>
            <Button size="small" onClick={() => test.mutate()} disabled={test.isPending}>
              Test connection
            </Button>
          </Stack>
        </>
      )}

      {testResult && (
        <Alert
          sx={{ mb: 1.5 }}
          severity={testResult.startsWith("OK") ? "success" : "error"}
          onClose={() => setTestResult(null)}
        >
          {testResult}
        </Alert>
      )}
      {saveError && (
        <Alert sx={{ mb: 1.5 }} severity="error" onClose={() => setSaveError(null)}>
          {saveError}
        </Alert>
      )}

      <Typography variant="overline" color="text.secondary" sx={{ display: "block", mb: 1 }}>
        Recent deliveries
      </Typography>
      {deliveriesQuery.isError && (
        <Alert severity="error" sx={{ mb: 1 }}>
          Failed to load recent deliveries.
        </Alert>
      )}
      {deliveriesQuery.isLoading && <CircularProgress size={18} />}
      {!deliveriesQuery.isLoading && !deliveriesQuery.isError && deliveries.length === 0 && (
        <Typography variant="body2" color="text.disabled">
          No deliveries yet.
        </Typography>
      )}
      <Stack spacing={0.75}>
        {deliveries.map((delivery) => (
          <Stack key={delivery.id} direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <Box
              aria-label={`delivery status: ${delivery.status}`}
              sx={{
                width: 7,
                height: 7,
                borderRadius: "50%",
                background: getDeliveryStatusColor(delivery.status, resultColors),
                flexShrink: 0,
              }}
            />
            <Typography variant="caption" sx={{ flex: 1 }}>
              {delivery.event}
              {delivery.case_id ? ` · case #${delivery.case_id}` : ""}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {new Date(delivery.created_at).toLocaleString()}
            </Typography>
          </Stack>
        ))}
      </Stack>
    </InnerCard>
  );
}
