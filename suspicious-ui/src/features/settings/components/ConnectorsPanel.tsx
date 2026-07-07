import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Stack,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import BlockOutlined from "@mui/icons-material/BlockOutlined";
import CheckCircleOutlined from "@mui/icons-material/CheckCircleOutlined";
import EmailOutlined from "@mui/icons-material/EmailOutlined";
import ExtensionOutlined from "@mui/icons-material/ExtensionOutlined";
import HubOutlined from "@mui/icons-material/HubOutlined";
import ShareOutlined from "@mui/icons-material/ShareOutlined";
import VisibilityOutlined from "@mui/icons-material/VisibilityOutlined";
import WarningAmberOutlined from "@mui/icons-material/WarningAmberOutlined";
import type { SvgIconProps } from "@mui/material";
import { useState } from "react";
import type { ComponentType } from "react";

import {
  type ConfigField,
  type Connector,
  getConnectorConfig,
  listConnectors,
  putConnectorConfig,
  setConnectorEnabled,
  testConnector,
} from "./connectors";

type IconType = ComponentType<SvgIconProps>;

const CONNECTOR_ICONS: Record<string, IconType> = {
  thehive: HubOutlined,
  misp: ShareOutlined,
  watcher: VisibilityOutlined,
  smtp_notify: EmailOutlined,
};

const STATUS_CHIP: Record<
  Connector["status"],
  { label: string; color: "success" | "warning" | "default" }
> = {
  connected: { label: "Connected", color: "success" },
  partial: { label: "Incomplete", color: "warning" },
  disabled: { label: "Disabled", color: "default" },
};

function dottedGet(obj: Record<string, unknown>, key: string): unknown {
  return key.split(".").reduce<unknown>(
    (node, part) =>
      node && typeof node === "object" ? (node as Record<string, unknown>)[part] : undefined,
    obj,
  );
}

function dottedSet(obj: Record<string, unknown>, key: string, value: unknown) {
  const parts = key.split(".");
  let node = obj;
  for (const part of parts.slice(0, -1)) {
    node[part] = (node[part] as Record<string, unknown>) ?? {};
    node = node[part] as Record<string, unknown>;
  }
  node[parts[parts.length - 1]] = value;
}

function ConfigFieldInput({
  field,
  value,
  onChange,
}: {
  field: ConfigField;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  if (field.type === "secret") {
    return (
      <TextField
        size="small"
        fullWidth
        type="password"
        label={field.key}
        value={typeof value === "string" && value !== "********" ? value : ""}
        placeholder="********"
        helperText="Leave blank to keep the current secret"
        autoComplete="new-password"
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }
  if (field.type === "bool") {
    return (
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
        <Switch checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />
        <Typography variant="body2">{field.key}</Typography>
      </Stack>
    );
  }
  return (
    <TextField
      size="small"
      fullWidth
      label={field.key}
      required={field.required}
      type={field.type === "int" ? "number" : "text"}
      value={value ?? ""}
      helperText={field.help}
      onChange={(e) =>
        onChange(field.type === "int" ? Number(e.target.value) : e.target.value)
      }
    />
  );
}

function KpiTile({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  icon: IconType;
  color: "success.main" | "warning.main" | "text.secondary";
}) {
  return (
    <Card variant="outlined" sx={{ flex: 1, minWidth: 140 }}>
      <CardContent sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
        <Icon sx={{ color, fontSize: 32 }} />
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ textTransform: "uppercase" }}>
            {label}
          </Typography>
          <Typography variant="h6">{value}</Typography>
        </Box>
      </CardContent>
    </Card>
  );
}

function ConnectorCard({ connector }: { connector: Connector }) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const configQuery = useQuery({
    queryKey: ["connector-config", connector.name],
    queryFn: () => getConnectorConfig(connector.name),
  });

  const toggle = useMutation({
    mutationFn: (enabled: boolean) => setConnectorEnabled(connector.name, enabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["connectors"] }),
  });

  const save = useMutation({
    mutationFn: (config: Record<string, unknown>) =>
      putConnectorConfig(connector.name, config),
    onSuccess: () => {
      setDraft(null);
      setSaveError(null);
      queryClient.invalidateQueries({
        queryKey: ["connector-config", connector.name],
      });
      queryClient.invalidateQueries({ queryKey: ["connectors"] });
    },
    onError: (err: unknown) => {
      const e = err as { response?: { data?: { errors?: Record<string, string> } } };
      const errs = e.response?.data?.errors;
      setSaveError(
        errs ? Object.entries(errs).map(([k, v]) => `${k}: ${v}`).join("; ")
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

  function stripUnchangedSecrets(cfg: Record<string, unknown>) {
    const out = structuredClone(cfg);
    for (const key of secretKeys) {
      const current = dottedGet(out, key);
      if (current === "" || current === "********" || current == null) {
        const parts = key.split(".");
        let node: Record<string, unknown> | undefined = out;
        for (const part of parts.slice(0, -1)) {
          node = node?.[part] as Record<string, unknown> | undefined;
          if (!node) break;
        }
        if (node) delete node[parts[parts.length - 1]];
      }
    }
    return out;
  }

  const Icon = CONNECTOR_ICONS[connector.name] ?? ExtensionOutlined;
  const statusChip = STATUS_CHIP[connector.status];

  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
          <Icon fontSize="small" color="action" />
          <Typography variant="h6">{connector.name}</Typography>
          <Chip size="small" label={connector.version} variant="outlined" />
          <Chip size="small" color={statusChip.color} label={statusChip.label} />
          {connector.last_health_ok !== null && (
            <Chip
              size="small"
              color={connector.last_health_ok ? "success" : "error"}
              label={connector.last_health_ok ? "Healthy" : "Unhealthy"}
            />
          )}
          <Box sx={{ flexGrow: 1 }} />
          <Switch
            checked={connector.enabled}
            onChange={(e) => toggle.mutate(e.target.checked)}
            slotProps={{ input: { "aria-label": `Enable ${connector.name}` } }}
          />
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {connector.description}
        </Typography>
        <Stack spacing={1.5}>
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
        <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
          <Button
            size="small"
            variant="contained"
            disabled={!draft || save.isPending}
            onClick={() => draft && save.mutate(stripUnchangedSecrets(draft))}
          >
            Save
          </Button>
          <Button size="small" onClick={() => test.mutate()} disabled={test.isPending}>
            Test connection
          </Button>
        </Stack>
        {testResult && (
          <Alert
            sx={{ mt: 1 }}
            severity={testResult.startsWith("OK") ? "success" : "error"}
            onClose={() => setTestResult(null)}
          >
            {testResult}
          </Alert>
        )}
        {saveError && (
          <Alert sx={{ mt: 1 }} severity="error" onClose={() => setSaveError(null)}>
            {saveError}
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

export function ConnectorsPanel() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["connectors"],
    queryFn: listConnectors,
  });

  if (isLoading) return <CircularProgress size={24} />;
  if (error) return <Alert severity="error">Failed to load connectors.</Alert>;

  const connectors = data?.connectors ?? [];
  const kpi = {
    connected: connectors.filter((c) => c.status === "connected").length,
    partial: connectors.filter((c) => c.status === "partial").length,
    disabled: connectors.filter((c) => c.status === "disabled").length,
  };

  const byCategory = new Map<string, Connector[]>();
  for (const c of connectors) {
    const key = c.category || "Other";
    byCategory.set(key, [...(byCategory.get(key) ?? []), c]);
  }
  const categories = [...byCategory.keys()].sort((a, b) => a.localeCompare(b));

  return (
    <Stack spacing={2}>
      <Stack direction="row" spacing={2} sx={{ flexWrap: "wrap" }}>
        <KpiTile label="Connected" value={kpi.connected} icon={CheckCircleOutlined} color="success.main" />
        <KpiTile label="Incomplete" value={kpi.partial} icon={WarningAmberOutlined} color="warning.main" />
        <KpiTile label="Disabled" value={kpi.disabled} icon={BlockOutlined} color="text.secondary" />
      </Stack>

      {Object.entries(data?.load_errors ?? {}).map(([name, message]) => (
        <Alert key={name} severity="warning">
          Connector {name} failed to load: {message}
        </Alert>
      ))}

      {categories.map((category) => (
        <Box key={category}>
          <Typography
            variant="overline"
            color="text.secondary"
            sx={{ display: "block", mb: 1, letterSpacing: "0.08em" }}
          >
            {category}
          </Typography>
          <Stack spacing={2}>
            {(byCategory.get(category) ?? []).map((connector) => (
              <ConnectorCard key={connector.name} connector={connector} />
            ))}
          </Stack>
        </Box>
      ))}
    </Stack>
  );
}
