import { useEffect, useId, useState } from "react";
import { useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, AlertTitle, Box, Button, Chip, CircularProgress, IconButton, Stack, Tab, Tabs, Typography } from "@mui/material";
import ArrowBackOutlined from "@mui/icons-material/ArrowBackOutlined";

import { useReportUnsaved } from "@/features/settings/unsaved";
import { cleanDescription } from "@/features/settings/labels";
import { relativeTime } from "@/features/settings/connectorConfig";
import { InnerCard } from "@/features/settings/components/cards";
import { ConnectorConfigForm } from "@/features/settings/components/ConnectorConfigForm";
import { ConnectorDeliveries } from "@/features/settings/components/ConnectorDeliveries";
import { ConnectorLogo } from "@/features/settings/components/ConnectorLogo";
import { ConnectorOverview } from "@/features/settings/components/ConnectorOverview";
import { StatusLabel, connectorStatus } from "@/features/settings/components/StatusLabel";
import {
  dottedSet,
  stripUnchangedSecrets,
} from "@/features/settings/components/configHelpers";
import {
  type Connector,
  getConnectorConfig,
  putConnectorConfig,
  testConnector,
} from "@/features/settings/components/connectors";

const TABS = [
  { value: "overview", label: "Overview" },
  { value: "configuration", label: "Configuration" },
  { value: "deliveries", label: "Deliveries" },
] as const;
type TabValue = (typeof TABS)[number]["value"];

const parseTab = (raw: string | null): TabValue => TABS.find((t) => t.value === raw)?.value ?? "overview";

function testFailureMessage(err: unknown): string {
  const response = (err as { response?: { status?: number; data?: { detail?: unknown; error?: unknown } } })
    .response;
  const message = response?.data?.detail ?? response?.data?.error;
  if (typeof message === "string" && message) return message;
  return response?.status ? `Connection test failed (HTTP ${response.status}).` : "Connection test failed.";
}

export function ConnectorDetail({
  connector,
  onBack,
  onDirtyChange,
}: {
  connector: Connector;
  onBack?: () => void;
  /** Lets the parent guard switching connector, which would otherwise drop the draft. */
  onDirtyChange?: (dirty: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const tab = parseTab(params.get("tab"));
  const ids = useId();
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [testAlert, setTestAlert] = useState<{ severity: "success" | "error"; text: string } | null>(
    null,
  );
  const hintId = useId();
  const testHintId = useId();
  const [saveError, setSaveError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  // The draft lives here, above the tab panels, so switching tabs never loses an edit.
  const configQuery = useQuery({
    queryKey: ["connector-config", connector.name],
    queryFn: () => getConnectorConfig(connector.name),
    enabled: tab === "configuration" || draft !== null,
  });

  const save = useMutation({
    mutationFn: (config: Record<string, unknown>) => putConnectorConfig(connector.name, config),
    onSuccess: (saved) => {
      // Write the saved config before dropping the draft, or the form flashes the old values until the refetch lands.
      queryClient.setQueryData(["connector-config", connector.name], saved);
      setDraft(null);
      setSaveError(null);
      setFieldErrors({});
      queryClient.invalidateQueries({ queryKey: ["connector-config", connector.name] });
      queryClient.invalidateQueries({ queryKey: ["connectors"] });
    },
    onError: (err: unknown) => {
      const e = err as { response?: { data?: { errors?: Record<string, string> } } };
      const errs = e.response?.data?.errors;
      setFieldErrors(errs ?? {});
      setSaveError(
        errs
          ? Object.entries(errs).map(([k, v]) => `${k}: ${v}`).join("; ")
          : "Failed to save configuration.",
      );
    },
  });

  const test = useMutation({
    mutationFn: () => {
      setTestAlert(null);
      return testConnector(connector.name);
    },
    onSuccess: (result) =>
      setTestAlert(
        result.ok
          ? { severity: "success", text: `OK: ${result.detail}` }
          : { severity: "error", text: `Failed: ${result.detail}` },
      ),
    // A rejected request (4xx/5xx, network) must not vanish: say what went wrong.
    onError: (err) => setTestAlert({ severity: "error", text: testFailureMessage(err) }),
  });

  const hasDraft = draft !== null;
  useReportUnsaved("connectors", hasDraft);
  useEffect(() => {
    onDirtyChange?.(hasDraft);
    return () => onDirtyChange?.(false);
  }, [hasDraft, onDirtyChange]);

  const saved = configQuery.data ?? {};
  const config = draft ?? saved;
  const secretKeys = connector.config_schema
    .filter((f) => f.type === "secret")
    .map((f) => f.key);

  const status = connectorStatus(connector);
  const description = cleanDescription(connector.description);
  const checked = connector.last_health_at
    ? `Last checked ${relativeTime(connector.last_health_at, new Date())}${connector.last_health_detail ? `: ${connector.last_health_detail}` : ""}`
    : "Not checked yet";

  const tabId = (v: TabValue) => `${ids}-tab-${v}`;
  const panelId = (v: TabValue) => `${ids}-panel-${v}`;

  const configLoaded = !configQuery.isLoading && !configQuery.isError;

  return (
    <InnerCard sx={{ p: { xs: 2, md: 2.5 } }}>
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "flex-start", mb: 1 }}>
        {onBack && (
          <IconButton size="small" aria-label="Back to connector list" onClick={onBack} sx={{ mt: 1 }}>
            <ArrowBackOutlined fontSize="small" />
          </IconButton>
        )}
        <ConnectorLogo name={connector.name} size={48} />
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap", rowGap: 0.5 }}>
            <Typography variant="h6" component="h3">
              {connector.name}
            </Typography>
            <Chip size="small" label={connector.version} variant="outlined" />
            <StatusLabel tone={status.tone} label={status.label} />
          </Stack>
          {description && (
            <Typography variant="body2" color="text.secondary">
              {description}
            </Typography>
          )}
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.25 }}>
            {checked}
          </Typography>
          {hasDraft && tab !== "configuration" && (
            <Typography variant="caption" color="warning.main" sx={{ display: "block", mt: 0.25 }}>
              Unsaved changes in Configuration
            </Typography>
          )}
        </Box>
      </Stack>

      <Tabs
        value={tab}
        onChange={(_e, value: TabValue) => {
          // replace: moving between tabs is not a page the Back button should walk through.
          const next = new URLSearchParams(params);
          next.set("tab", value);
          setParams(next, { replace: true });
        }}
        variant="scrollable"
        scrollButtons="auto"
        allowScrollButtonsMobile
        aria-label="Connector sections"
        sx={{ borderBottom: 1, borderColor: "divider", mb: 2.5 }}
      >
        {TABS.map((t) => (
          <Tab key={t.value} value={t.value} label={t.label} id={tabId(t.value)} aria-controls={panelId(t.value)} />
        ))}
      </Tabs>

      {TABS.map((t) => (
        <Box
          key={t.value}
          role="tabpanel"
          id={panelId(t.value)}
          aria-labelledby={tabId(t.value)}
          hidden={tab !== t.value}
        >
          {tab === t.value && t.value === "overview" && <ConnectorOverview connector={connector} />}

          {tab === t.value && t.value === "configuration" && (
            <>
              {configQuery.isError && <Alert severity="error">Failed to load configuration.</Alert>}
              {configQuery.isLoading && <CircularProgress size={18} sx={{ display: "block" }} />}
              {configLoaded && (
                <>
                  <ConnectorConfigForm
                    connector={connector}
                    config={config}
                    saved={saved}
                    errors={fieldErrors}
                    onChange={(field, value) => {
                      const next = structuredClone(config);
                      dottedSet(next, field.key, value);
                      setDraft(next);
                      setFieldErrors(({ [field.key]: _gone, ...rest }) => rest);
                    }}
                  />

                  <Box
                    data-panel-actions
                    sx={{
                      position: "sticky",
                      bottom: 0,
                      zIndex: 2,
                      mt: 3,
                      py: 1.5,
                      bgcolor: "background.paper",
                      borderTop: 1,
                      borderColor: "divider",
                    }}
                  >
                    {/* Inside the bar, not below it: a result under a sticky bar would sit off screen. */}
                    {testAlert && (
                      <Alert sx={{ mb: 1.5 }} severity={testAlert.severity} onClose={() => setTestAlert(null)}>
                        <AlertTitle>Tested the saved configuration</AlertTitle>
                        {testAlert.text}
                      </Alert>
                    )}
                    {saveError && (
                      <Alert sx={{ mb: 1.5 }} severity="error" onClose={() => setSaveError(null)}>
                        {saveError}
                      </Alert>
                    )}
                    <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap", rowGap: 1 }}>
                      <Button
                        variant="contained"
                        disabled={!draft || save.isPending}
                        aria-describedby={draft ? undefined : hintId}
                        onClick={() => draft && save.mutate(stripUnchangedSecrets(draft, secretKeys))}
                      >
                        Save changes
                      </Button>
                      <Button
                        variant="outlined"
                        onClick={() => test.mutate()}
                        disabled={test.isPending}
                        aria-describedby={draft ? testHintId : undefined}
                      >
                        Test connection
                      </Button>
                      {!draft && (
                        <Typography id={hintId} variant="caption" color="text.secondary">
                          No changes to save
                        </Typography>
                      )}
                      {draft && (
                        <Typography id={testHintId} variant="caption" color="text.secondary">
                          Test connection checks the saved configuration, not your unsaved changes.
                        </Typography>
                      )}
                    </Stack>
                  </Box>
                </>
              )}
            </>
          )}

          {tab === t.value && t.value === "deliveries" && <ConnectorDeliveries name={connector.name} />}
        </Box>
      ))}
    </InnerCard>
  );
}
