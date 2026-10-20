import { useEffect, useId, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Box, Button, Chip, CircularProgress, Drawer, IconButton, Stack, Tab, Tabs, Typography, useMediaQuery } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import CloseOutlined from "@mui/icons-material/CloseOutlined";

import { ensureContrast, flatten } from "@/shared/lib/contrast";
import { ActionBar } from "@/features/settings/components/PanelSection";
import { useReportUnsaved } from "@/features/settings/unsaved";
import { useAccent } from "@/features/settings/useAccent";
import { useMuted } from "@/features/settings/useMuted";
import { missingRequired, relativeTime } from "@/features/settings/connectorConfig";
import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";
import { ConnectorConfigForm } from "@/features/settings/components/ConnectorConfigForm";
import { ConnectorDeliveries } from "@/features/settings/components/ConnectorDeliveries";
import { ConnectorMark } from "@/features/settings/components/ConnectorMark";
import { ConnectorOverview } from "@/features/settings/components/ConnectorOverview";
import { SetupChecklist } from "@/features/settings/components/SetupChecklist";
import { StatusLabel, connectorStatus } from "@/features/settings/components/StatusLabel";
import { useConnectorTest } from "@/features/settings/components/useConnectorTest";
import { dottedSet, stripUnchangedSecrets } from "@/features/settings/components/configHelpers";
import { type Connector, getConnectorConfig, putConnectorConfig } from "@/features/settings/components/connectors";

const TABS = [
  { value: "overview", label: "Overview" },
  { value: "configuration", label: "Configuration" },
  { value: "deliveries", label: "Deliveries" },
] as const;
type TabValue = (typeof TABS)[number]["value"];

const parseTab = (raw: string | null): TabValue => TABS.find((t) => t.value === raw)?.value ?? "overview";

/**
 * Everything about one connector in a right-hand drawer (full screen below md): header, Overview / Configuration / Deliveries,
 * and the Save / Test bar as the footer. Closing by the button, Esc or the backdrop asks first when there is a draft.
 */
export function ConnectorDrawer({
  connector,
  open = true,
  onClose,
  onExited,
  onDirtyChange,
  disableAutoFocus = false,
}: {
  connector: Connector;
  open?: boolean;
  /** Called once closing is allowed (no draft, or the user chose Discard). */
  onClose: () => void;
  /** After the slide-out has finished, so the parent can drop the connector. */
  onExited?: () => void;
  /** Lets the parent guard switching connector, which would otherwise drop the draft. */
  onDirtyChange?: (dirty: boolean) => void;
  /** A deep link opens the drawer on load; the page then keeps focus instead of having it taken. */
  disableAutoFocus?: boolean;
}) {
  const queryClient = useQueryClient();
  const theme = useTheme();
  const accent = useAccent();
  const muted = useMuted();
  const isPhone = useMediaQuery(theme.breakpoints.down("md"), { noSsr: true });
  const [params, setParams] = useSearchParams();
  const tab = parseTab(params.get("tab"));
  const ids = useId();
  const titleId = `${ids}-title`;
  const hintId = `${ids}-hint`;
  const testHintId = `${ids}-test-hint`;
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [confirmClose, setConfirmClose] = useState(false);
  const [savedNotice, setSavedNotice] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const test = useConnectorTest(connector.name);

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
      setSavedNotice(true);
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

  const hasDraft = draft !== null;
  useReportUnsaved("connectors", hasDraft);
  useEffect(() => {
    onDirtyChange?.(hasDraft);
    return () => onDirtyChange?.(false);
  }, [hasDraft, onDirtyChange]);

  const requestClose = () => (hasDraft ? setConfirmClose(true) : onClose());

  // After a deep link the page keeps focus (disableAutoFocus), and the modal only hears Esc from inside itself.
  // While focus is on the page body, Esc still has to close the drawer. A confirm dialog on top holds focus itself.
  const closeRef = useRef(requestClose);
  closeRef.current = requestClose;
  useEffect(() => {
    if (!open || !disableAutoFocus) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && document.activeElement === document.body) closeRef.current();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, disableAutoFocus]);

  const saved = configQuery.data ?? {};
  const config = draft ?? saved;
  const secretKeys = connector.config_schema.filter((f) => f.type === "secret").map((f) => f.key);
  // From the saved config only: a draft does not tick an item off until it is saved.
  const missing = missingRequired(connector.config_schema, saved);
  const requiredTotal = connector.config_schema.filter((f) => f.required).length;

  const status = connectorStatus(connector);
  const since = relativeTime(connector.last_health_at, new Date());
  // relativeTime says "not checked yet" for a missing or unparsable timestamp; never print that after "Last checked".
  const checked =
    since === "not checked yet"
      ? "Not checked yet"
      : `Last checked ${since}${connector.last_health_detail ? `: ${connector.last_health_detail}` : ""}`;

  // The theme's disabled contained button keeps the brand fill, which leaves the label unreadable; a neutral fill with text pushed to 4.5:1.
  const paper = theme.palette.background.paper;
  const disabledFill = flatten(theme.palette.action.disabledBackground, paper);
  const disabledText = ensureContrast(flatten(theme.palette.text.secondary, disabledFill), disabledFill, 4.5);

  // Unselected tabs use the secondary text colour, which is under 4.5:1 on paper in a few themes.
  const tabText = ensureContrast(flatten(theme.palette.text.secondary, paper), paper, 4.5);
  const tabId = (v: TabValue) => `${ids}-tab-${v}`;
  const panelId = (v: TabValue) => `${ids}-panel-${v}`;

  const configLoaded = !configQuery.isLoading && !configQuery.isError;
  const showFooter = tab === "configuration" && configLoaded;

  return (
    <>
      <Drawer
        anchor="right"
        open={open}
        onClose={requestClose}
        slotProps={{
          root: { disableAutoFocus, disableRestoreFocus: disableAutoFocus },
          transition: { onExited },
          paper: {
            role: "dialog",
            "aria-modal": true,
            "aria-labelledby": titleId,
            sx: {
              width: isPhone ? "100%" : "min(600px, 100vw)",
              display: "flex",
              flexDirection: "column",
              bgcolor: "background.paper",
              backgroundImage: "none",
              borderLeft: 1,
              borderColor: "divider",
            },
          } as object,
        }}
      >
        <Box
          component="header"
          sx={{
            flexShrink: 0,
            px: { xs: 2, sm: 3 },
            pt: "calc(env(safe-area-inset-top, 0px) + 20px)",
            borderBottom: 1,
            borderColor: "divider",
            backgroundImage: `linear-gradient(180deg, ${alpha(theme.palette.text.primary, 0.04)} 0%, ${alpha(paper, 0)} 100%)`,
          }}
        >
          <Stack direction="row" spacing={2} sx={{ alignItems: "flex-start" }}>
            <Box sx={{ pl: 0.5, pt: 0.5 }}>
              <ConnectorMark name={connector.name} size={48} />
            </Box>
            <Box sx={{ minWidth: 0, flex: 1 }}>
              <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap", rowGap: 0.5 }}>
                <Typography id={titleId} variant="h6" component="h2" sx={{ overflowWrap: "anywhere" }}>
                  {connector.name}
                </Typography>
                <Chip size="small" label={connector.version} variant="outlined" />
              </Stack>
              <Box sx={{ mt: 0.5 }}>
                <StatusLabel tone={status.tone} label={status.label} />
              </Box>
              <Typography variant="caption" sx={{ display: "block", mt: 0.5, overflowWrap: "anywhere", color: muted }}>
                {checked}
              </Typography>
              {hasDraft && tab !== "configuration" && (
                <Typography variant="caption" color="warning.main" sx={{ display: "block", mt: 0.25 }}>
                  Unsaved changes in Configuration
                </Typography>
              )}
            </Box>
            <IconButton aria-label={`Close ${connector.name}`} onClick={requestClose} edge="end" sx={{ mt: -0.5 }}>
              <CloseOutlined />
            </IconButton>
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
            aria-label="Connector sections"
            // Tighter padding on a phone so all three labels fit; swiping still works if a theme or font makes them wider.
            sx={{
              mt: 1.5,
              mb: "-1px",
              "& .MuiTab-root": { minWidth: 0, px: { xs: 1, sm: 2 }, color: tabText },
              "& .MuiTab-root.Mui-selected": { color: accent.text },
              "& .MuiTabs-indicator": { backgroundColor: accent.mark },
            }}
          >
            {TABS.map((t) => (
              <Tab key={t.value} value={t.value} label={t.label} id={tabId(t.value)} aria-controls={panelId(t.value)} />
            ))}
          </Tabs>
        </Box>

        {/* Only the body scrolls: the header and the footer stay put (Carbon side panel guidance). */}
        <Box sx={{ flex: 1, minHeight: 0, overflowY: "auto", px: { xs: 2, sm: 3 }, py: 3 }}>
          {TABS.map((t) => (
            <Box
              key={t.value}
              role="tabpanel"
              id={panelId(t.value)}
              aria-labelledby={tabId(t.value)}
              hidden={tab !== t.value}
              // APG: a panel whose first content cannot take focus is itself a tab stop. Configuration's first field can, once loaded.
              tabIndex={t.value === "configuration" && configLoaded ? undefined : 0}
            >
              {tab === t.value && t.value === "overview" && <ConnectorOverview connector={connector} />}

              {tab === t.value && t.value === "configuration" && (
                <>
                  {configQuery.isError && <Alert severity="error">Failed to load configuration.</Alert>}
                  {configQuery.isLoading && <CircularProgress size={18} sx={{ display: "block" }} />}
                  {configLoaded && (
                    <>
                      <SetupChecklist missing={missing} total={requiredTotal} />
                      <ConnectorConfigForm
                        connector={connector}
                        config={config}
                        saved={saved}
                        errors={fieldErrors}
                        onChange={(field, value) => {
                          const next = structuredClone(config);
                          dottedSet(next, field.key, value);
                          setDraft(next);
                          setSavedNotice(false);
                          setFieldErrors(({ [field.key]: _gone, ...rest }) => rest);
                        }}
                      />
                    </>
                  )}
                </>
              )}

              {tab === t.value && t.value === "deliveries" && <ConnectorDeliveries name={connector.name} />}
            </Box>
          ))}
        </Box>

        {showFooter && (
          <ActionBar sx={{ display: "block", flexShrink: 0, px: { xs: 2, sm: 3 }, pb: "calc(env(safe-area-inset-bottom, 0px) + 12px)" }}>
            {/* Inside the bar, not below it: a result under a sticky bar would sit off screen. */}
            {test.result && (
              <Alert sx={{ mb: 1.5 }} severity={test.result.ok ? "success" : "error"} onClose={test.dismiss}>
                <Box component="span" sx={{ display: "block", fontWeight: 600 }}>Tested the saved configuration</Box>
                {test.result.text}
              </Alert>
            )}
            {saveError && (
              <Alert sx={{ mb: 1.5 }} severity="error" onClose={() => setSaveError(null)}>
                {saveError}
              </Alert>
            )}
            {savedNotice && !draft && (
              <Alert
                data-saved-row
                role="status"
                sx={{ mb: 1.5 }}
                severity="success"
                action={
                  <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }}>
                    <Button
                      size="small"
                      color="inherit"
                      onClick={() => {
                        setSavedNotice(false);
                        test.run();
                      }}
                    >
                      Test now
                    </Button>
                    <IconButton size="small" color="inherit" aria-label="Dismiss saved message" onClick={() => setSavedNotice(false)}>
                      <CloseOutlined fontSize="small" />
                    </IconButton>
                  </Stack>
                }
              >
                Saved. Run a test now?
              </Alert>
            )}
            <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap", rowGap: 1 }}>
              <Button
                variant="contained"
                sx={{ "&.Mui-disabled": { bgcolor: disabledFill, color: disabledText, backgroundImage: "none" } }}
                disabled={!draft || save.isPending}
                aria-describedby={draft ? undefined : hintId}
                onClick={() => draft && save.mutate(stripUnchangedSecrets(draft, secretKeys))}
              >
                Save changes
              </Button>
              <Button
                variant="outlined"
                // Disabled while the request runs; the theme's disabled grey is under 4.5:1 on paper.
                sx={{ color: accent.text, "&.Mui-disabled": { color: tabText } }}
                onClick={test.run}
                disabled={test.pending}
                aria-describedby={draft ? testHintId : undefined}
              >
                Test connection
              </Button>
              {!draft && (
                <Typography id={hintId} variant="caption" sx={{ color: muted }}>
                  No changes to save
                </Typography>
              )}
              {draft && (
                <Typography id={testHintId} variant="caption" sx={{ color: muted }}>
                  Test connection checks the saved configuration, not your unsaved changes.
                </Typography>
              )}
            </Stack>
          </ActionBar>
        )}
      </Drawer>

      <ConfirmDialog
        open={confirmClose}
        title={`Discard unsaved changes to ${connector.name}?`}
        body="Your edits to this connector have not been saved and will be lost."
        confirmLabel="Discard"
        destructive
        onConfirm={() => {
          setConfirmClose(false);
          onClose();
        }}
        onCancel={() => setConfirmClose(false)}
      />
    </>
  );
}
