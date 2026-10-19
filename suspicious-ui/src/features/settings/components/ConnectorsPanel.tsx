import { useCallback, useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Alert, CircularProgress, Grid, useMediaQuery } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";
import { EmptyList } from "@/features/settings/components/cards";
import { ConnectorDetail } from "@/features/settings/components/ConnectorDetail";
import { ConnectorList } from "@/features/settings/components/ConnectorList";
import { listConnectors } from "@/features/settings/components/connectors";

export function ConnectorsPanel() {
  const theme = useTheme();
  const isDesktop = useMediaQuery(theme.breakpoints.up("md"));

  const { data, isLoading, error } = useQuery({
    queryKey: ["connectors"],
    queryFn: listConnectors,
  });

  const connectors = useMemo(() => data?.connectors ?? [], [data]);
  const [selected, setSelected] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  // Where the user asked to go while a draft exists; `null` is a valid target (mobile back).
  const [pending, setPending] = useState<{ to: string | null } | null>(null);

  const requestSelect = (to: string | null) => {
    if (to === selected) return;
    if (dirty) setPending({ to });
    else setSelected(to);
  };
  const onDirtyChange = useCallback((d: boolean) => setDirty(d), []);

  useEffect(() => {
    if (isDesktop && !selected && connectors.length > 0) {
      setSelected(connectors[0].name);
    }
  }, [isDesktop, selected, connectors]);

  if (isLoading) return <CircularProgress size={24} />;
  if (error) return <Alert severity="error">Failed to load connectors.</Alert>;

  const selectedConnector = connectors.find((c) => c.name === selected) ?? null;

  const discardDialog = (
    <ConfirmDialog
      open={pending !== null}
      title={`Discard unsaved changes to ${selected}?`}
      body="Your edits to this connector have not been saved and will be lost."
      confirmLabel="Discard"
      destructive
      onConfirm={() => {
        if (pending) setSelected(pending.to);
        setPending(null);
      }}
      onCancel={() => setPending(null)}
    />
  );

  if (!isDesktop && selectedConnector) {
    return (
      <>
        <ConnectorDetail
          key={selectedConnector.name}
          connector={selectedConnector}
          onBack={() => requestSelect(null)}
          onDirtyChange={onDirtyChange}
        />
        {discardDialog}
      </>
    );
  }

  return (
    <Grid container spacing={2}>
      <Grid size={{ xs: 12, md: 4.5 }}>
        <ConnectorList
          connectors={connectors}
          loadErrors={data?.load_errors ?? {}}
          selected={selected}
          onSelect={requestSelect}
        />
      </Grid>
      {isDesktop && (
        <Grid size={{ md: 7.5 }}>
          {selectedConnector ? (
            <ConnectorDetail
              key={selectedConnector.name}
              connector={selectedConnector}
              onDirtyChange={onDirtyChange}
            />
          ) : (
            <EmptyList message="Select a connector to view its configuration." />
          )}
        </Grid>
      )}
      {discardDialog}
    </Grid>
  );
}
