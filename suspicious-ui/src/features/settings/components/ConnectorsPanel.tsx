import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Alert, CircularProgress, Grid, useMediaQuery } from "@mui/material";
import { useTheme } from "@mui/material/styles";

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

  const connectors = data?.connectors ?? [];
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    if (isDesktop && !selected && connectors.length > 0) {
      setSelected(connectors[0].name);
    }
  }, [isDesktop, selected, connectors]);

  if (isLoading) return <CircularProgress size={24} />;
  if (error) return <Alert severity="error">Failed to load connectors.</Alert>;

  const selectedConnector = connectors.find((c) => c.name === selected) ?? null;

  if (!isDesktop && selectedConnector) {
    return <ConnectorDetail connector={selectedConnector} onBack={() => setSelected(null)} />;
  }

  return (
    <Grid container spacing={2}>
      <Grid size={{ xs: 12, md: 4.5 }}>
        <ConnectorList
          connectors={connectors}
          loadErrors={data?.load_errors ?? {}}
          selected={selected}
          onSelect={setSelected}
        />
      </Grid>
      {isDesktop && (
        <Grid size={{ md: 7.5 }}>
          {selectedConnector ? (
            <ConnectorDetail connector={selectedConnector} />
          ) : (
            <EmptyList message="Select a connector to view its configuration." />
          )}
        </Grid>
      )}
    </Grid>
  );
}
