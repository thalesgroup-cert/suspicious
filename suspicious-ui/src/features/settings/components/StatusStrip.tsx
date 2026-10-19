import * as React from "react";
import { Box, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";

import { getFeederStatus, listAnalyzers } from "@/features/settings/api";
import { listConnectors } from "@/features/settings/components/connectors";
import type { SectionKey } from "@/features/settings/components/sections";
import FeederHealthBadge from "@/shared/components/FeederHealthBadge";

function Cell({
  to,
  label,
  loading,
  failed,
  value,
  extra,
}: {
  to: SectionKey;
  label: string;
  loading: boolean;
  failed: boolean;
  value: string;
  extra?: React.ReactNode;
}) {
  const theme = useTheme();
  return (
    <Box
      component={Link}
      to={`/settings/${to}`}
      sx={{
        flex: 1,
        minWidth: 0,
        px: 1.5,
        py: 1,
        borderRadius: 2,
        border: `1px solid ${theme.palette.divider}`,
        color: "inherit",
        textDecoration: "none",
        "&:hover": { background: alpha(theme.palette.primary.main, 0.06) },
      }}
    >
      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
        {label}
      </Typography>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
        <Typography variant="subtitle2" component="span">
          {failed ? "unavailable" : loading ? "Loading" : value}
        </Typography>
        {!failed && !loading && extra}
      </Stack>
    </Box>
  );
}

/** Facts the page already fetches. Each cell loads on its own so one outage never blanks the strip. */
export function StatusStrip() {
  const feeder = useQuery({ queryKey: ["settings", "email_feeder"], queryFn: getFeederStatus, retry: false });
  const connectors = useQuery({ queryKey: ["connectors"], queryFn: listConnectors, retry: false });
  const analyzers = useQuery({ queryKey: ["settings", "scoring"], queryFn: listAnalyzers, retry: false });

  const list = connectors.data?.connectors ?? [];
  const unhealthy = list.filter((c) => c.last_health_ok === false).length;
  const enabled = list.filter((c) => c.enabled).length;
  const all = analyzers.data ?? [];

  return (
    <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ mb: 2 }}>
      <Cell
        to="email_feeder"
        label="Email feeder"
        loading={feeder.isPending}
        failed={feeder.isError}
        value={feeder.data?.enabled ? "Running" : "Stopped"}
        extra={<FeederHealthBadge label="Health" />}
      />
      <Cell
        to="connectors"
        label="Connectors"
        loading={connectors.isPending}
        failed={connectors.isError}
        value={`${enabled} of ${list.length} enabled, ${unhealthy} unhealthy`}
      />
      <Cell
        to="scoring"
        label="Analyzers"
        loading={analyzers.isPending}
        failed={analyzers.isError}
        value={`${all.filter((a) => a.is_active).length} of ${all.length} active`}
      />
    </Stack>
  );
}
