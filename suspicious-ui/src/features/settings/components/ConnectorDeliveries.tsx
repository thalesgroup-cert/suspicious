import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Link,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { Link as RouterLink } from "react-router";

import { StatusLabel, type StatusTone } from "@/features/settings/components/StatusLabel";
import { listDeliveries, type ConnectorDelivery } from "@/features/settings/components/connectors";
import { DELIVERY_STATUS_LABEL } from "@/features/settings/labels";

export const DELIVERY_LIMIT = 10;
const LONG_ERROR = 80;
const hidden = {
  position: "absolute", width: "1px", height: "1px", overflow: "hidden", clip: "rect(0 0 0 0)", whiteSpace: "nowrap",
} as const;

const TONE: Record<ConnectorDelivery["status"], StatusTone> = { success: "ok", failed: "danger", skipped: "neutral" };

export function ConnectorDeliveries({ name }: { name: string }) {
  const [failedOnly, setFailedOnly] = useState(false);
  const query = useQuery({
    queryKey: ["connector-deliveries", name],
    queryFn: () => listDeliveries(name, DELIVERY_LIMIT),
  });

  if (query.isLoading) return <CircularProgress size={18} />;
  if (query.isError) return <Alert severity="error">Failed to load recent deliveries.</Alert>;

  const all = query.data ?? [];
  if (all.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        No deliveries yet.
      </Typography>
    );
  }
  const rows = failedOnly ? all.filter((d) => d.status === "failed") : all;

  return (
    <Stack spacing={1.5}>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", rowGap: 1 }}>
        {all.length === DELIVERY_LIMIT && (
          <Typography variant="caption" color="text.secondary">
            Showing the last {DELIVERY_LIMIT}
          </Typography>
        )}
        <Button
          size="small"
          sx={{ ml: "auto" }}
          variant={failedOnly ? "contained" : "outlined"}
          aria-pressed={failedOnly}
          onClick={() => setFailedOnly((v) => !v)}
        >
          Failed only
        </Button>
      </Stack>
      {rows.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          No failed deliveries among these.
        </Typography>
      ) : (
        // Focusable so a keyboard user can scroll the table sideways on a phone.
        <TableContainer tabIndex={0} role="region" aria-label="Deliveries table" sx={{ overflowX: "auto" }}>
          <Table size="small" sx={{ minWidth: 560 }}>
            <Box component="caption" sx={hidden}>Recent deliveries</Box>
            <TableHead>
              <TableRow>
                {["Event", "Case", "Status", "Time", "Error"].map((h) => (
                  <TableCell key={h} component="th" scope="col">{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((d) => (
                <TableRow key={d.id}>
                  <TableCell>{d.event}</TableCell>
                  <TableCell>
                    {d.case_id != null ? (
                      <Link component={RouterLink} to={`/investigation?open=${encodeURIComponent(String(d.case_id))}`} underline="always">
                        {`Case #${d.case_id}`}
                      </Link>
                    ) : (
                      <Typography variant="body2" color="text.secondary">None</Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <StatusLabel size="small" tone={TONE[d.status] ?? "neutral"} label={DELIVERY_STATUS_LABEL[d.status] ?? d.status} />
                  </TableCell>
                  <TableCell sx={{ whiteSpace: "nowrap" }}>{new Date(d.created_at).toLocaleString()}</TableCell>
                  <TableCell sx={{ maxWidth: 280 }}>
                    {d.error && (
                      // The text stays whole in the DOM (assistive tech reads it all); only the view is clamped.
                      <Box
                        component="span"
                        title={d.error.length > LONG_ERROR ? d.error : undefined}
                        sx={{ display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical", overflow: "hidden", overflowWrap: "anywhere" }}
                      >
                        {d.error}
                      </Box>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Stack>
  );
}
