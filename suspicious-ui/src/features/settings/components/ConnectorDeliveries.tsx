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
import { useTheme } from "@mui/material/styles";
import { Link as RouterLink } from "react-router";

import { composite, ensureContrast, flatten } from "@/shared/lib/contrast";

import { StatusLabel, type StatusTone } from "@/features/settings/components/StatusLabel";
import { useAccent } from "@/features/settings/useAccent";
import { listDeliveries, type ConnectorDelivery } from "@/features/settings/components/connectors";
import { DELIVERY_STATUS_LABEL } from "@/features/settings/labels";

export const DELIVERY_LIMIT = 10;
const LONG_ERROR = 80;
// The detail pane is about 520px wide at 1440 and the page is 390px on a phone, so the fold follows the table's own width, not the viewport.
const WIDE = "@container (min-width: 720px)";
const wideOnly = { display: "none", [WIDE]: { display: "table-cell" } } as const;
const foldedIn = { display: "block", [WIDE]: { display: "none" } } as const;
const when = (d: ConnectorDelivery) => new Date(d.created_at).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
const hidden = {
  position: "absolute", width: "1px", height: "1px", overflow: "hidden", clip: "rect(0 0 0 0)", whiteSpace: "nowrap",
} as const;

const TONE: Record<ConnectorDelivery["status"], StatusTone> = { success: "ok", failed: "danger", skipped: "neutral" };

const caseLink = (d: ConnectorDelivery, color: string) =>
  d.case_id != null ? (
    <Link component={RouterLink} to={`/investigation?open=${encodeURIComponent(String(d.case_id))}`} underline="always" sx={{ color }}>
      {`Case #${d.case_id}`}
    </Link>
  ) : null;

export function ConnectorDeliveries({ name }: { name: string }) {
  const accent = useAccent();
  const theme = useTheme();
  // The theme paints the header text.secondary on a faint text.primary tint; in graphite that is under 4.5:1.
  const headBg = composite(theme.palette.text.primary, theme.palette.mode === "dark" ? 0.03 : 0.025, theme.palette.background.paper);
  const headText = ensureContrast(flatten(theme.palette.text.secondary, headBg), headBg, 4.5);
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
          sx={{ ml: "auto", ...(failedOnly ? {} : { color: accent.text }) }}
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
        <TableContainer tabIndex={0} role="region" aria-label="Deliveries table" sx={{ overflowX: "auto", containerType: "inline-size" }}>
          <Table size="small" sx={{ "& th, & td": { px: { xs: 0.75, sm: 2 } } }}>
            <Box component="caption" sx={hidden}>Recent deliveries</Box>
            <TableHead>
              <TableRow>
                {["Event", "Case", "Status", "Time", "Error"].map((h) => (
                  // On a phone Time and Case fold into the Event cell: five columns would need sideways scrolling to reach Status and Error.
                  <TableCell key={h} component="th" scope="col" sx={{ color: headText, ...(h === "Time" || h === "Case" ? wideOnly : {}) }}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((d) => (
                <TableRow key={d.id}>
                  <TableCell sx={{ whiteSpace: "normal", [WIDE]: { whiteSpace: "nowrap" } }}>
                    {d.event}
                    <Typography variant="caption" color="text.secondary" sx={foldedIn}>
                      {when(d)}
                    </Typography>
                    <Box sx={foldedIn}>{caseLink(d, accent.text)}</Box>
                  </TableCell>
                  <TableCell sx={{ whiteSpace: "nowrap", ...wideOnly }}>
                    {caseLink(d, accent.text) ?? <Typography variant="body2" color="text.secondary">None</Typography>}
                  </TableCell>
                  <TableCell>
                    <StatusLabel size="small" tone={TONE[d.status] ?? "neutral"} label={DELIVERY_STATUS_LABEL[d.status] ?? d.status} />
                  </TableCell>
                  <TableCell sx={{ whiteSpace: "nowrap", ...wideOnly }}>{when(d)}</TableCell>
                  <TableCell sx={{ minWidth: 96, maxWidth: 280 }}>
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
