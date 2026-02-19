// file: src/features/dashboard/components/RankedPrefixesTable.tsx
import * as React from "react";
import {
  Box,
  Divider,
  IconButton,
  InputAdornment,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { ContentCopyOutlined, OpenInNewOutlined, SearchOutlined } from "@mui/icons-material";

type PrefixItem = { label: string; value: number };

async function copyToClipboard(text: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // no-op: clipboard may be unavailable depending on context
  }
}

export default function RankedPrefixesTable(props: {
  data: PrefixItem[];
  search: string;
  onSearchChange: (v: string) => void;
}) {
  const rows = React.useMemo(() => {
    // ensure stable sort by value desc, then label asc
    return [...props.data].sort((a, b) => (b.value - a.value) || a.label.localeCompare(b.label));
  }, [props.data]);

  return (
    <Box
      sx={{
        borderRadius: 3,
        border: "1px solid",
        borderColor: "divider",
        bgcolor: "background.paper",
        overflow: "hidden",
      }}
    >
      <Box sx={{ p: 2 }}>
        <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={2}>
          <Typography sx={{ fontWeight: 900, fontSize: 14 }}>Ranked prefixes</Typography>

          <TextField
            size="small"
            value={props.search}
            onChange={(e) => props.onSearchChange(e.target.value)}
            placeholder="Search prefix…"
            inputProps={{ "aria-label": "Search prefix" }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchOutlined fontSize="small" />
                </InputAdornment>
              ),
            }}
            sx={{ width: { xs: "100%", sm: 280 } }}
          />
        </Stack>

        <Box sx={{ mt: 0.75, color: "text.secondary", fontSize: 12 }}>
          Copy a prefix or open details (route TODO).
        </Box>
      </Box>

      <Divider />

      <Box sx={{ maxHeight: 360, overflow: "auto" }}>
        <Table stickyHeader size="small" aria-label="Ranked prefixes table">
          <TableHead>
            <TableRow>
              <TableCell sx={{ fontWeight: 900 }}>Prefix</TableCell>
              <TableCell sx={{ fontWeight: 900 }} align="right">
                Count
              </TableCell>
              <TableCell sx={{ width: 88 }} align="right">
                <span style={{ position: "absolute", left: -9999 }}>Actions</span>
              </TableCell>
            </TableRow>
          </TableHead>

          <TableBody>
            {rows.length ? (
              rows.map((r) => (
                <TableRow
                  key={r.label}
                  hover
                  tabIndex={0}
                  sx={{
                    "&:focus": { outline: "2px solid rgba(255,255,255,0.22)", outlineOffset: -2 },
                  }}
                >
                  <TableCell sx={{ fontWeight: 800 }}>{r.label}</TableCell>
                  <TableCell align="right" sx={{ fontVariantNumeric: "tabular-nums", fontWeight: 900 }}>
                    {r.value}
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Copy prefix">
                      <IconButton size="small" aria-label={`Copy ${r.label}`} onClick={() => copyToClipboard(r.label)}>
                        <ContentCopyOutlined fontSize="inherit" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Open details (TODO)">
                      <span>
                        <IconButton size="small" aria-label={`Open ${r.label}`} disabled>
                          <OpenInNewOutlined fontSize="inherit" />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={3}>
                  <Box sx={{ py: 3, textAlign: "center", color: "text.secondary" }}>
                    No matches.
                  </Box>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Box>
    </Box>
  );
}
