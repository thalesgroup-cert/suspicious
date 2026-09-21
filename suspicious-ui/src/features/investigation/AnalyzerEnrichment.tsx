import { useState } from "react";
import {
  Box,
  Button,
  Chip,
  Link,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";

import type { Enrichment } from "./enrichment";

const CATEGORY_COLOR: Record<string, "error" | "warning" | "default"> = {
  malicious: "error",
  suspicious: "warning",
};

const MAX_ROWS = 200;

function categoryColor(category: string) {
  return CATEGORY_COLOR[category] ?? "default";
}

function FactGrid({ enrichment }: { enrichment: Enrichment }) {
  const rows: Array<[string, string]> = [];
  const add = (label: string, value: unknown) => {
    if (value === undefined || value === null || value === "") return;
    if (Array.isArray(value)) {
      if (value.length === 0) return;
      rows.push([label, value.join(", ")]);
    } else {
      rows.push([label, String(value)]);
    }
  };

  add("AS owner", enrichment.as_owner);
  add("Country", enrichment.country);
  add("ASN", enrichment.asn);
  add("Network", enrichment.network);
  add("Registrar", enrichment.registrar);
  add("Created", enrichment.creation_date);
  add("Final URL", enrichment.final_url);
  add("Page title", enrichment.page_title);
  add("Filename", enrichment.meaningful_name);
  add("Size", enrichment.size);
  add("Type", enrichment.type_description);
  add("Threat label", enrichment.threat_label);
  add("First seen", enrichment.first_seen);
  add("Last seen", enrichment.last_seen);
  add("Reputation", enrichment.reputation);
  add("Tags", enrichment.tags);

  if (rows.length === 0) return null;

  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: "max-content 1fr",
        columnGap: 2,
        rowGap: 0.5,
        mb: 1.5,
      }}
    >
      {rows.map(([label, value]) => (
        <Box key={label} sx={{ display: "contents" }}>
          <Typography variant="caption" color="text.secondary">
            {label}
          </Typography>
          <Typography variant="body2">{value}</Typography>
        </Box>
      ))}
    </Box>
  );
}

function VendorTable({ enrichment }: { enrichment: Enrichment }) {
  const [showAll, setShowAll] = useState(false);
  const vendors = enrichment.vendors ?? [];
  const flagging = vendors.filter(
    (v) => v.category === "malicious" || v.category === "suspicious",
  );

  const flaggedCount =
    (enrichment.malicious_count ?? 0) + (enrichment.suspicious_count ?? 0) || flagging.length;
  const total = enrichment.total ?? enrichment.vendors?.length ?? 0;

  const list = showAll ? vendors : flagging;
  const shown = list.slice(0, MAX_ROWS);
  const overflow = list.length - shown.length;

  return (
    <Stack spacing={1}>
      <Typography variant="body2" color="text.secondary">
        {`${flaggedCount} / ${total} security vendors flagged this`}
      </Typography>

      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Vendor</TableCell>
            <TableCell>Category</TableCell>
            <TableCell>Result</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {shown.map((v, i) => (
            <TableRow key={`${v.name}-${i}`}>
              <TableCell>{v.name}</TableCell>
              <TableCell>
                <Chip size="small" color={categoryColor(v.category)} label={v.category} />
              </TableCell>
              <TableCell>{v.result ?? "—"}</TableCell>
            </TableRow>
          ))}
          {overflow > 0 ? (
            <TableRow>
              <TableCell colSpan={3}>+{overflow} more</TableCell>
            </TableRow>
          ) : null}
        </TableBody>
      </Table>

      {vendors.length > flagging.length ? (
        <Box>
          <Button size="small" onClick={() => setShowAll((s) => !s)}>
            {showAll ? "Show flagged only" : `Show all ${vendors.length}`}
          </Button>
        </Box>
      ) : null}
    </Stack>
  );
}

export function AnalyzerEnrichment({ enrichment }: { enrichment: Enrichment }) {
  return (
    <Stack spacing={1.5}>
      <FactGrid enrichment={enrichment} />
      <VendorTable enrichment={enrichment} />
      {enrichment.vt_link ? (
        <Link href={enrichment.vt_link} target="_blank" rel="noopener">
          View on VirusTotal
        </Link>
      ) : null}
    </Stack>
  );
}
