import {
  Box,
  Button,
  Link,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  useMediaQuery,
} from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { Link as RouterLink } from "react-router";

import type { CampaignRow } from "@/features/campaigns/api";
import { formatSeen, sortRows, useSort } from "@/features/campaigns/utils";
import { SortCell } from "./PanelState";

type Key = "first_seen" | "last_seen" | "messages" | "dangerous_share";
const KEYS: Record<Key, (c: CampaignRow) => string | number> = {
  first_seen: (c) => c.first_seen,
  last_seen: (c) => c.last_seen,
  messages: (c) => c.messages,
  dangerous_share: (c) => c.dangerous_share,
};

// Thousands of DOM rows make the page sluggish; the sort puts the ones worth looking at first.
const MAX_ROWS = 100;

const NOTE = "Campaigns are inferred from shared source references; first and last seen are within the selected period.";

// Names are cut to their first source references, so two campaigns can share one.
const rowKey = (c: CampaignRow, i: number) => `${c.first_seen}|${c.name}|${i}`;

function share(c: CampaignRow) {
  return `${c.dangerous.toLocaleString()} (${Math.round(c.dangerous_share * 100)}%)`;
}

function Actions({ c, onSelectCases, stacked = false }: { c: CampaignRow; onSelectCases: (ids: string[]) => void; stacked?: boolean }) {
  return (
    // Stacked in the table so the column stays one control wide; side by side on the phone cards.
    <Stack direction={stacked ? "column" : "row"} useFlexGap spacing={stacked ? 0.5 : 1} sx={{ alignItems: stacked ? "flex-start" : "center", flexWrap: "wrap" }}>
      {c.case_ids.length ? (
        // The investigation page opens one case: the most recent one, not a filtered list.
        <Link component={RouterLink} to={`/investigation?open=${encodeURIComponent(c.case_ids[0])}`} variant="body2">
          Open latest case
        </Link>
      ) : (
        <Typography variant="body2" color="text.secondary">
          No case linked
        </Typography>
      )}
      <Button size="small" variant="outlined" disabled={!c.case_ids.length} onClick={() => onSelectCases(c.case_ids)}>
        Show in map
      </Button>
    </Stack>
  );
}

function Status({ active }: { active: boolean }) {
  return (
    <Typography variant="body2" sx={{ fontWeight: active ? 600 : 400 }} color={active ? "text.primary" : "text.secondary"}>
      {active ? "Active" : "Ended"}
    </Typography>
  );
}

export default function CampaignTable(props: { campaigns: CampaignRow[]; onSelectCases: (caseIds: string[]) => void }) {
  const theme = useTheme();
  const phone = useMediaQuery(theme.breakpoints.down("sm"), { noSsr: true });
  // Dates and counts start descending: the newest and largest campaigns are the ones to look at first.
  const { sort, onSort } = useSort<Key>({ key: "last_seen", dir: "desc" }, () => "desc");
  const rows = sortRows(props.campaigns, KEYS[sort.key], sort.dir).slice(0, MAX_ROWS);

  if (!rows.length) {
    return (
      <Typography variant="body2" color="text.secondary">
        No campaigns in this period.
      </Typography>
    );
  }

  const note = (
    <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 1.5 }}>
      {NOTE}
    </Typography>
  );
  const capped =
    props.campaigns.length > MAX_ROWS ? (
      <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 1 }}>
        Showing {MAX_ROWS} of {props.campaigns.length.toLocaleString()} campaigns
      </Typography>
    ) : null;

  if (phone) {
    // A table of eight columns cannot fit 390px without scrolling sideways: one card per campaign instead.
    return (
      <>
        {capped}
        <Stack component="ul" spacing={1.5} sx={{ m: 0, p: 0, listStyle: "none" }}>
          {rows.map((c, i) => (
            <Box
              component="li"
              key={rowKey(c, i)}
              sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, p: 1.5 }}
            >
              <Typography variant="body2" sx={{ fontWeight: 600, overflowWrap: "anywhere" }}>
                {c.name}
              </Typography>
              <Status active={c.active} />
              <Typography variant="body2" color="text.secondary">
                {formatSeen(c.first_seen)} to {formatSeen(c.last_seen)}
              </Typography>
              <Typography variant="body2">
                {c.messages.toLocaleString()} messages, {share(c)} dangerous
              </Typography>
              {c.sample_subject ? (
                <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: "anywhere" }}>
                  {c.sample_subject}
                </Typography>
              ) : null}
              <Box sx={{ mt: 1 }}>
                <Actions c={c} onSelectCases={props.onSelectCases} />
              </Box>
            </Box>
          ))}
        </Stack>
        {note}
      </>
    );
  }

  return (
    <>
      {capped}
      <TableContainer>
        <Table size="small" aria-label="Campaigns in this period">
          <TableHead>
            <TableRow>
              <TableCell>Campaign</TableCell>
              <TableCell>Status</TableCell>
              <SortCell id="first_seen" sort={sort} onSort={onSort}>
                First seen
              </SortCell>
              <SortCell id="last_seen" sort={sort} onSort={onSort}>
                Last seen
              </SortCell>
              <SortCell id="messages" sort={sort} onSort={onSort} align="right">
                Messages
              </SortCell>
              <SortCell id="dangerous_share" sort={sort} onSort={onSort} align="right">
                Dangerous
              </SortCell>
              <TableCell>Sample subject</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((c, i) => (
              <TableRow key={rowKey(c, i)}>
                {/* Full name, wrapped: truncating it hides the only thing that tells campaigns apart. */}
                <TableCell sx={{ overflowWrap: "anywhere", minWidth: 200 }}>{c.name}</TableCell>
                <TableCell>
                  <Status active={c.active} />
                </TableCell>
                <TableCell sx={{ whiteSpace: "nowrap" }}>{formatSeen(c.first_seen)}</TableCell>
                <TableCell sx={{ whiteSpace: "nowrap" }}>{formatSeen(c.last_seen)}</TableCell>
                <TableCell align="right" sx={{ fontVariantNumeric: "tabular-nums" }}>
                  {c.messages.toLocaleString()}
                </TableCell>
                <TableCell align="right" sx={{ fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>
                  {share(c)}
                </TableCell>
                <TableCell sx={{ maxWidth: 180 }}>
                  <Typography
                    variant="body2"
                    title={c.sample_subject ?? undefined}
                    sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  >
                    {c.sample_subject ?? "—"}
                  </Typography>
                </TableCell>
                <TableCell sx={{ whiteSpace: "nowrap" }}>
                  <Actions c={c} onSelectCases={props.onSelectCases} stacked />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      {note}
    </>
  );
}
