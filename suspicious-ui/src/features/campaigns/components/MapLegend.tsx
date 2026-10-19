import { Box, Stack, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import type { CampaignRow } from "@/features/campaigns/api";
import { formatFullDay } from "@/features/campaigns/utils";

const dot = (colour: string) => <Box component="span" aria-hidden sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: colour, flexShrink: 0, mt: "5px" }} />;

/** The campaigns that have a colour, their names in full, and what the grey means. */
export function CampaignLegend({ campaigns, colours, neutral, inMap }: { campaigns: CampaignRow[]; colours: string[]; neutral: string; inMap: number[] }) {
  if (!campaigns.length) {
    return (
      <Typography variant="body2" color="text.secondary">
        No campaigns in the selected period.
      </Typography>
    );
  }
  return (
    <>
      <Box component="ul" aria-label="Campaigns" sx={{ m: 0, p: 0, listStyle: "none" }}>
        {campaigns.map((c, i) => (
          <Stack component="li" key={c.name} direction="row" spacing={1} sx={{ py: 0.25 }}>
            {dot(colours[i])}
            <Typography variant="body2" sx={{ overflowWrap: "anywhere" }}>
              {c.name}
              <Typography component="span" variant="caption" color="text.secondary">
                {` · ${c.messages.toLocaleString()} messages, ${inMap[i]} in the map`}
              </Typography>
            </Typography>
          </Stack>
        ))}
        <Stack component="li" direction="row" spacing={1} sx={{ py: 0.25 }}>
          {dot(neutral)}
          <Typography variant="body2">Not in a listed campaign</Typography>
        </Stack>
      </Box>
      <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 0.5 }}>
        Colours cover the case ids the summary lists, up to 20 per campaign; other messages are grey. A campaign is messages sharing the same source references (inferred).
      </Typography>
    </>
  );
}

/** The age ramp from the oldest to the newest day of the sample, and the swatch for messages without a date. */
export function AgeLegend({ oldest, newest, from, to, none, hasUndated }: { oldest: string | null; newest: string | null; from: string; to: string; none: string; hasUndated: boolean }) {
  const theme = useTheme();
  return (
    <Box role="group" aria-label="Age scale">
      {oldest && newest ? (
        <>
          <Box aria-hidden sx={{ height: 10, borderRadius: 1, background: `linear-gradient(to right, ${from}, ${to})`, border: "1px solid", borderColor: theme.palette.divider }} />
          <Stack direction="row" sx={{ justifyContent: "space-between", mt: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              {`Oldest ${formatFullDay(oldest)}`}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {`Newest ${formatFullDay(newest)}`}
            </Typography>
          </Stack>
        </>
      ) : null}
      {hasUndated ? (
        <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
          {dot(none)}
          <Typography variant="caption" color="text.secondary">
            No date
          </Typography>
        </Stack>
      ) : null}
    </Box>
  );
}
