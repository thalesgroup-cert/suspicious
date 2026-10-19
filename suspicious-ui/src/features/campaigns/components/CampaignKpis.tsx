import { Box, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import { Kpi, Line } from "@/features/dashboard/components/KpiTrendPanels";
import { delta, onCard, plural } from "@/features/dashboard/format";
import { useResultColors } from "@/styles/colorStore";
import type { CampaignSummary } from "@/features/campaigns/api";
import { formatDay } from "@/features/campaigns/utils";

/** Whole percent, "<1" for a non-zero share that rounds to 0. */
function pct(share: number) {
  const p = Math.round(share * 100);
  return share > 0 && p === 0 ? "<1" : String(p);
}

function shareDelta(prevLabel: string, share: number | null, previous: number | null) {
  if (share === null || previous === null) return `vs ${prevLabel}: no data`;
  // From the rounded values shown, so the delta always matches the two numbers on screen.
  const d = Math.round(share * 100) - Math.round(previous * 100);
  const sign = d > 0 ? "+" : "";
  return `vs ${prevLabel}: ${sign}${d} ${Math.abs(d) === 1 ? "point" : "points"} from ${pct(previous)}%`;
}

export default function CampaignKpis({ summary: s }: { summary: CampaignSummary }) {
  const theme = useTheme();
  const result = useResultColors();
  const prev = `previous ${s.days} days`;

  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", sm: "repeat(2, 1fr)", md: "repeat(3, 1fr)" },
        gap: 2,
      }}
    >
      <Kpi title="Messages" value={s.messages}>
        <Line>{delta(prev, s.messages, s.previous_messages, s.previous_messages > 0)}</Line>
        {s.unclassified > 0 ? <Line>{s.unclassified.toLocaleString()} without a classification</Line> : null}
      </Kpi>

      <Kpi
        title="Dangerous share"
        value={s.dangerous_share === null ? "—" : `${pct(s.dangerous_share)}%`}
        marker={onCard(result.dangerous.main, theme.palette, 3)}
      >
        {s.messages > 0 ? <Line>{plural(s.dangerous, "dangerous message")} of {s.messages.toLocaleString()}</Line> : null}
        <Line>{shareDelta(prev, s.dangerous_share, s.previous_dangerous_share)}</Line>
      </Kpi>

      <Kpi title="Active campaigns" value={s.active_campaigns}>
        <Line>of {s.campaigns.length.toLocaleString()} in this period</Line>
        {s.active_window_hours > 0 ? (
          <Typography variant="caption" color="text.secondary">
            active = seen in the last {s.active_window_hours} hours
          </Typography>
        ) : null}
      </Kpi>

      <Kpi title="Largest campaign" value={s.largest_campaign ? s.largest_campaign.messages : "—"}>
        {s.largest_campaign ? (
          <>
            <Line>messages</Line>
            {/* Full name: it is the campaign's only identity; wrap rather than truncate. */}
            <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: "anywhere" }}>
              {s.largest_campaign.name}
            </Typography>
          </>
        ) : (
          <Line>No campaigns in this period</Line>
        )}
      </Kpi>

      <Kpi title="Peak day" value={s.peak_day ? s.peak_day.count : "—"}>
        {s.peak_day ? (
          <Line>
            messages on <span>{formatDay(s.peak_day.date)}</span>
          </Line>
        ) : null}
      </Kpi>
    </Box>
  );
}
