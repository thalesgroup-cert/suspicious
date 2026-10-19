import * as React from "react";
import {
  Box,
  Button,
  Paper,
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
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { onCard, plural } from "@/features/dashboard/format";
import { useResultColors } from "@/styles/colorStore";
import type { CampaignRow, MailVolumeResponse } from "@/features/campaigns/api";
import { formatDay } from "@/features/campaigns/utils";

// More windows than this turn the strip into a list nobody reads; the table below has them all.
const MAX_BANDS = 5;
// Fixed plot insets, so the campaign strip below lines up with the chart's x axis.
const Y_AXIS_WIDTH = 40;
const RIGHT_MARGIN = 24;

type Row = { idx: number; date: string; other: number; dangerous: number };

/** The UTC day of a datetime ("YYYY-MM-DD"), like the backend's days: an offset time may fall on another day in UTC. */
const utcDay = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
};

/** Evenly spaced tick indices that always end on the last day (never clipped: the chart keeps a right margin). */
function tickIndices(n: number, max: number): number[] {
  if (n <= max) return Array.from({ length: n }, (_, i) => i);
  const step = Math.ceil((n - 1) / (max - 1));
  const out: number[] = [];
  for (let i = 0; i < n - 1; i += step) out.push(i);
  // Drop the tick before the last when the two would collide.
  if (n - 1 - out[out.length - 1] < step / 2) out.pop();
  out.push(n - 1);
  return out;
}

function VolumeTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload?: Row }> }) {
  const row = payload?.[0]?.payload;
  if (!active || !row) return null;
  return (
    <Paper variant="outlined" sx={{ px: 1.25, py: 1 }}>
      <Typography variant="subtitle2" component="p">
        {formatDay(row.date)}
      </Typography>
      <Typography variant="body2">Other: {row.other.toLocaleString()}</Typography>
      <Typography variant="body2">Dangerous: {row.dangerous.toLocaleString()}</Typography>
    </Paper>
  );
}

export default function VolumeChart({ volume, campaigns }: { volume: MailVolumeResponse; campaigns: CampaignRow[] }) {
  const theme = useTheme();
  const result = useResultColors();
  const phone = useMediaQuery(theme.breakpoints.down("sm"), { noSsr: true });
  const [asTable, setAsTable] = React.useState(false);

  const rows: Row[] = volume.dates.map((date, idx) => ({
    idx,
    date,
    other: volume.non_danger[idx] ?? 0,
    dangerous: volume.dangerous[idx] ?? 0,
  }));
  const total = rows.reduce((a, r) => a + r.other + r.dangerous, 0);
  const dangerous = rows.reduce((a, r) => a + r.dangerous, 0);
  // Earliest day wins a tie, like the backend's peak day.
  const peak = rows.reduce<Row | null>((best, r) => (!best || r.other + r.dangerous > best.other + best.dangerous ? r : best), null);

  // Dangerous takes the verdict colour; Other mixes four classes, so it gets the neutral text tone, not a verdict colour.
  const dangerColor = onCard(result.dangerous.main, theme.palette, 3);
  const otherColor = onCard(theme.palette.text.secondary, theme.palette, 3);
  // Campaign windows are not message counts: the theme accent keeps them apart from both areas.
  const barColor = onCard(theme.palette.primary.main, theme.palette, 3);

  const index = new Map(volume.dates.map((d, i) => [d, i]));
  const last = rows.length - 1;
  const bands = campaigns
    .slice(0, MAX_BANDS)
    .map((c, i) => ({ key: `${c.first_seen}|${c.name}|${i}`, name: c.name, s: index.get(utcDay(c.first_seen)), e: index.get(utcDay(c.last_seen)) }))
    .filter((b): b is { key: string; name: string; s: number; e: number } => b.s !== undefined && b.e !== undefined);

  const summary =
    total === 0
      ? "Messages per day: no messages"
      : `Messages per day: ${plural(total, "message")}, ${dangerous.toLocaleString()} dangerous, peak ${formatDay(peak!.date)}`;

  const legend = (
    <Stack component="ul" aria-label="Legend" direction="row" spacing={2} sx={{ m: 0, p: 0, listStyle: "none" }}>
      {[
        ["Other", otherColor],
        ["Dangerous", dangerColor],
      ].map(([label, color]) => (
        <Stack key={label} component="li" direction="row" spacing={0.75} sx={{ alignItems: "center" }}>
          <Box aria-hidden sx={{ width: 10, height: 10, borderRadius: 0.5, bgcolor: color }} />
          <Typography variant="body2">{label}</Typography>
        </Stack>
      ))}
    </Stack>
  );

  return (
    <>
      <Stack direction="row" useFlexGap spacing={1} sx={{ mb: 1, alignItems: "center", justifyContent: "space-between", flexWrap: "wrap" }}>
        {asTable ? <span /> : legend}
        <Button size="small" onClick={() => setAsTable((v) => !v)} aria-pressed={asTable}>
          Table view
        </Button>
      </Stack>

      {asTable ? (
        <TableContainer sx={{ maxHeight: 320 }}>
          <Table size="small" stickyHeader aria-label="Messages per day">
            <TableHead>
              <TableRow>
                <TableCell>Date</TableCell>
                <TableCell align="right">Other</TableCell>
                <TableCell align="right">Dangerous</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={r.date}>
                  <TableCell>{formatDay(r.date)}</TableCell>
                  <TableCell align="right">{r.other.toLocaleString()}</TableCell>
                  <TableCell align="right">{r.dangerous.toLocaleString()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : (
        <Box role="img" aria-label={summary} sx={{ height: 240 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={rows} margin={{ top: 8, right: RIGHT_MARGIN, bottom: 0, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} vertical={false} />
              <XAxis
                type="number"
                dataKey="idx"
                domain={[0, Math.max(last, 1)]}
                ticks={tickIndices(rows.length, phone ? 4 : 8)}
                tickFormatter={(i: number) => formatDay(rows[i]?.date ?? "")}
                tick={{ fill: theme.palette.text.secondary, fontSize: theme.typography.caption.fontSize }}
                stroke={theme.palette.divider}
              />
              <YAxis
                width={Y_AXIS_WIDTH}
                allowDecimals={false}
                tick={{ fill: theme.palette.text.secondary, fontSize: theme.typography.caption.fontSize }}
                stroke={theme.palette.divider}
              />
              <Tooltip content={<VolumeTooltip />} cursor={{ stroke: theme.palette.divider }} />
              <Area
                type="linear"
                dataKey="other"
                name="Other"
                stackId="v"
                stroke={otherColor}
                fill={otherColor}
                fillOpacity={0.18}
                isAnimationActive={false}
              />
              <Area
                type="linear"
                dataKey="dangerous"
                name="Dangerous"
                stackId="v"
                stroke={dangerColor}
                fill={dangerColor}
                fillOpacity={0.35}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </Box>
      )}

      {bands.length > 0 && !asTable ? (
        // Named windows under the axis instead of shaded areas: overlapping shades washed the whole plot grey and named nothing.
        <Box sx={{ mt: 1.5, pl: `${Y_AXIS_WIDTH}px`, pr: `${RIGHT_MARGIN}px` }}>
          <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 0.5 }}>
            Campaign windows: first to last day seen for{" "}
            {campaigns.length > MAX_BANDS ? `the ${MAX_BANDS} largest of ${campaigns.length} campaigns` : plural(bands.length, "campaign")}.
          </Typography>
          <Stack component="ul" spacing={0.75} sx={{ m: 0, p: 0, listStyle: "none" }}>
            {bands.map((b) => {
              const span = Math.max(last, 1);
              const left = (Math.max(0, b.s - 0.5) / span) * 100;
              const right = (Math.min(last, b.e + 0.5) / span) * 100;
              return (
                <Box component="li" key={b.key}>
                  <Typography variant="caption" component="p" sx={{ overflowWrap: "anywhere" }}>
                    {b.name} · {formatDay(rows[b.s].date)}
                    {b.e !== b.s ? ` to ${formatDay(rows[b.e].date)}` : ""}
                  </Typography>
                  <Box sx={{ position: "relative", height: 6 }}>
                    <Box
                      aria-hidden
                      sx={{ position: "absolute", top: 0, bottom: 0, left: `${left}%`, width: `max(4px, ${right - left}%)`, borderRadius: 1, bgcolor: barColor }}
                    />
                  </Box>
                </Box>
              );
            })}
          </Stack>
        </Box>
      ) : null}
    </>
  );
}
