import * as React from "react";
import { Box, Chip, Paper, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { CartesianGrid, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis } from "recharts";

import { plural } from "@/features/dashboard/format";
import { readableOnTint } from "@/shared/lib/contrast";
import type { PcaPoint } from "@/features/campaigns/api";
import { CLASSES, classLabel, normalizeLabel, useClassColors, type ClassKey } from "@/features/campaigns/utils";

const R = 3;
const CHIP_TINT = 0.18;

/** [min, max] of the values, padded 5% (or ±1 when they are all equal), so every point sits inside the axes. */
function fit(values: number[]): [number, number] {
  if (!values.length) return [-1, 1];
  const lo = Math.min(...values);
  const hi = Math.max(...values);
  const pad = hi > lo ? (hi - lo) * 0.05 : 1;
  return [lo - pad, hi + pad];
}

/** Five evenly spaced ticks across the fitted domain: recharts' own picks crowded the last two labels together. */
const ticks = ([lo, hi]: [number, number]) => Array.from({ length: 5 }, (_, i) => lo + ((hi - lo) * i) / 4);

function PointTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload?: PcaPoint }> }) {
  const p = payload?.[0]?.payload;
  if (!active || !p) return null;
  return (
    <Paper variant="outlined" sx={{ px: 1.25, py: 1, maxWidth: 280 }}>
      <Typography variant="subtitle2" component="p">
        {classLabel(p.label)}
      </Typography>
      {p.mail_subject ? <Typography variant="body2">{p.mail_subject}</Typography> : null}
      {p.suspicious_case_id ? (
        <Typography variant="caption" color="text.secondary">
          Case {p.suspicious_case_id}
        </Typography>
      ) : null}
    </Paper>
  );
}

/** 2D scatter of the first two components (Task 4 puts the 3D map in front of it). */
export default function Embedding2D({ points, selectedCaseIds }: { points: PcaPoint[]; selectedCaseIds: string[] }) {
  const theme = useTheme();
  const colors = useClassColors();
  const [hidden, setHidden] = React.useState<ClassKey[]>([]);
  const selected = new Set(selectedCaseIds);

  const byClass = new Map<string, PcaPoint[]>();
  for (const p of points) {
    const k = normalizeLabel(p.label);
    byClass.set(k, [...(byClass.get(k) ?? []), p]);
  }
  const visible = points.filter((p) => !hidden.includes(normalizeLabel(p.label) as ClassKey));
  const xDomain = fit(visible.map((p) => p.x));
  const yDomain = fit(visible.map((p) => p.y));
  const backgrounds = [theme.palette.background.paper, theme.palette.background.default];
  const tick = { fill: theme.palette.text.secondary, fontSize: theme.typography.caption.fontSize };
  const counts = CLASSES.map(([k, l]) => `${l} ${byClass.get(k)?.length ?? 0}`).join(", ");

  const toggle = (k: ClassKey) => setHidden((h) => (h.includes(k) ? h.filter((x) => x !== k) : [...h, k]));

  return (
    <>
      <Stack direction="row" useFlexGap spacing={0.75} sx={{ flexWrap: "wrap", mb: 1 }}>
        {CLASSES.map(([k, label]) => {
          const on = !hidden.includes(k);
          return (
            <Chip
              key={k}
              size="small"
              clickable
              aria-pressed={on}
              onClick={() => toggle(k)}
              icon={<Box component="span" aria-hidden sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: colors[k], ml: "6px !important" }} />}
              label={`${label} ${byClass.get(k)?.length ?? 0}`}
              variant="outlined"
              sx={{
                borderColor: on ? colors[k] : "divider",
                // Tinted, not filled: white on orange/cyan fell to about 2:1 (audit C7).
                bgcolor: on ? alpha(colors[k], CHIP_TINT) : "transparent",
                color: on ? readableOnTint(theme.palette.text.primary, colors[k], CHIP_TINT, backgrounds) : "text.secondary",
                textDecoration: on ? "none" : "line-through",
              }}
            />
          );
        })}
      </Stack>
      <Box role="img" aria-label={`Embedding map, first two components, ${plural(points.length, "message")}: ${counts}`} sx={{ height: 360 }}>
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 8, right: 16, bottom: 0, left: -8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
            <XAxis type="number" dataKey="x" name="PC1" domain={xDomain} ticks={ticks(xDomain)} tickFormatter={(v: number) => v.toFixed(1)} tick={tick} stroke={theme.palette.divider} />
            <YAxis type="number" dataKey="y" name="PC2" domain={yDomain} ticks={ticks(yDomain)} tickFormatter={(v: number) => v.toFixed(1)} tick={tick} stroke={theme.palette.divider} />
            <Tooltip content={<PointTooltip />} cursor={{ stroke: theme.palette.divider }} />
            {CLASSES.filter(([k]) => !hidden.includes(k)).map(([k]) => (
              <Scatter
                key={k}
                name={k}
                data={byClass.get(k) ?? []}
                fill={colors[k]}
                isAnimationActive={false}
                shape={(props: { cx?: number; cy?: number; payload?: PcaPoint }) => {
                  const on = props.payload?.suspicious_case_id ? selected.has(props.payload.suspicious_case_id) : false;
                  return (
                    <circle
                      cx={props.cx}
                      cy={props.cy}
                      r={on ? R + 2 : R}
                      fill={colors[k]}
                      stroke={on ? theme.palette.text.primary : "none"}
                      strokeWidth={on ? 1.5 : 0}
                    />
                  );
                }}
              />
            ))}
          </ScatterChart>
        </ResponsiveContainer>
      </Box>
    </>
  );
}
