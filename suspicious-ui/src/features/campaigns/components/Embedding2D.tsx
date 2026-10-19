import * as React from "react";
import { Box, Stack } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { CartesianGrid, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis } from "recharts";

import { plural } from "@/features/dashboard/format";
import type { PcaPoint } from "@/features/campaigns/api";
import { SERIES, classKey, classLabel, useClassColors, type SeriesKey } from "@/features/campaigns/utils";
import ClassChip from "./ClassChip";
import MapTooltip from "./MapTooltip";

const R = 3;

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

/** Decimals that keep the five labels distinct: two significant digits of the step between ticks. */
const decimals = ([lo, hi]: [number, number]) => Math.min(6, Math.max(0, 1 - Math.floor(Math.log10((hi - lo) / 4))));

function PointTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload?: PcaPoint }> }) {
  const p = payload?.[0]?.payload;
  return active && p ? <MapTooltip point={p} /> : null;
}

/** 2D scatter of the first two components: the fallback when there is no WebGL or no third component, or when the user prefers it. */
export default function Embedding2D({ points, selectedCaseIds }: { points: PcaPoint[]; selectedCaseIds: string[] }) {
  const theme = useTheme();
  const colors = useClassColors();
  const [hidden, setHidden] = React.useState<SeriesKey[]>([]);
  const selected = React.useMemo(() => new Set(selectedCaseIds), [selectedCaseIds]);

  const byClass = React.useMemo(() => {
    const m = new Map<SeriesKey, PcaPoint[]>();
    for (const p of points) {
      const k = classKey(p.label);
      const list = m.get(k);
      if (list) list.push(p);
      else m.set(k, [p]);
    }
    return m;
  }, [points]);
  // The four classes are always listed; "Unclassified" only when the sample holds such messages.
  const series = SERIES.filter(([k]) => k !== "UNKNOWN" || byClass.has("UNKNOWN"));
  const drawn = series.filter(([k]) => !hidden.includes(k));
  // The axes follow exactly what is drawn.
  const { xDomain, yDomain } = React.useMemo(() => {
    const visible = [...byClass].filter(([k]) => !hidden.includes(k)).flatMap(([, list]) => list);
    return { xDomain: fit(visible.map((p) => p.x)), yDomain: fit(visible.map((p) => p.y)) };
  }, [byClass, hidden]);
  const tick = { fill: theme.palette.text.secondary, fontSize: theme.typography.caption.fontSize };
  const counts = series.map(([k, l]) => `${l} ${byClass.get(k)?.length ?? 0}`).join(", ");

  const toggle = (k: SeriesKey) => setHidden((h) => (h.includes(k) ? h.filter((x) => x !== k) : [...h, k]));

  return (
    <>
      <Stack direction="row" useFlexGap spacing={0.75} sx={{ flexWrap: "wrap", mb: 1 }}>
        {series.map(([k, label]) => (
          <ClassChip key={k} k={k} label={`${label} ${byClass.get(k)?.length ?? 0}`} on={!hidden.includes(k)} clickable aria-pressed={!hidden.includes(k)} onClick={() => toggle(k)} />
        ))}
      </Stack>
      <Box role="img" aria-label={`Embedding map, first two components, ${plural(points.length, "message")}: ${counts}`} sx={{ height: 360 }}>
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 8, right: 16, bottom: 0, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
            <XAxis
              type="number"
              dataKey="x"
              name="PC1"
              domain={xDomain}
              ticks={ticks(xDomain)}
              tickFormatter={(v: number) => v.toFixed(decimals(xDomain))}
              tick={tick}
              stroke={theme.palette.divider}
              height={44}
              label={{ value: "PC1", position: "insideBottom", offset: 0, ...tick }}
            />
            <YAxis
              type="number"
              dataKey="y"
              name="PC2"
              domain={yDomain}
              ticks={ticks(yDomain)}
              tickFormatter={(v: number) => v.toFixed(decimals(yDomain))}
              tick={tick}
              stroke={theme.palette.divider}
              width={64}
              label={{ value: "PC2", angle: -90, position: "insideLeft", offset: 8, style: { textAnchor: "middle" }, ...tick }}
            />
            <Tooltip content={<PointTooltip />} cursor={{ stroke: theme.palette.divider }} />
            {drawn.map(([k]) => (
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
