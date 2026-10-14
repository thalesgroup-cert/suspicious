import { Typography } from "@mui/material";

const W = 120;
const H = 32;
const PAD = 3; // room for the end dot

/** Weekly values as a small line; fewer than two points cannot make a line, so they read as text. */
export function Sparkline({ values, label }: { values: number[]; label: string }) {
  if (values.length === 0) return null;
  if (values.length === 1) {
    return (
      <Typography variant="caption" color="text.secondary">
        {label}: {values[0].toLocaleString()}
      </Typography>
    );
  }
  const max = Math.max(...values, 1);
  const pts = values.map((v, i) => [
    PAD + (i * (W - 2 * PAD)) / (values.length - 1),
    H - PAD - (v / max) * (H - 2 * PAD),
  ]);
  const [lx, ly] = pts[pts.length - 1];
  return (
    <svg role="img" aria-label={`${label}: ${values.join(", ")}`} width={W} height={H} viewBox={`0 0 ${W} ${H}`}>
      <polyline
        points={pts.map((p) => p.join(",")).join(" ")}
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      <circle cx={lx} cy={ly} r={2.5} fill="currentColor" />
    </svg>
  );
}
