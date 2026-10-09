import { decomposeColor, rgbToHex } from "@mui/material/styles";

type RGB = [number, number, number];
const rgb = (c: string): RGB => decomposeColor(c).values.slice(0, 3) as RGB;

const lum = ([r, g, b]: RGB) => {
  const f = (v: number) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
};

/** WCAG contrast ratio between two opaque colours. */
export function contrastRatio(a: string, b: string): number {
  const [x, y] = [lum(rgb(a)), lum(rgb(b))].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

/** A translucent fill composited over an opaque background, as a hex string. */
export function composite(fill: string, alpha: number, over: string): string {
  const f = rgb(fill), b = rgb(over);
  return rgbToHex(`rgb(${[0, 1, 2].map((i) => Math.round(f[i] * alpha + b[i] * (1 - alpha))).join(",")})`);
}

function toHsl([r, g, b]: RGB): [number, number, number] {
  r /= 255; g /= 255; b /= 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b), l = (max + min) / 2, d = max - min;
  if (!d) return [0, 0, l];
  const s = d / (1 - Math.abs(2 * l - 1));
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return [(h * 60 + 360) % 360, s, l];
}
function fromHsl(h: number, s: number, l: number): string {
  const k = (n: number) => (n + h / 30) % 12, a = s * Math.min(l, 1 - l);
  const f = (n: number) => Math.round(255 * (l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)))));
  return rgbToHex(`rgb(${f(0)},${f(8)},${f(4)})`);
}

/**
 * Moves fg toward black (light bg) or white (dark bg) in HSL lightness steps, keeping hue and saturation,
 * until it reaches `min`:1 on bg (or the extreme). A colour that already passes is returned unchanged. Inputs must be hex or rgb()/rgba(), not hsl() or color().
 */
export function ensureContrast(fg: string, bg: string, min = 4.5): string {
  const key = `${fg}|${bg}|${min}`;
  const hit = cache.get(key);
  if (hit) return hit;
  if (cache.size > 500) cache.clear();
  const out = adjust(fg, bg, min);
  cache.set(key, out);
  return out;
}

// Chips re-render a lot and the stepping loop is up to 100 iterations; same inputs always give the same output.
const cache = new Map<string, string>();

function adjust(fg: string, bg: string, min: number): string {
  if (contrastRatio(fg, bg) >= min) return fg;
  const [h, s, l] = toHsl(rgb(fg));
  const dir = lum(rgb(bg)) > 0.179 ? -1 : 1;
  let best = fg;
  for (let step = 1; step <= 100; step++) {
    const nl = Math.min(1, Math.max(0, l + (dir * step) / 100));
    best = fromHsl(h, s, nl);
    if (contrastRatio(best, bg) >= min || nl === 0 || nl === 1) break;
  }
  return contrastRatio(best, bg) > contrastRatio(fg, bg) ? best : fg;
}

/** Text colour `fg` for a chip filled with `tint` at `alpha`, readable on that fill over every page background it can sit on. */
export function readableOnTint(fg: string, tint: string, alpha: number, backgrounds: string[], min = 4.5): string {
  return backgrounds.reduce((out, bg) => ensureContrast(out, composite(tint, alpha, bg), min), fg);
}

/** Any colour (including rgba) laid over an opaque background, as an opaque hex; `extraAlpha` scales its own alpha. */
export function flatten(color: string, over: string, extraAlpha = 1): string {
  const v = decomposeColor(color).values;
  return composite(color, (v[3] ?? 1) * extraAlpha, over);
}
