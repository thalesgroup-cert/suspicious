import { fbm } from "./noise";
import { loadLogoMask, maskToSprite, type LogoMask } from "./logoMask";

export type Rgb = readonly [number, number, number];

export type GlyphSmokePalette = {
  /** Page background; also what the canvas is cleared to. */
  bg: string;
  /** Sparse smoke. */
  base: Rgb;
  /** Dense smoke. */
  dense: Rgb;
  /** Glyphs under the pointer. */
  hot: Rgb;
  /** Click light: the logo-shaped ripple. */
  ripple: Rgb;
};

export const DEFAULT_PALETTE: GlyphSmokePalette = {
  bg: "#151515",
  base: [52, 100, 150],
  dense: [104, 166, 200],
  hot: [226, 235, 222],
  ripple: [70, 150, 255],
};

export type GlyphSmokeStats = {
  frames: number;
  lit: number;
  hoverCells: number;
  rippleCells: number;
  ripples: number;
  logoReady: boolean;
};

export type GlyphSmoke = {
  start(): void;
  stop(): void;
  resize(): void;
  /** `null` clears the pointer. */
  pointer(x: number | null, y?: number): void;
  ripple(x: number, y: number): void;
  /** Draws one frame at `time` seconds without scheduling the next. */
  renderOnce(time?: number): void;
  destroy(): void;
  stats: GlyphSmokeStats;
  /** Test hook: stop ripples ageing and place one at a given age (seconds). */
  debug: { freeze: boolean; spawn(x: number, y: number, age: number): void; clear(): void };
};

export type GlyphSmokeOptions = {
  logoUrl: string;
  palette?: Partial<GlyphSmokePalette>;
  /** Draw a single still frame: no loop, no pointer response. */
  reducedMotion?: boolean;
};

const CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const CW = 7.2;
const CH = 14;
const FONT_PX = 11;
const FONT_FAMILY = 'ui-monospace, "IBM Plex Mono", "SF Mono", Menlo, Consolas, monospace';
const HOVER_R = 110;
const RIPPLE_LIFE = 2.2;
/** Seconds between the logo and each echo that follows it, and each echo's strength. */
const ECHO_DELAY = 0.2;
const ECHO_GAIN = [1, 0.62, 0.38] as const;
const ALPHA_LEVELS = 12;
const RAMP = 6; // colour steps per ramp
const RAMPS = 3; // smoke, ripple, hover
const KEYS = ALPHA_LEVELS * RAMP * RAMPS;
const MAX_RIPPLES = 6;
/** Peak alpha of idle smoke. Kept low: UI text sits on top of it. */
const AMBIENT = 0.42;

type Ripple = { x: number; y: number; t: number };

const clamp01 = (v: number) => (v < 0 ? 0 : v > 1 ? 1 : v);
const mix = (a: Rgb, b: Rgb, t: number): Rgb => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
const easeOut = (t: number) => 1 - (1 - t) * (1 - t) * (1 - t);

export function createGlyphSmoke(canvas: HTMLCanvasElement, opts: GlyphSmokeOptions): GlyphSmoke | null {
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  const palette: GlyphSmokePalette = { ...DEFAULT_PALETTE, ...opts.palette };

  const stats: GlyphSmokeStats = { frames: 0, lit: 0, hoverCells: 0, rippleCells: 0, ripples: 0, logoReady: false };
  const ripples: Ripple[] = [];
  const pointer = { x: -9999, y: -9999, on: false };
  const debug = { freeze: false, spawn: (x: number, y: number, age: number) => { ripples.push({ x, y, t: age }); }, clear: () => { ripples.length = 0; } };

  let W = 0, H = 0, dpr = 1, cols = 0, rows = 0;
  let glyph = new Uint8Array(0);
  let vignette = new Float32Array(0);
  // Lit cells are sorted by (alpha level, colour step) so fillStyle changes once per group, not once per glyph.
  let keyOf = new Uint8Array(0);
  let order = new Int32Array(0);
  const counts = new Int32Array(KEYS);
  let mask: LogoMask | null = null;
  let fillSprite: HTMLCanvasElement | null = null;
  let edgeSprite: HTMLCanvasElement | null = null;
  let raf = 0, running = false, last = 0, t0 = 0, destroyed = false;

  // Colour ramps the atlas is drawn in: smoke (base → dense), ripple (blue → pale blue), hover (blue → hot).
  const ramps: Rgb[][] = [
    Array.from({ length: RAMP }, (_, i) => mix(palette.base, palette.dense, i / (RAMP - 1))),
    Array.from({ length: RAMP }, (_, i) => mix(palette.ripple, [190, 225, 255], i / (RAMP - 1))),
    Array.from({ length: RAMP }, (_, i) => mix(palette.dense, palette.hot, i / (RAMP - 1))),
  ];

  const styles: string[] = [];
  for (let level = 0; level < ALPHA_LEVELS; level++) {
    for (let row = 0; row < RAMP * RAMPS; row++) {
      const rgb = ramps[(row / RAMP) | 0][row % RAMP];
      styles.push(`rgba(${rgb[0] | 0},${rgb[1] | 0},${rgb[2] | 0},${((level + 0.5) / ALPHA_LEVELS).toFixed(3)})`);
    }
  }

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = canvas.clientWidth || window.innerWidth;
    H = canvas.clientHeight || window.innerHeight;
    canvas.width = Math.max(1, Math.round(W * dpr));
    canvas.height = Math.max(1, Math.round(H * dpr));
    cols = Math.ceil(W / CW) + 1;
    rows = Math.ceil(H / CH) + 1;
    const n = cols * rows;
    glyph = new Uint8Array(n);
    for (let i = 0; i < n; i++) glyph[i] = (Math.random() * CHARS.length) | 0;
    // Fewer glyphs toward the viewport edge.
    vignette = new Float32Array(n);
    const edge = 90;
    for (let j = 0; j < rows; j++) {
      const cy = j * CH + CH / 2;
      for (let i = 0; i < cols; i++) {
        const cx = i * CW + CW / 2;
        const e = Math.min(Math.min(cx, W - cx) / edge, Math.min(cy, H - cy) / edge);
        vignette[j * cols + i] = clamp01(e * 0.5 + 0.5);
      }
    }
    keyOf = new Uint8Array(n);
    order = new Int32Array(n);
  }

  // Logo sprites are built once the image has loaded. Until then clicks still draw nothing but never throw.
  void loadLogoMask(opts.logoUrl).then((m) => {
    if (destroyed || !m) return;
    mask = m;
    fillSprite = maskToSprite(m.fill, m.w, m.h, palette.ripple);
    edgeSprite = maskToSprite(m.edge, m.w, m.h, [150, 205, 255]);
    stats.logoReady = true;
  });

  const logoSize = () => {
    const base = Math.min(560, 0.5 * Math.max(W, H));
    const aspect = mask ? mask.h / mask.w : 1.13;
    return { lw: base, lh: base * aspect };
  };
  /** Logo scale for an echo at age `te`: it blooms out from a small form. */
  const logoScale = (te: number) => 0.4 + 1.1 * easeOut(clamp01(te / RIPPLE_LIFE));
  const echoAlpha = (te: number, k: number) => Math.pow(1 - clamp01(te / RIPPLE_LIFE), 1.6) * ECHO_GAIN[k];

  function frame(time: number, dt: number) {
    if (!debug.freeze) for (let i = ripples.length - 1; i >= 0; i--) { ripples[i].t += dt; if (ripples[i].t > RIPPLE_LIFE + ECHO_DELAY * 2) ripples.splice(i, 1); }

    ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx!.globalAlpha = 1;
    ctx!.globalCompositeOperation = "source-over";
    ctx!.fillStyle = palette.bg;
    ctx!.fillRect(0, 0, W, H);

    const { lw, lh } = logoSize();

    // Blue light: the logo, as a soft silhouette, then two fainter rims blooming out behind it.
    if (mask && fillSprite && edgeSprite) {
      ctx!.globalCompositeOperation = "lighter";
      ctx!.imageSmoothingEnabled = true;
      for (const r of ripples) {
        for (let k = 0; k < ECHO_GAIN.length; k++) {
          const te = r.t - k * ECHO_DELAY;
          if (te < 0 || te > RIPPLE_LIFE) continue;
          const s = logoScale(te);
          ctx!.globalAlpha = Math.min(1, echoAlpha(te, k) * (k === 0 ? 0.55 : 0.8));
          ctx!.drawImage(k === 0 ? fillSprite : edgeSprite, r.x - (lw * s) / 2, r.y - (lh * s) / 2, lw * s, lh * s);
        }
      }
      ctx!.globalAlpha = 1;
      ctx!.globalCompositeOperation = "source-over";
    }

    counts.fill(0);
    keyOf.fill(0);
    let lit = 0, hov = 0, rip = 0;
    const churn = Math.max(1, Math.round(cols * rows * 0.0016));
    if (!debug.freeze) for (let n = 0; n < churn; n++) glyph[(Math.random() * glyph.length) | 0] = (Math.random() * CHARS.length) | 0;

    for (let j = 0; j < rows; j++) {
      const cy = j * CH + CH / 2;
      for (let i = 0; i < cols; i++) {
        const idx = j * cols + i;
        const cx = i * CW + CW / 2;

        // Smoke: slow fbm field, thresholded into wisps.
        const n = fbm(cx / 210 + time * 0.035, cy / 150 - time * 0.05, time * 0.06);
        let d = (n - 0.47) * 3.4;
        d = d > 0 ? Math.pow(Math.min(d, 1), 1.25) : 0;
        d *= vignette[idx];

        let hot = 0;
        if (pointer.on) {
          const dx = cx - pointer.x, dy = cy - pointer.y;
          const q = 1 - Math.sqrt(dx * dx + dy * dy) / HOVER_R;
          if (q > 0) { hot = q * q * (3 - 2 * q); hov++; }
        }

        let blue = 0;
        if (mask) {
          for (const r of ripples) {
            for (let k = 0; k < ECHO_GAIN.length; k++) {
              const te = r.t - k * ECHO_DELAY;
              if (te < 0 || te > RIPPLE_LIFE) continue;
              const s = logoScale(te);
              const u = (cx - r.x) / (lw * s) + 0.5;
              const v = (cy - r.y) / (lh * s) + 0.5;
              if (u < 0 || v < 0 || u >= 1 || v >= 1) continue;
              const m = (k === 0 ? mask.fill : mask.edge)[((v * mask.h) | 0) * mask.w + ((u * mask.w) | 0)];
              const val = m * echoAlpha(te, k);
              if (val > blue) blue = val;
              if (k === 0 && val > 0.25 && Math.random() < 0.12) glyph[idx] = (Math.random() * CHARS.length) | 0;
            }
          }
        }
        if (blue > 0.05) rip++;

        const a = Math.max(d * AMBIENT, hot * 0.9, blue * 1.1);
        const level = Math.min(ALPHA_LEVELS - 1, Math.floor(a * ALPHA_LEVELS));
        if (a < 0.04) continue;

        const ramp = hot > blue && hot > 0.05 ? 2 : blue > 0.05 ? 1 : 0;
        const driver = ramp === 2 ? hot : ramp === 1 ? blue : d;
        const key = level * RAMP * RAMPS + ramp * RAMP + Math.min(RAMP - 1, Math.floor(driver * RAMP));
        keyOf[idx] = key + 1;
        counts[key]++;
        lit++;
      }
    }

    // Counting sort by key, then one fillStyle per group.
    let acc = 0;
    const start = new Int32Array(KEYS);
    for (let k = 0; k < KEYS; k++) { start[k] = acc; acc += counts[k]; }
    const next = start.slice();
    for (let idx = 0; idx < keyOf.length; idx++) { const k = keyOf[idx]; if (k) order[next[k - 1]++] = idx; }
    ctx!.font = `600 ${FONT_PX}px ${FONT_FAMILY}`;
    ctx!.textBaseline = "top";
    for (let k = 0; k < KEYS; k++) {
      if (!counts[k]) continue;
      ctx!.fillStyle = styles[k];
      for (let n = start[k], end = start[k] + counts[k]; n < end; n++) {
        const idx = order[n];
        const j = (idx / cols) | 0, i = idx - j * cols;
        ctx!.fillText(CHARS[glyph[idx]], i * CW, j * CH);
      }
    }

    stats.frames++;
    stats.lit = lit;
    stats.hoverCells = hov;
    stats.rippleCells = rip;
    stats.ripples = ripples.length;
  }

  function loop(now: number) {
    if (!running) return;
    const dt = Math.min((now - last) / 1000, 0.05);
    last = now;
    frame((now - t0) / 1000, dt);
    raf = requestAnimationFrame(loop);
  }

  const api: GlyphSmoke = {
    stats,
    debug,
    start() {
      if (running || destroyed) return;
      if (opts.reducedMotion) { api.renderOnce(); return; }
      running = true;
      t0 = last = performance.now();
      raf = requestAnimationFrame(loop);
    },
    stop() { running = false; cancelAnimationFrame(raf); },
    resize() {
      resize();
      if (!running) api.renderOnce();
    },
    pointer(x, y = 0) {
      if (opts.reducedMotion) return;
      if (x === null) { pointer.on = false; pointer.x = pointer.y = -9999; return; }
      pointer.x = x; pointer.y = y; pointer.on = true;
    },
    ripple(x, y) {
      if (opts.reducedMotion || destroyed) return;
      if (ripples.length >= MAX_RIPPLES) ripples.shift();
      ripples.push({ x, y, t: 0 });
    },
    renderOnce(time = 0) { frame(time, 0); },
    destroy() { destroyed = true; api.stop(); ripples.length = 0; },
  };

  resize();
  return api;
}
