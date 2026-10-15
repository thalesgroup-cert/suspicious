// Turns the Suspicious logo's alpha channel into soft masks the ripple is drawn from.

export type LogoMask = {
  w: number;
  h: number;
  /** Silhouette, 0..1. */
  fill: Float32Array;
  /** Rim of the silhouette, 0..1: what the trailing echoes are drawn from. */
  edge: Float32Array;
};

const MASK_W = 240;

function boxBlur(src: Float32Array, w: number, h: number): Float32Array {
  const out = new Float32Array(src.length);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      let sum = 0, n = 0;
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          const xx = x + dx, yy = y + dy;
          if (xx < 0 || yy < 0 || xx >= w || yy >= h) continue;
          sum += src[yy * w + xx];
          n++;
        }
      }
      out[y * w + x] = sum / n;
    }
  }
  return out;
}

function erode(src: Float32Array, w: number, h: number, radius: number): Float32Array {
  const out = new Float32Array(src.length);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      let m = 1;
      for (let dy = -radius; dy <= radius && m > 0; dy++) {
        for (let dx = -radius; dx <= radius; dx++) {
          const xx = x + dx, yy = y + dy;
          const v = xx < 0 || yy < 0 || xx >= w || yy >= h ? 0 : src[yy * w + xx];
          if (v < m) m = v;
        }
      }
      out[y * w + x] = m;
    }
  }
  return out;
}

/** `alpha` is RGBA bytes (4 per pixel) of a w×h image. */
export function buildLogoMask(rgba: Uint8ClampedArray, w: number, h: number): LogoMask {
  const raw = new Float32Array(w * h);
  for (let i = 0; i < raw.length; i++) raw[i] = rgba[i * 4 + 3] > 40 ? 1 : 0;
  const fill = boxBlur(raw, w, h);
  const inner = erode(raw, w, h, 4);
  const edge = boxBlur(raw.map((v, i) => Math.max(0, v - inner[i])), w, h);
  for (let i = 0; i < edge.length; i++) edge[i] = Math.min(1, edge[i] * 2.2);
  return { w, h, fill, edge };
}

/** Loads the logo and samples it at MASK_W px wide. Resolves null when the image or a 2D context is unavailable. */
export function loadLogoMask(url: string): Promise<LogoMask | null> {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => {
      try {
        const w = MASK_W;
        const h = Math.max(1, Math.round((img.naturalHeight / img.naturalWidth) * w));
        const c = document.createElement("canvas");
        c.width = w;
        c.height = h;
        const g = c.getContext("2d", { willReadFrequently: true });
        if (!g) return resolve(null);
        g.drawImage(img, 0, 0, w, h);
        resolve(buildLogoMask(g.getImageData(0, 0, w, h).data, w, h));
      } catch {
        resolve(null);
      }
    };
    img.onerror = () => resolve(null);
    img.src = url;
  });
}

/** Mask sprite: `color` tinted, alpha = mask * 255. Upscaling it gives a soft glow in the shape of the logo. */
export function maskToSprite(mask: Float32Array, w: number, h: number, rgb: readonly [number, number, number]): HTMLCanvasElement | null {
  const c = document.createElement("canvas");
  c.width = w;
  c.height = h;
  const g = c.getContext("2d");
  if (!g) return null;
  const img = g.createImageData(w, h);
  for (let i = 0; i < mask.length; i++) {
    img.data[i * 4] = rgb[0];
    img.data[i * 4 + 1] = rgb[1];
    img.data[i * 4 + 2] = rgb[2];
    img.data[i * 4 + 3] = Math.round(mask[i] * 255);
  }
  g.putImageData(img, 0, 0);
  return c;
}
