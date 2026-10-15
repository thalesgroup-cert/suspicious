// Seeded 3D value noise: x/y drift the smoke, z is time.

const perm = new Uint8Array(512);
(function seed() {
  const p = Array.from({ length: 256 }, (_, i) => i);
  let s = 1337;
  for (let i = 255; i > 0; i--) {
    s = (s * 16807) % 2147483647;
    const j = s % (i + 1);
    [p[i], p[j]] = [p[j], p[i]];
  }
  for (let i = 0; i < 512; i++) perm[i] = p[i & 255];
})();

const fade = (t: number) => t * t * t * (t * (t * 6 - 15) + 10);
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const hash = (x: number, y: number, z: number) => perm[perm[perm[x & 255] + (y & 255)] + (z & 255)] / 255;

export function noise3(x: number, y: number, z: number): number {
  const xi = Math.floor(x), yi = Math.floor(y), zi = Math.floor(z);
  const xf = fade(x - xi), yf = fade(y - yi), zf = fade(z - zi);
  return lerp(
    lerp(
      lerp(hash(xi, yi, zi), hash(xi + 1, yi, zi), xf),
      lerp(hash(xi, yi + 1, zi), hash(xi + 1, yi + 1, zi), xf),
      yf,
    ),
    lerp(
      lerp(hash(xi, yi, zi + 1), hash(xi + 1, yi, zi + 1), xf),
      lerp(hash(xi, yi + 1, zi + 1), hash(xi + 1, yi + 1, zi + 1), xf),
      yf,
    ),
    zf,
  );
}

/** Three octaves, weights sum to 1, so the result stays in [0, 1]. */
export function fbm(x: number, y: number, z: number): number {
  return 0.55 * noise3(x, y, z) + 0.28 * noise3(x * 2.1, y * 2.1, z * 1.6 + 9) + 0.17 * noise3(x * 4.3, y * 4.3, z * 2.2 + 21);
}
