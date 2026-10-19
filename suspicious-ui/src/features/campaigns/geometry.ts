// Pure maths for the 3D embedding map: no three.js import, so all of it is unit-tested without WebGL.

export type Vec3 = [number, number, number];
export type XYZ = { x: number; y: number; z: number };

const xyz = (p: XYZ): Vec3 => [p.x, p.y, p.z];

// ---------------------------------------------------------------- bounds and scale

export type Bounds = { min: Vec3; max: Vec3; center: Vec3; extent: Vec3 };

/** The box around the points; null when there are none. */
export function bounds(points: XYZ[]): Bounds | null {
  if (!points.length) return null;
  const min = xyz(points[0]);
  const max = xyz(points[0]);
  for (const p of points) {
    const v = xyz(p);
    for (let i = 0; i < 3; i++) {
      if (v[i] < min[i]) min[i] = v[i];
      if (v[i] > max[i]) max[i] = v[i];
    }
  }
  return {
    min,
    max,
    center: [0, 1, 2].map((i) => (min[i] + max[i]) / 2) as Vec3,
    extent: [0, 1, 2].map((i) => max[i] - min[i]) as Vec3,
  };
}

/** scene = (real - offset) * scale. One scale for all three axes, so distances keep their proportions. */
export type Normalisation = { offset: Vec3; scale: number };

/** Fits the points in the box -1..1 (the widest axis touches it). Always finite, whatever the points. */
export function normalise(points: XYZ[]): Normalisation {
  const b = bounds(points);
  if (!b) return { offset: [0, 0, 0], scale: 1 };
  const half = Math.max(...b.extent) / 2;
  return { offset: b.center, scale: half > 0 ? 1 / half : 1 };
}

export const toScene = (p: Vec3, n: Normalisation): Vec3 => [(p[0] - n.offset[0]) * n.scale, (p[1] - n.offset[1]) * n.scale, (p[2] - n.offset[2]) * n.scale];

// ---------------------------------------------------------------- category clouds

export type Ellipsoid = { center: Vec3; axes: [Vec3, Vec3, Vec3]; radii: Vec3 };

/** Fewer points than this and a covariance says little: no cloud is drawn. */
export const MIN_CLOUD_POINTS = 5;
// A flat or straight cloud has eigenvalues of about 0: keep them at a millionth of the largest so it still draws (as a thin sheet or needle).
const FLAT = 1e-6;

/** Eigen decomposition of a symmetric 3x3 matrix by cyclic Jacobi rotations; eigenvectors are the columns of `vectors`. */
function jacobi(m: number[][]): { values: Vec3; vectors: number[][] } {
  const a = m.map((r) => [...r]);
  const v = [[1, 0, 0], [0, 1, 0], [0, 0, 1]];
  for (let sweep = 0; sweep < 50; sweep++) {
    let p = 0;
    let q = 1;
    if (Math.abs(a[0][2]) > Math.abs(a[p][q])) [p, q] = [0, 2];
    if (Math.abs(a[1][2]) > Math.abs(a[p][q])) [p, q] = [1, 2];
    const off = Math.abs(a[p][q]);
    if (off <= 1e-15 * (Math.abs(a[0][0]) + Math.abs(a[1][1]) + Math.abs(a[2][2]))) break;
    const theta = (a[q][q] - a[p][p]) / (2 * a[p][q]);
    const t = (theta < 0 ? -1 : 1) / (Math.abs(theta) + Math.sqrt(theta * theta + 1));
    const c = 1 / Math.sqrt(t * t + 1);
    const s = t * c;
    for (let k = 0; k < 3; k++) {
      const [kp, kq] = [a[k][p], a[k][q]];
      a[k][p] = c * kp - s * kq;
      a[k][q] = s * kp + c * kq;
    }
    for (let k = 0; k < 3; k++) {
      const [pk, qk] = [a[p][k], a[q][k]];
      a[p][k] = c * pk - s * qk;
      a[q][k] = s * pk + c * qk;
    }
    for (let k = 0; k < 3; k++) {
      const [kp, kq] = [v[k][p], v[k][q]];
      v[k][p] = c * kp - s * kq;
      v[k][q] = s * kp + c * kq;
    }
  }
  return { values: [a[0][0], a[1][1], a[2][2]], vectors: v };
}

/**
 * The 2-standard-deviation ellipsoid of a point cloud: its mean, the principal axes (orthonormal, right-handed,
 * largest first) and a radius of 2 sigma along each. Null under MIN_CLOUD_POINTS points or when they all coincide.
 * (Of a 3D normal cloud, about 74% falls inside 2 sigma: the copy must not call it 95%.)
 */
export function categoryEllipsoid(points: XYZ[]): Ellipsoid | null {
  const n = points.length;
  if (n < MIN_CLOUD_POINTS) return null;
  const mean: Vec3 = [0, 0, 0];
  for (const p of points) for (let i = 0; i < 3; i++) mean[i] += xyz(p)[i] / n;
  const cov = [[0, 0, 0], [0, 0, 0], [0, 0, 0]];
  for (const p of points) {
    const d = [p.x - mean[0], p.y - mean[1], p.z - mean[2]];
    for (let i = 0; i < 3; i++) for (let j = 0; j < 3; j++) cov[i][j] += (d[i] * d[j]) / n;
  }
  const { values, vectors } = jacobi(cov);
  const order = [0, 1, 2].sort((i, j) => values[j] - values[i]);
  const largest = values[order[0]];
  const scale = Math.max(1, mean[0] ** 2 + mean[1] ** 2 + mean[2] ** 2);
  if (!Number.isFinite(largest) || largest <= 1e-20 * scale) return null;

  // Sign them so the result does not depend on the order the points came in: the biggest component positive, third axis the cross product.
  const axis = (k: number): Vec3 => {
    const col: Vec3 = [vectors[0][order[k]], vectors[1][order[k]], vectors[2][order[k]]];
    const big = col.reduce((b, x, i) => (Math.abs(x) > Math.abs(col[b]) ? i : b), 0);
    return col[big] < 0 ? [-col[0], -col[1], -col[2]] : col;
  };
  const [a0, a1] = [axis(0), axis(1)];
  const a2: Vec3 = [a0[1] * a1[2] - a0[2] * a1[1], a0[2] * a1[0] - a0[0] * a1[2], a0[0] * a1[1] - a0[1] * a1[0]];
  const radii = order.map((i) => 2 * Math.sqrt(Math.max(values[i], FLAT * largest))) as Vec3;
  return { center: mean, axes: [a0, a1, a2], radii };
}

// ---------------------------------------------------------------- neighbours

export type Near = { index: number; distance: number };

/** How many nearest messages the map highlights and the side panel lists: one number, so the two always agree. */
export const NEAREST = 8;

/** The k points closest to `points[index]` in the three components (not the full embedding), nearest first; ties go to the lower index; never the point itself. */
export function nearest(points: XYZ[], index: number, k: number): Near[] {
  if (!(index >= 0 && index < points.length) || k <= 0) return [];
  const o = points[index];
  const all: Near[] = [];
  for (let i = 0; i < points.length; i++) {
    if (i === index) continue;
    const p = points[i];
    all.push({ index: i, distance: Math.sqrt((p.x - o.x) ** 2 + (p.y - o.y) ** 2 + (p.z - o.z) ** 2) });
  }
  // ponytail: a full sort of n distances, ~1 ms at the 5000-point cap; a bounded heap only if the cap grows
  return all.sort((a, b) => a.distance - b.distance || a.index - b.index).slice(0, k);
}

// ---------------------------------------------------------------- age and campaigns

/** The value for a message without a usable date: outside 0..1, so it never shares a colour with a dated one. */
export const NO_DATE = -1;

const day = (iso: string) => Date.parse(iso.length === 10 ? `${iso}T00:00:00Z` : iso);

/** 0 for the oldest day of the sample, 1 for the newest; NO_DATE when the date is missing or unreadable. */
export function recencyRamp(date: string | null, minISO: string, maxISO: string): number {
  const d = date ? day(date) : NaN;
  if (Number.isNaN(d)) return NO_DATE;
  const [lo, hi] = [day(minISO), day(maxISO)];
  if (!(hi > lo)) return 1;
  return Math.min(1, Math.max(0, (d - lo) / (hi - lo)));
}

type Ranked = { name: string; messages: number; case_ids: string[] };

/** The n largest campaigns by message count; equal counts by name, so the colours stay put between refreshes. */
export function topCampaigns<T extends Pick<Ranked, "name" | "messages">>(campaigns: T[], n = 6): T[] {
  return [...campaigns].sort((a, b) => b.messages - a.messages || a.name.localeCompare(b.name)).slice(0, n);
}

/** case id -> index in `campaigns`; a case listed by several campaigns belongs to the largest (the first on a tie). */
export function caseIdToCampaign(campaigns: Ranked[]): Map<string, number> {
  const out = new Map<string, number>();
  campaigns.forEach((c, i) => {
    for (const id of c.case_ids) {
      const held = out.get(id);
      if (held === undefined || c.messages > campaigns[held].messages) out.set(id, i);
    }
  });
  return out;
}

// ---------------------------------------------------------------- camera maths (y up, like three.js)

// Stay off the poles, where "up" is undefined and the view would flip.
const POLE = 0.01;

/**
 * The camera position after turning around `target` by `dTheta` (azimuth, + = the camera moves towards +x when
 * it looks down -z) and `dPhi` (polar angle, + = the camera goes down). The distance stays the same.
 */
export function orbitBy(position: Vec3, target: Vec3, dTheta: number, dPhi: number): Vec3 {
  const o = [position[0] - target[0], position[1] - target[1], position[2] - target[2]];
  const r = Math.hypot(o[0], o[1], o[2]);
  if (r === 0) return position;
  const theta = Math.atan2(o[0], o[2]) + dTheta;
  const phi = Math.min(Math.PI - POLE, Math.max(POLE, Math.acos(Math.min(1, Math.max(-1, o[1] / r))) + dPhi));
  return [target[0] + r * Math.sin(phi) * Math.sin(theta), target[1] + r * Math.cos(phi), target[2] + r * Math.sin(phi) * Math.cos(theta)];
}

/** The camera position after moving along the line to the target: distance times `factor`, kept within the limits. */
export function zoomBy(position: Vec3, target: Vec3, factor: number, minDistance: number, maxDistance: number): Vec3 {
  const o = [position[0] - target[0], position[1] - target[1], position[2] - target[2]];
  const r = Math.hypot(o[0], o[1], o[2]);
  if (r === 0) return position;
  const s = Math.min(maxDistance, Math.max(minDistance, r * factor)) / r;
  return [target[0] + o[0] * s, target[1] + o[1] * s, target[2] + o[2] * s];
}

/**
 * Size multiplier for a point at depth `t` (0 = nearest to the camera, 1 = farthest of the cloud).
 * Perspective already shrinks distant spheres; this exaggerates it a little, the Embedding Projector's size cue.
 */
export function depthScale(t: number): number {
  return 1.25 - 0.55 * Math.min(1, Math.max(0, t));
}

/** Each axis as a segment through the origin of the components, across the data (the origin clamped into the data when it lies outside). */
export function axisSegments(b: Bounds): { from: Vec3; to: Vec3 }[] {
  const origin = [0, 1, 2].map((i) => Math.min(b.max[i], Math.max(b.min[i], 0)));
  return [0, 1, 2].map((i) => {
    const from = [...origin] as Vec3;
    const to = [...origin] as Vec3;
    from[i] = b.min[i];
    to[i] = b.max[i];
    return { from, to };
  });
}

/** Sphere radius in scene units: a big mark for a handful of messages, a small one for thousands. */
export function pointRadius(count: number): number {
  return Math.min(0.05, Math.max(0.018, 0.15 / Math.cbrt(Math.max(1, count))));
}

/** World radius that spans `pixels` on screen for something `distance` from a camera with a vertical field of view of `fovDeg` on a canvas `heightPx` tall. */
export function pixelRadius(pixels: number, distance: number, fovDeg: number, heightPx: number): number {
  return heightPx > 0 ? (pixels * 2 * distance * Math.tan((fovDeg * Math.PI) / 360)) / heightPx : 0;
}

/** Sphere segments (around, from pole to pole): a few thousand marks only a few pixels wide do not need the roundness of a handful of large ones, and the triangle count is what a weak GPU feels. */
export function sphereDetail(count: number): [number, number] {
  return count <= 400 ? [12, 8] : count <= 2000 ? [8, 6] : [6, 4];
}

/**
 * Linear fog range for a camera `distance` from the middle of a cloud of scene radius `radius`: clear at the
 * nearest point, `maxFog` (0..1) of the way to the background at the farthest.
 */
export function fogRange(distance: number, radius: number, maxFog: number): { near: number; far: number } {
  const near = Math.max(0.05, distance - radius);
  return { near, far: near + (distance + radius - near) / maxFog };
}

/** How far the camera starts from a cloud normalised into the box -1..1 (the box's corners just fit a 45 degree view; the cloud itself rarely reaches them). */
export const FIT_DISTANCE = 3.7;

/** The starting distance for a canvas of this width/height: the view angle is fixed vertically, so a narrow (phone) canvas needs to be farther away to fit the cloud's width. */
export function fitDistance(aspect: number): number {
  return Number.isFinite(aspect) && aspect > 0 ? FIT_DISTANCE / Math.min(1, aspect) : FIT_DISTANCE;
}

/** Where the camera starts: turned a little round and above the cloud, so the third component shows up as depth rather than being edge-on. */
export const initialPosition = (distance: number): Vec3 => orbitBy([0, 0, distance], [0, 0, 0], 0.6, -0.35);
export const INITIAL_POSITION: Vec3 = initialPosition(FIT_DISTANCE);
