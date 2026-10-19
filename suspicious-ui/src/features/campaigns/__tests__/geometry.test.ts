import { describe, it, expect } from "vitest";
import {
  NO_DATE,
  bounds,
  caseIdToCampaign,
  categoryEllipsoid,
  axisSegments,
  depthScale,
  FIT_DISTANCE,
  fitDistance,
  fogRange,
  initialPosition,
  nearest,
  normalise,
  orbitBy,
  pixelRadius,
  pointRadius,
  sphereDetail,
  recencyRamp,
  toData,
  toScene,
  topCampaigns,
  zoomBy,
  type Vec3,
} from "../geometry";

const P = (x: number, y: number, z: number) => ({ x, y, z });
const dot = (a: Vec3, b: Vec3) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
const norm = (a: Vec3) => Math.sqrt(dot(a, a));
const finite = (...v: number[]) => v.every(Number.isFinite);

/** A fixed pseudo-random sequence in [0,1), so the tests are repeatable. */
function rng(seed = 7) {
  let s = seed;
  return () => ((s = (s * 1664525 + 1013904223) % 4294967296) / 4294967296);
}

describe("bounds", () => {
  it("is null without points", () => {
    expect(bounds([])).toBeNull();
  });

  it("is a single position for one point", () => {
    expect(bounds([P(1, 2, 3)])).toEqual({ min: [1, 2, 3], max: [1, 2, 3], center: [1, 2, 3], extent: [0, 0, 0] });
  });

  it("spans the points", () => {
    const b = bounds([P(-1, 0, 4), P(3, -2, 5), P(0, 6, 4)])!;
    expect(b.min).toEqual([-1, -2, 4]);
    expect(b.max).toEqual([3, 6, 5]);
    expect(b.center).toEqual([1, 2, 4.5]);
    expect(b.extent).toEqual([4, 8, 1]);
  });
});

describe("normalise", () => {
  it("fits the points in the box -1..1 with one scale for all axes, and round-trips", () => {
    const pts = [P(0, 0, 0), P(10, 2, -1), P(4, -2, 1)];
    const n = normalise(pts);
    for (const p of pts) {
      const s = toScene([p.x, p.y, p.z], n);
      expect(s.every((v) => Math.abs(v) <= 1 + 1e-9)).toBe(true);
      const back = toData(s, n);
      expect(back[0]).toBeCloseTo(p.x, 9);
      expect(back[1]).toBeCloseTo(p.y, 9);
      expect(back[2]).toBeCloseTo(p.z, 9);
    }
    // the widest axis (x, 10 wide) touches the box; the others keep their proportion
    expect(toScene([0, 0, 0], n)[0]).toBeCloseTo(-1, 9);
    expect(toScene([10, 0, 0], n)[0]).toBeCloseTo(1, 9);
    expect(toScene([0, 2, 0], n)[1] - toScene([0, 0, 0], n)[1]).toBeCloseTo(0.4, 9);
  });

  it.each([
    ["no points", []],
    ["one point", [P(3, 4, 5)]],
    ["identical points", [P(3, 4, 5), P(3, 4, 5), P(3, 4, 5)]],
  ])("gives a finite transform for %s", (_name, pts) => {
    const n = normalise(pts);
    expect(finite(n.scale, ...n.offset)).toBe(true);
    expect(n.scale).toBeGreaterThan(0);
    if (pts.length) expect(toScene([pts[0].x, pts[0].y, pts[0].z], n)).toEqual([0, 0, 0]);
  });
});

describe("categoryEllipsoid", () => {
  const cross = (a: number, b: number, c: number) => [P(a, 0, 0), P(-a, 0, 0), P(0, b, 0), P(0, -b, 0), P(0, 0, c), P(0, 0, -c)];

  it("needs at least 5 points", () => {
    expect(categoryEllipsoid([])).toBeNull();
    expect(categoryEllipsoid([P(0, 0, 0)])).toBeNull();
    expect(categoryEllipsoid(cross(3, 2, 1).slice(0, 4))).toBeNull();
    expect(categoryEllipsoid(cross(3, 2, 1).slice(0, 5))).not.toBeNull();
  });

  it("is null when every point is the same", () => {
    expect(categoryEllipsoid(Array.from({ length: 10 }, () => P(1, 2, 3)))).toBeNull();
  });

  it("has radii of 2 standard deviations on each principal axis, largest first", () => {
    // Variance along x is 2a^2/6, so sigma = a/sqrt(3) and the radius 2a/sqrt(3).
    const e = categoryEllipsoid(cross(3, 2, 1))!;
    expect(e.center[0]).toBeCloseTo(0, 9);
    expect(e.radii[0]).toBeCloseTo((2 * 3) / Math.sqrt(3), 6);
    expect(e.radii[1]).toBeCloseTo((2 * 2) / Math.sqrt(3), 6);
    expect(e.radii[2]).toBeCloseTo((2 * 1) / Math.sqrt(3), 6);
    expect(Math.abs(e.axes[0][0])).toBeCloseTo(1, 6);
    expect(Math.abs(e.axes[1][1])).toBeCloseTo(1, 6);
    expect(Math.abs(e.axes[2][2])).toBeCloseTo(1, 6);
  });

  it("centres on the mean", () => {
    const e = categoryEllipsoid(cross(3, 2, 1).map((p) => P(p.x + 10, p.y - 5, p.z + 0.5)))!;
    expect(e.center[0]).toBeCloseTo(10, 9);
    expect(e.center[1]).toBeCloseTo(-5, 9);
    expect(e.center[2]).toBeCloseTo(0.5, 9);
  });

  it("finds a tilted principal axis", () => {
    const r = rng();
    // Long along (1,1,0), short elsewhere.
    const pts = Array.from({ length: 200 }, () => {
      const t = (r() - 0.5) * 10;
      return P(t + (r() - 0.5), t + (r() - 0.5), (r() - 0.5) * 0.5);
    });
    const e = categoryEllipsoid(pts)!;
    expect(Math.abs(e.axes[0][0])).toBeCloseTo(Math.SQRT1_2, 1);
    expect(Math.abs(e.axes[0][1])).toBeCloseTo(Math.SQRT1_2, 1);
    expect(e.radii[0]).toBeGreaterThan(e.radii[1]);
  });

  it("returns orthonormal axes, right-handed, on a random cloud", () => {
    const r = rng(3);
    const e = categoryEllipsoid(Array.from({ length: 60 }, () => P(r() * 4, r() * 2 + r(), r() - r() * 3)))!;
    for (let i = 0; i < 3; i++) {
      expect(norm(e.axes[i])).toBeCloseTo(1, 9);
      for (let j = i + 1; j < 3; j++) expect(dot(e.axes[i], e.axes[j])).toBeCloseTo(0, 9);
    }
    const [a, b, c] = e.axes;
    const det = a[0] * (b[1] * c[2] - b[2] * c[1]) - a[1] * (b[0] * c[2] - b[2] * c[0]) + a[2] * (b[0] * c[1] - b[1] * c[0]);
    expect(det).toBeCloseTo(1, 9);
    expect(e.radii[0]).toBeGreaterThanOrEqual(e.radii[1]);
    expect(e.radii[1]).toBeGreaterThanOrEqual(e.radii[2]);
  });

  it("still draws a flat (planar) cloud, with no NaN and a thin third axis", () => {
    const r = rng(5);
    const e = categoryEllipsoid(Array.from({ length: 30 }, () => P(r() * 4, r() * 2, 1)))!;
    expect(finite(...e.center, ...e.radii, ...e.axes.flat())).toBe(true);
    expect(e.radii[2]).toBeGreaterThan(0);
    expect(e.radii[2]).toBeLessThan(e.radii[1] * 0.01);
  });

  it("still draws collinear points", () => {
    const e = categoryEllipsoid(Array.from({ length: 8 }, (_, i) => P(i, 2 * i, -i)))!;
    expect(finite(...e.center, ...e.radii, ...e.axes.flat())).toBe(true);
    expect(e.radii[1]).toBeGreaterThan(0);
    expect(e.radii[2]).toBeGreaterThan(0);
    expect(e.radii[0]).toBeGreaterThan(e.radii[1] * 100);
  });
});

describe("nearest", () => {
  const pts = [P(0, 0, 0), P(3, 0, 0), P(1, 0, 0), P(0, 2, 0), P(0, 0, 5)];

  it("lists the closest first with their distances, never the point itself", () => {
    expect(nearest(pts, 0, 3)).toEqual([
      { index: 2, distance: 1 },
      { index: 3, distance: 2 },
      { index: 1, distance: 3 },
    ]);
  });

  it("returns fewer when there are not k others, and nothing for k of 0 or a bad index", () => {
    expect(nearest(pts, 0, 99)).toHaveLength(4);
    expect(nearest(pts, 0, 0)).toEqual([]);
    expect(nearest(pts, -1, 3)).toEqual([]);
    expect(nearest(pts, 5, 3)).toEqual([]);
    expect(nearest([P(1, 1, 1)], 0, 8)).toEqual([]);
    expect(nearest([], 0, 8)).toEqual([]);
  });

  it("breaks ties by the lower index and measures in all three components", () => {
    const tied = [P(0, 0, 0), P(0, 0, 2), P(2, 0, 0), P(0, 2, 0), P(1, 1, 1)];
    expect(nearest(tied, 0, 4).map((n) => n.index)).toEqual([4, 1, 2, 3]);
    expect(nearest(tied, 0, 1)[0].distance).toBeCloseTo(Math.sqrt(3), 12);
  });
});

describe("recencyRamp", () => {
  const MIN = "2026-10-01";
  const MAX = "2026-10-11";

  it("is 0 at the oldest date and 1 at the newest, linear between", () => {
    expect(recencyRamp(MIN, MIN, MAX)).toBe(0);
    expect(recencyRamp(MAX, MIN, MAX)).toBe(1);
    expect(recencyRamp("2026-10-06", MIN, MAX)).toBeCloseTo(0.5, 9);
  });

  it("clamps dates outside the range", () => {
    expect(recencyRamp("2026-09-01", MIN, MAX)).toBe(0);
    expect(recencyRamp("2026-12-01", MIN, MAX)).toBe(1);
  });

  it("puts a missing or unreadable date in its own bucket, outside 0..1", () => {
    expect(NO_DATE).toBeLessThan(0);
    expect(recencyRamp(null, MIN, MAX)).toBe(NO_DATE);
    expect(recencyRamp("not a date", MIN, MAX)).toBe(NO_DATE);
  });

  it("is 1 when every date is the same", () => {
    expect(recencyRamp(MIN, MIN, MIN)).toBe(1);
  });
});

describe("topCampaigns", () => {
  const c = (name: string, messages: number, case_ids: string[] = []) => ({ name, messages, case_ids });

  it("ranks by messages, breaks ties by name, and keeps at most 6", () => {
    const all = [c("b", 5), c("a", 5), c("big", 20), c("c", 1), c("d", 2), c("e", 3), c("f", 4), c("g", 6)];
    expect(topCampaigns(all, 6).map((x) => x.name)).toEqual(["big", "g", "a", "b", "f", "e"]);
  });

  it("returns what there is, without mutating the input", () => {
    const all = [c("x", 1), c("y", 2)];
    expect(topCampaigns(all, 6).map((x) => x.name)).toEqual(["y", "x"]);
    expect(all.map((x) => x.name)).toEqual(["x", "y"]);
    expect(topCampaigns([], 6)).toEqual([]);
  });
});

describe("caseIdToCampaign", () => {
  const c = (name: string, messages: number, case_ids: string[]) => ({ name, messages, case_ids });

  it("maps each case id to the index of its campaign", () => {
    const m = caseIdToCampaign([c("a", 3, ["1", "2"]), c("b", 2, ["3"])]);
    expect(m.get("1")).toBe(0);
    expect(m.get("2")).toBe(0);
    expect(m.get("3")).toBe(1);
    expect(m.has("4")).toBe(false);
  });

  it("gives a case in several campaigns to the largest, the first on a tie", () => {
    const m = caseIdToCampaign([c("small", 2, ["1", "9"]), c("large", 9, ["1"]), c("tied", 9, ["9"])]);
    expect(m.get("1")).toBe(1);
    expect(m.get("9")).toBe(2); // "tied" (9 messages) beats "small" (2); "large" does not hold it
  });
});

describe("camera maths", () => {
  it("orbits at a constant distance from the target", () => {
    const p = orbitBy([0, 0, 5], [0, 0, 0], Math.PI / 2, 0);
    expect(p[0]).toBeCloseTo(5, 9);
    expect(p[1]).toBeCloseTo(0, 9);
    expect(p[2]).toBeCloseTo(0, 9);
    const q = orbitBy([1, 2, 3], [1, 1, 1], 0.4, -0.3);
    expect(norm([q[0] - 1, q[1] - 1, q[2] - 1])).toBeCloseTo(norm([0, 1, 2]), 9);
  });

  it("never passes over the poles", () => {
    const up = orbitBy([0, 1, 4], [0, 0, 0], 0, -10);
    const down = orbitBy([0, 1, 4], [0, 0, 0], 0, 10);
    expect(finite(...up, ...down)).toBe(true);
    expect(up[1]).toBeGreaterThan(0);
    expect(down[1]).toBeLessThan(0);
    expect(Math.hypot(up[0], up[2])).toBeGreaterThan(0);
  });

  it("keeps a camera that sits on the target where it is", () => {
    expect(orbitBy([1, 1, 1], [1, 1, 1], 1, 1)).toEqual([1, 1, 1]);
  });

  it("zooms along the line to the target within the limits", () => {
    expect(zoomBy([0, 0, 4], [0, 0, 0], 0.5, 1, 10)).toEqual([0, 0, 2]);
    expect(zoomBy([0, 0, 4], [0, 0, 0], 0.1, 1, 10)).toEqual([0, 0, 1]);
    expect(zoomBy([0, 0, 4], [0, 0, 0], 100, 1, 10)).toEqual([0, 0, 10]);
    expect(zoomBy([1, 0, 4], [1, 0, 0], 2, 1, 10)).toEqual([1, 0, 8]);
  });

  it("makes near points larger than far ones, within a modest range", () => {
    expect(depthScale(0)).toBeGreaterThan(depthScale(1));
    expect(depthScale(0)).toBeLessThan(2);
    expect(depthScale(1)).toBeGreaterThan(0.4);
    expect(depthScale(-3)).toBe(depthScale(0));
    expect(depthScale(7)).toBe(depthScale(1));
  });
});

describe("axisSegments", () => {
  it("runs each axis through the origin of the components, across the data", () => {
    const b = bounds([P(-1, -2, -3), P(3, 4, 5)])!;
    expect(axisSegments(b)).toEqual([
      { from: [-1, 0, 0], to: [3, 0, 0] },
      { from: [0, -2, 0], to: [0, 4, 0] },
      { from: [0, 0, -3], to: [0, 0, 5] },
    ]);
  });

  it("keeps the axes inside the data when the origin lies outside it", () => {
    const b = bounds([P(2, 3, 4), P(3, 5, 6)])!;
    const [x, y, z] = axisSegments(b);
    expect(x).toEqual({ from: [2, 3, 4], to: [3, 3, 4] });
    expect(y).toEqual({ from: [2, 3, 4], to: [2, 5, 4] });
    expect(z).toEqual({ from: [2, 3, 4], to: [2, 3, 6] });
  });
});

describe("pointRadius", () => {
  it("shrinks as the sample grows, within fixed limits", () => {
    expect(pointRadius(1)).toBe(0.05);
    expect(pointRadius(231)).toBeLessThan(pointRadius(31));
    expect(pointRadius(5000)).toBe(0.018);
    expect(pointRadius(0)).toBe(0.05);
    for (const n of [0, 1, 31, 231, 1500, 5000, 1e6]) expect(Number.isFinite(pointRadius(n))).toBe(true);
  });
});

describe("fogRange", () => {
  it("starts at the nearest point of the cloud and fades the farthest one by the given share", () => {
    const { near, far } = fogRange(5, 1.75, 0.45);
    expect(near).toBeCloseTo(3.25, 9);
    // the farthest point, at distance + radius, is fogged by `max`
    const t = (5 + 1.75 - near) / (far - near);
    expect(t).toBeCloseTo(0.45, 9);
  });

  it("never starts behind the camera", () => {
    expect(fogRange(1, 1.75, 0.45).near).toBeGreaterThan(0);
  });
});

describe("fitDistance", () => {
  it("is the base distance for a canvas at least as wide as it is tall, and farther for a narrow one", () => {
    expect(fitDistance(1.6)).toBe(FIT_DISTANCE);
    expect(fitDistance(1)).toBe(FIT_DISTANCE);
    expect(fitDistance(0.5)).toBeCloseTo(FIT_DISTANCE * 2, 9);
  });

  it("falls back to the base distance before the canvas has a size", () => {
    expect(fitDistance(0)).toBe(FIT_DISTANCE);
    expect(fitDistance(NaN)).toBe(FIT_DISTANCE);
    expect(fitDistance(Infinity)).toBe(FIT_DISTANCE);
  });
});

describe("initialPosition", () => {
  it("looks at the middle from the given distance, a little round and above", () => {
    const p = initialPosition(5);
    expect(norm(p)).toBeCloseTo(5, 9);
    expect(p[1]).toBeGreaterThan(0);
    expect(p[0]).toBeGreaterThan(0);
    expect(p[2]).toBeGreaterThan(0);
  });
});

describe("sphereDetail", () => {
  it("uses fewer triangles as the sample grows, and always at least a rough sphere", () => {
    const tris = (n: number) => {
      const [w, h] = sphereDetail(n);
      return w * h * 2;
    };
    expect(tris(0)).toBe(tris(400));
    expect(tris(401)).toBeLessThan(tris(400));
    expect(tris(2001)).toBeLessThan(tris(2000));
    for (const n of [0, 1, 400, 2000, 5000, 1e6]) {
      const [w, h] = sphereDetail(n);
      expect(w).toBeGreaterThanOrEqual(3);
      expect(h).toBeGreaterThanOrEqual(2);
    }
  });
});

describe("pixelRadius", () => {
  it("is the world size that covers the given pixels", () => {
    // at 90 degrees the view is 2 * distance tall: 100 px of a 200 px canvas, 5 away, is 5 world units
    expect(pixelRadius(100, 5, 90, 200)).toBeCloseTo(5, 9);
    expect(pixelRadius(7, 10, 45, 460)).toBeCloseTo((7 * 2 * 10 * Math.tan(Math.PI / 8)) / 460, 12);
  });

  it("grows with distance and is 0 for a canvas with no height", () => {
    expect(pixelRadius(7, 8, 45, 400)).toBeGreaterThan(pixelRadius(7, 4, 45, 400));
    expect(pixelRadius(7, 8, 45, 0)).toBe(0);
  });
});
