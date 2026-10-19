import * as React from "react";
import { OrbitControls, PerformanceMonitor } from "@react-three/drei";
import { useFrame, useThree } from "@react-three/fiber";
import { BackSide, BufferGeometry, Color, DoubleSide, Float32BufferAttribute, Matrix4, Quaternion, Vector3, type Fog, type InstancedMesh, type PerspectiveCamera } from "three";

import { FIT_DISTANCE, depthScale, fitDistance, fogRange, initialPosition, orbitBy, pixelRadius, pointRadius, sphereDetail, zoomBy, type Vec3 } from "@/features/campaigns/geometry";

/** What the keyboard and the Reset view button drive; the page-side handler is in mapSupport.ts. */
export type SceneApi = {
  rotate(dTheta: number, dPhi: number): void;
  zoom(factor: number): void;
  reset(): void;
};

export type Cloud = { key: string; colour: string; centre: Vec3; axes: [Vec3, Vec3, Vec3]; radii: Vec3 };

export type SceneProps = {
  /** Scene coordinates (the cloud normalised into the box -1..1), one per point. */
  positions: Vec3[];
  colours: string[];
  visible: boolean[];
  /** Indices of the selected points and of the nearest neighbours of a single selected one (both only among visible points). */
  selected: number[];
  neighbours: number[];
  hovered: number | null;
  clouds: Cloud[];
  axes: { from: Vec3; to: Vec3 }[];
  paint: { background: string; axis: string; outline: string; neighbourOutline: string };
  reducedMotion: boolean;
  /** Where to bring the camera target when the selection changes from outside the map. */
  focus: { key: string; target: Vec3 } | null;
  /** True (once) for the key of a selection made by clicking in the map: the camera stays put for that one. */
  consumeSkip(key: string): boolean;
  apiRef: React.RefObject<SceneApi | null>;
  /** Three elements, moved onto the positive end of each axis. */
  labelRefs: React.RefObject<(HTMLElement | null)[]>;
  onHover(index: number | null, clientX?: number, clientY?: number): void;
  onPick(index: number): void;
  /** A new sample: the camera goes back to the starting view. */
  fitKey: unknown;
};

const SCENE_RADIUS = Math.sqrt(3); // the corner of the box -1..1
// At most this share of the way to the background for the farthest point: far points fade, they never vanish.
const MAX_FOG = 0.45;
// A hidden point shrinks to nothing visible but keeps a non-degenerate matrix, so the ray test never meets a singular one.
const HIDDEN = 1e-5;
// Constant on purpose (see SceneFog): the real colour and range are set on the object, from the theme and the camera.
const FOG_ARGS: [string, number, number] = ["#000000", 1, 20];
const FOCUS_MS = 260;
const SELECTED = 2.6;
const NEIGHBOUR = 1.6;
const HOVERED = 1.5;
const DIM = 0.4;

// How far, in pixels, from a mark's centre the pointer still picks it (a finger is coarser than a mouse).
const pickPixels = () => (window.matchMedia?.("(pointer: coarse)").matches ? 14 : 7);

const vec = (v: Vector3): Vec3 => [v.x, v.y, v.z];

/** The points: one InstancedMesh, one draw call. Size follows depth and zoom; selected, neighbour and hovered points get a ring. */
function Points({ positions, colours, visible, selected, neighbours, hovered, paint, onHover, onPick }: SceneProps) {
  const camera = useThree((s) => s.camera);
  const invalidate = useThree((s) => s.invalidate);
  const height = useThree((s) => s.size.height);
  const controls = useThree((s) => s.controls) as (EventTarget & { target: Vector3 }) | null;
  const main = React.useRef<InstancedMesh>(null);
  const picks = React.useRef<InstancedMesh>(null);
  const rings = React.useRef<InstancedMesh>(null);
  const n = positions.length;
  const radius = pointRadius(n);
  const detail = sphereDetail(n);
  // Reused between updates: allocating per point on every camera move would make the garbage collector the bottleneck.
  const scratchRef = React.useRef<{ m: Matrix4; c: Color; dist: Float32Array; scale: Float32Array } | null>(null);
  const scratch = () => {
    const s = (scratchRef.current ??= { m: new Matrix4(), c: new Color(), dist: new Float32Array(n), scale: new Float32Array(n) });
    if (s.dist.length !== n) {
      s.dist = new Float32Array(n);
      s.scale = new Float32Array(n);
    }
    return s;
  };

  // Selected first, then neighbours, then the hovered point if it is none of those: the order of the ring instances.
  const marked = React.useMemo(() => {
    const out: { index: number; boost: number; ring: string }[] = [];
    const seen = new Set<number>();
    const add = (index: number, boost: number, ring: string) => {
      if (seen.has(index)) return;
      seen.add(index);
      out.push({ index, boost, ring });
    };
    selected.forEach((i) => add(i, SELECTED, paint.outline));
    neighbours.forEach((i) => add(i, NEIGHBOUR, paint.neighbourOutline));
    if (hovered !== null && visible[hovered]) add(hovered, HOVERED, paint.outline);
    return out;
  }, [selected, neighbours, hovered, visible, paint.outline, paint.neighbourOutline]);
  const boosts = React.useMemo(() => {
    const b = new Float32Array(n).fill(1);
    marked.forEach((m) => (b[m.index] = m.boost));
    return b;
  }, [marked, n]);

  const applyColours = React.useCallback(() => {
    const m = main.current;
    if (!m) return;
    const { c } = scratch();
    const bg = new Color(paint.background);
    const dimOthers = selected.length > 0;
    for (let i = 0; i < n; i++) {
      c.set(colours[i]);
      // Others recede while something is selected: toward the background, which is what a lower opacity would look like on it.
      if (dimOthers && boosts[i] === 1) c.lerp(bg, DIM);
      m.setColorAt(i, c);
    }
    if (m.instanceColor) m.instanceColor.needsUpdate = true;
    const r = rings.current;
    if (r) {
      marked.forEach((k, j) => r.setColorAt(j, c.set(k.ring)));
      if (r.instanceColor) r.instanceColor.needsUpdate = true;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- scratch only wraps a ref
  }, [n, colours, paint.background, selected.length, boosts, marked]);

  const applyMatrices = React.useCallback(() => {
    const m = main.current;
    if (!m) return;
    const { m: matrix, dist, scale: scaleOf } = scratch();
    const cam = camera.position;
    let near = Infinity;
    let far = -Infinity;
    for (let i = 0; i < n; i++) {
      if (!visible[i]) continue;
      const p = positions[i];
      const d = Math.hypot(p[0] - cam.x, p[1] - cam.y, p[2] - cam.z);
      dist[i] = d;
      if (d < near) near = d;
      if (d > far) far = d;
    }
    // Zooming in grows the marks, but only by the square root, so they neither vanish zoomed out nor swamp the view zoomed in.
    const zoom = Math.min(1.8, Math.max(0.55, Math.sqrt((controls ? cam.distanceTo(controls.target) : FIT_DISTANCE) / FIT_DISTANCE)));
    for (let i = 0; i < n; i++) {
      const s = visible[i] ? radius * zoom * depthScale(far > near ? (dist[i] - near) / (far - near) : 0) * boosts[i] : HIDDEN;
      scaleOf[i] = s;
      const p = positions[i];
      m.setMatrixAt(i, matrix.makeScale(s, s, s).setPosition(p[0], p[1], p[2]));
    }
    m.instanceMatrix.needsUpdate = true;
    // The picking spheres are invisible and at least PICK_PX wide on screen, so a few-pixel mark is still easy to hit.
    const p = picks.current;
    if (p) {
      const fov = (camera as PerspectiveCamera).fov;
      const reach = pickPixels(); // asked once per update, not once per point
      for (let i = 0; i < n; i++) {
        const s = visible[i] ? Math.max(scaleOf[i], pixelRadius(reach, dist[i], fov, height)) : HIDDEN;
        const q = positions[i];
        p.setMatrixAt(i, matrix.makeScale(s, s, s).setPosition(q[0], q[1], q[2]));
      }
      p.instanceMatrix.needsUpdate = true;
      p.boundingSphere = null; // the ray test would otherwise use the first sphere ever computed
    }
    const r = rings.current;
    if (r) {
      marked.forEach((k, j) => {
        const s = scaleOf[k.index] * 1.4;
        const p = positions[k.index];
        r.setMatrixAt(j, matrix.makeScale(s, s, s).setPosition(p[0], p[1], p[2]));
      });
      r.instanceMatrix.needsUpdate = true;
      r.boundingSphere = null;
    }
    invalidate();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- scratch only wraps a ref
  }, [camera, controls, n, visible, positions, radius, boosts, marked, height, invalidate]);

  React.useLayoutEffect(() => {
    applyColours();
    applyMatrices();
  }, [applyColours, applyMatrices]);

  // Size by distance has to follow the camera, but only when it moves: not every frame.
  React.useEffect(() => {
    if (!controls) return;
    controls.addEventListener("change", applyMatrices);
    return () => controls.removeEventListener("change", applyMatrices);
  }, [controls, applyMatrices]);

  if (!n) return null;
  return (
    <>
      <instancedMesh key={n} ref={main} args={[undefined, undefined, n]} frustumCulled={false} raycast={() => null}>
        <sphereGeometry args={[1, ...detail]} />
        <meshBasicMaterial />
      </instancedMesh>
      <instancedMesh
        key={`pick-${n}`}
        ref={picks}
        args={[undefined, undefined, n]}
        frustumCulled={false}
        onPointerMove={(e) => {
          const i = e.instanceId;
          if (i === undefined || !visible[i]) return;
          e.stopPropagation();
          (e.nativeEvent.target as HTMLElement).style.cursor = "pointer";
          onHover(i, e.nativeEvent.clientX, e.nativeEvent.clientY);
        }}
        onPointerOut={(e) => {
          (e.nativeEvent.target as HTMLElement).style.cursor = "";
          onHover(null);
        }}
        onClick={(e) => {
          // Orbiting ends with a pointer-up over whatever is underneath: a drag is not a click.
          if (e.delta > 4 || e.instanceId === undefined || !visible[e.instanceId]) return;
          e.stopPropagation();
          onPick(e.instanceId);
        }}
      >
        <sphereGeometry args={[1, 6, 4]} />
        <meshBasicMaterial visible={false} />
      </instancedMesh>
      {marked.length ? (
        <instancedMesh key={`ring-${marked.length}`} ref={rings} args={[undefined, undefined, marked.length]} frustumCulled={false} raycast={() => null}>
          <sphereGeometry args={[1, 12, 8]} />
          <meshBasicMaterial side={BackSide} />
        </instancedMesh>
      ) : null}
    </>
  );
}

/** One translucent ellipsoid. Fill does not write depth, so overlapping clouds and the points inside them stay visible. */
function CloudMesh({ cloud }: { cloud: Cloud }) {
  const rotation = React.useMemo(() => new Quaternion().setFromRotationMatrix(new Matrix4().makeBasis(...cloud.axes.map((a) => new Vector3(...a)) as [Vector3, Vector3, Vector3])), [cloud.axes]);
  return (
    <group position={cloud.centre} quaternion={rotation} scale={cloud.radii}>
      <mesh>
        <sphereGeometry args={[1, 28, 18]} />
        <meshBasicMaterial color={cloud.colour} transparent opacity={0.08} depthWrite={false} side={DoubleSide} />
      </mesh>
      <mesh>
        <sphereGeometry args={[1, 14, 8]} />
        <meshBasicMaterial color={cloud.colour} wireframe transparent opacity={0.14} depthWrite={false} />
      </mesh>
    </group>
  );
}

/** Faint axis lines; their labels are DOM elements outside the canvas (themed, readable, selectable) that follow the line ends. */
function Axes({ axes, paint, labelRefs }: Pick<SceneProps, "axes" | "paint" | "labelRefs">) {
  const geometry = React.useMemo(() => {
    const g = new BufferGeometry();
    g.setAttribute("position", new Float32BufferAttribute(axes.flatMap((a) => [...a.from, ...a.to]), 3));
    return g;
  }, [axes]);
  React.useEffect(() => () => geometry.dispose(), [geometry]);
  const tip = React.useMemo(() => new Vector3(), []);

  useFrame(({ camera, size }) => {
    camera.updateMatrixWorld();
    axes.forEach((a, i) => {
      const el = labelRefs.current[i];
      if (!el) return;
      tip.set(...a.to).project(camera);
      el.style.visibility = tip.z < 1 ? "visible" : "hidden";
      // Beside the line's end, but kept inside the canvas (the overflow is hidden, so a label past the edge would be cut).
      const [w, h] = [el.offsetWidth, el.offsetHeight];
      const x = Math.min(Math.max(4, (tip.x * 0.5 + 0.5) * size.width + 6), size.width - w - 4);
      const y = Math.min(Math.max(h / 2 + 4, (-tip.y * 0.5 + 0.5) * size.height), size.height - h / 2 - 4);
      el.style.transform = `translate(${x}px, ${y}px) translateY(-50%)`;
    });
  });

  return (
    <lineSegments geometry={geometry}>
      <lineBasicMaterial color={paint.axis} />
    </lineSegments>
  );
}

/**
 * Scene fog in the canvas background colour; its range follows the distance to the cloud, so the nearest point stays clear at any zoom.
 * The Fog object is created once and only its colour is changed with the theme: react-three-fiber builds a new object when the `args` change,
 * and the listener below would go on updating the old one.
 */
function SceneFog({ background }: { background: string }) {
  const camera = useThree((s) => s.camera);
  const invalidate = useThree((s) => s.invalidate);
  const controls = useThree((s) => s.controls) as (EventTarget & { target: Vector3 }) | null;
  const fog = React.useRef<Fog>(null);

  React.useLayoutEffect(() => {
    fog.current?.color.set(background);
    invalidate();
  }, [background, invalidate]);

  React.useEffect(() => {
    const f = fog.current;
    if (!f || !controls) return;
    const update = () => {
      const { near, far } = fogRange(camera.position.distanceTo(controls.target), SCENE_RADIUS, MAX_FOG);
      f.near = near;
      f.far = far;
    };
    update();
    controls.addEventListener("change", update);
    return () => controls.removeEventListener("change", update);
  }, [camera, controls]);

  return <fog ref={fog} attach="fog" args={FOG_ARGS} />;
}

/** Camera and controls: starting view, reset, keyboard steps, focus on a selection, fog that follows the zoom, resolution that drops under load. */
function Rig({ focus, consumeSkip, apiRef, reducedMotion, fitKey }: Pick<SceneProps, "focus" | "consumeSkip" | "apiRef" | "reducedMotion" | "fitKey">) {
  const camera = useThree((s) => s.camera);
  const invalidate = useThree((s) => s.invalidate);
  const setDpr = useThree((s) => s.setDpr);
  const controls = React.useRef<React.ComponentRef<typeof OrbitControls>>(null);
  const target = React.useRef<Vec3 | null>(null);

  // The starting view fits the cloud to the canvas. It is redone for a new sample, or when the canvas gets its size, but not
  // under a user who has already moved the camera (a window resize must not undo that).
  const size = useThree((s) => s.size);
  const moved = React.useRef(false);
  const fitted = React.useRef<unknown>(null);
  React.useEffect(() => {
    const c = controls.current;
    if (!c) return;
    const onStart = () => {
      moved.current = true;
    };
    c.addEventListener("start", onStart);
    return () => c.removeEventListener("start", onStart);
  }, []);
  React.useEffect(() => {
    const c = controls.current;
    if (!c) return;
    if (fitted.current !== fitKey) {
      fitted.current = fitKey;
      moved.current = false;
    } else if (moved.current) return;
    camera.position.set(...initialPosition(fitDistance(size.width / size.height)));
    c.target.set(0, 0, 0);
    c.update();
    c.saveState(); // what "Reset view" returns to
    invalidate();
  }, [fitKey, size.width, size.height, camera, invalidate]);

  React.useEffect(() => {
    apiRef.current = {
      rotate(dTheta, dPhi) {
        const c = controls.current;
        if (!c) return;
        moved.current = true;
        camera.position.set(...orbitBy(vec(camera.position), vec(c.target), dTheta, dPhi));
        c.update();
        invalidate();
      },
      zoom(factor) {
        const c = controls.current;
        if (!c) return;
        moved.current = true;
        camera.position.set(...zoomBy(vec(camera.position), vec(c.target), factor, c.minDistance, c.maxDistance));
        c.update();
        invalidate();
      },
      reset() {
        controls.current?.reset();
        moved.current = false; // back at the fitted view: a resize may refit again
        invalidate();
      },
    };
    return () => {
      apiRef.current = null;
    };
  }, [apiRef, camera, invalidate]);

  // Move the camera and its target together, so a selection comes to the middle without changing the angle or distance.
  const focusKey = focus?.key;
  React.useEffect(() => {
    target.current = focus?.target ?? null;
  });
  React.useEffect(() => {
    const c = controls.current;
    const to = target.current;
    if (!c || !to || focusKey === undefined) return;
    if (consumeSkip(focusKey)) return;
    const delta = new Vector3(...to).sub(c.target);
    if (delta.lengthSq() === 0) return;
    const shift = (d: Vector3) => {
      camera.position.add(d);
      c.target.add(d);
      c.update();
      invalidate();
    };
    if (reducedMotion) {
      shift(delta);
      return;
    }
    const applied = new Vector3();
    const start = performance.now();
    let frame = 0;
    const step = (now: number) => {
      const t = Math.min(1, (now - start) / FOCUS_MS);
      const next = delta.clone().multiplyScalar(1 - (1 - t) ** 3);
      shift(next.clone().sub(applied));
      applied.copy(next);
      if (t < 1) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [focusKey, reducedMotion, camera, invalidate, consumeSkip]);

  return (
    <>
      <OrbitControls
        ref={controls}
        makeDefault
        enableDamping={!reducedMotion}
        dampingFactor={0.12}
        rotateSpeed={0.7}
        zoomSpeed={0.8}
        minDistance={0.6}
        maxDistance={14}
      />
      <PerformanceMonitor onDecline={() => setDpr(1)} onIncline={() => setDpr(Math.min(2, window.devicePixelRatio))} />
    </>
  );
}

/** Everything inside the canvas. All colours come in as props: a canvas cannot read the MUI theme. */
export default function MapScene(props: SceneProps) {
  return (
    <>
      <color attach="background" args={[props.paint.background]} />
      <SceneFog background={props.paint.background} />
      <Rig {...props} />
      <Points {...props} />
      <Axes axes={props.axes} paint={props.paint} labelRefs={props.labelRefs} />
      {props.clouds.map((c) => (
        <CloudMesh key={c.key} cloud={c} />
      ))}
    </>
  );
}
