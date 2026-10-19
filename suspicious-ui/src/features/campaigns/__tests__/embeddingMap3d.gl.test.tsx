import { describe, it, expect, vi, afterEach } from "vitest";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { userEvent as real } from "@vitest/browser/context";
import * as React from "react";
import { useTheme } from "@mui/material/styles";
import { useThree } from "@react-three/fiber";
import { BufferGeometry, Color, InstancedMesh, Material, type Camera, type Fog, type Scene } from "three";
import { renderWithProviders } from "@/test/utils";
import { stubMatchMedia } from "@/test/matchMedia";
import type { PcaPoint } from "@/features/campaigns/api";
import EmbeddingMap from "../components/EmbeddingMap";
import EmbeddingMap3D from "../components/EmbeddingMap3D";
import { INITIAL_POSITION } from "../geometry";
import { detectWebGL } from "../mapSupport";

// Records what the scene asks of the orbit controls, and the scene and camera it renders into, passing everything
// through to the real controls. (The wrapper renders inside the canvas, so it can reach the three.js objects.)
const live = vi.hoisted(() => ({ controlProps: [] as Record<string, unknown>[], scene: null as unknown, camera: null as unknown }));
const controlProps = live.controlProps;
const scene = () => live.scene as Scene;
const camera = () => live.camera as Camera;
vi.mock("@react-three/drei", async (original) => {
  const drei = await original<typeof import("@react-three/drei")>();
  return {
    ...drei,
    OrbitControls: React.forwardRef<unknown, Record<string, unknown>>((props, ref) => {
      live.scene = useThree((s) => s.scene);
      live.camera = useThree((s) => s.camera);
      live.controlProps.push(props);
      return <drei.OrbitControls ref={ref as never} {...props} />;
    }),
  };
});

// The one test file that lets react-three-fiber draw for real, in the test browser's own WebGL. It is skipped where
// that browser has none: everything else about the map is covered with a stub canvas in embeddingMap3d.test.tsx.

const rng = (seed: number) => () => ((seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296);
function sample(n: number): PcaPoint[] {
  const r = rng(11);
  const labels = ["SAFE", "UNWANTED", "SUSPICIOUS", "DANGEROUS"];
  return Array.from({ length: n }, (_, i) => ({
    x: r() * 2 + (i % 4), y: r() - 0.5 + (i % 3), z: r() - 0.5, label: labels[i % 4],
    suspicious_case_id: String(i + 1), mail_subject: `Mail ${i + 1}`, sourceRefs: [], date: `2026-10-${String((i % 9) + 1).padStart(2, "0")}`,
  }));
}

afterEach(() => vi.unstubAllGlobals());

// Whatever the scene or three.js logged as an error; MUI's own "not wrapped in act" notices are not about the map.
const problems = (spy: { mock: { calls: unknown[][] } }) => spy.mock.calls.filter(([m]) => !/not wrapped in act/.test(String(m)));

describe.skipIf(!detectWebGL())("EmbeddingMap3D with a real WebGL canvas", () => {
  const props = { explainedVariance: [0.3, 0.2, 0.1], campaigns: [], selectedCaseIds: [] as string[], onSelectCases: () => {} };
  const frames = (n = 4) => act(() => new Promise<void>((done) => { let k = 0; const tick = () => (++k >= n ? done() : requestAnimationFrame(tick)); requestAnimationFrame(tick); }));

  it("draws, takes colour modes, a selection, filters and keys, and the degenerate samples, without an error", async () => {
    stubMatchMedia();
    const errors = vi.spyOn(console, "error");
    const user = userEvent.setup();
    const pts = sample(60);
    const { rerender } = renderWithProviders(<EmbeddingMap3D {...props} points={pts} />);

    await waitFor(() => expect(document.querySelector("canvas")).not.toBeNull());
    await frames();
    const group = screen.getByRole("group", { name: "3D embedding map" });

    await user.click(screen.getByRole("button", { name: "Age" }));
    await user.click(screen.getByRole("button", { name: "Campaign" }));
    await user.click(screen.getByRole("button", { name: "Category" }));
    await user.click(screen.getByRole("button", { name: /^Dangerous/ }));
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2" } });
    rerender(<EmbeddingMap3D {...props} points={pts} selectedCaseIds={["5"]} />);
    await frames();
    group.focus();
    for (const key of ["ArrowLeft", "ArrowDown", "+", "-", "0"]) fireEvent.keyDown(group, { key });
    await frames();
    // a sample with no points, then one point, then identical points
    rerender(<EmbeddingMap3D {...props} points={[]} />);
    rerender(<EmbeddingMap3D {...props} points={pts.slice(0, 1)} />);
    rerender(<EmbeddingMap3D {...props} points={[pts[0], { ...pts[0], suspicious_case_id: "x" }]} />);
    await frames();

    expect(problems(errors)).toEqual([]);
  });

  it("disposes the instanced meshes, geometries and materials of the scene on unmount", async () => {
    stubMatchMedia();
    const meshes = vi.spyOn(InstancedMesh.prototype, "dispose");
    const geometries = vi.spyOn(BufferGeometry.prototype, "dispose");
    const materials = vi.spyOn(Material.prototype, "dispose");
    // 60 points, 15 per class: four clouds. One selected point: a ring mesh.
    controlProps.length = 0; // earlier tests left entries: wait for this scene's own controls
    const { unmount } = renderWithProviders(<EmbeddingMap3D {...props} points={sample(60)} selectedCaseIds={["5"]} />);
    await waitFor(() => expect(controlProps.length).toBeGreaterThan(0));
    await frames();
    meshes.mockClear();
    geometries.mockClear();
    materials.mockClear();

    unmount();
    // drawn points, picking points, ring; each with a geometry and a material. Axes: one of each. Clouds: fill and wire, so two of each.
    await waitFor(() => expect(meshes.mock.calls.length).toBeGreaterThanOrEqual(3), { timeout: 4000 });
    await waitFor(() => expect(geometries.mock.calls.length).toBeGreaterThanOrEqual(3 + 1 + 2 * 4), { timeout: 4000 });
    await waitFor(() => expect(materials.mock.calls.length).toBeGreaterThanOrEqual(3 + 1 + 2 * 4), { timeout: 4000 });
    expect(document.querySelector("canvas")).toBeNull();
  });

  it("keeps the fog on the distance to the cloud, in the new background colour, when the theme changes while mounted", async () => {
    stubMatchMedia();
    live.scene = null;
    const Paper = () => <output data-testid="paper">{useTheme().palette.background.paper}</output>;
    renderWithProviders(
      <>
        <Paper />
        <EmbeddingMap3D {...props} points={sample(30)} />
      </>
    );
    await waitFor(() => expect(scene()?.fog).toBeTruthy());
    await frames();
    const paper = () => screen.getByTestId("paper").textContent!;
    const range = () => [(scene().fog as Fog).near, (scene().fog as Fog).far];
    const before = paper();
    // set from the camera distance, not the 1..20 the fog is created with
    expect(range()).not.toEqual([1, 20]);

    act(() => {
      window.dispatchEvent(new CustomEvent("suspicious:theme-hydrate", { detail: { theme: "midnight", autoSeasonal: false } }));
    });
    await waitFor(() => expect(paper()).not.toBe(before));
    await frames();
    const fog = scene().fog as Fog;
    expect(fog.color.getHexString()).toBe(new Color(paper()).getHexString());
    expect(range()).not.toEqual([1, 20]);
    // and it still follows the camera: zooming in moves it
    const at = range();
    const group = screen.getByRole("group", { name: "3D embedding map" });
    fireEvent.keyDown(group, { key: "+" });
    await frames();
    expect(range()).not.toEqual(at);
  });

  it("draws a few thousand points without error", async () => {
    stubMatchMedia();
    const errors = vi.spyOn(console, "error");
    renderWithProviders(<EmbeddingMap3D {...props} points={sample(5000)} />);
    await waitFor(() => expect(document.querySelector("canvas")).not.toBeNull());
    await frames();
    expect(problems(errors)).toEqual([]);
  });

  it("hands over to the 2D map, with a message, when the WebGL context is lost", async () => {
    stubMatchMedia();
    vi.spyOn(console, "error").mockImplementation(() => {});
    controlProps.length = 0;
    renderWithProviders(<EmbeddingMap points={sample(30)} explainedVariance={[0.3, 0.2, 0.1]} sampleLimit={1500} selectedCaseIds={[]} onSelectCases={() => {}} />);
    // the scene (and the context-loss listener, added when the canvas is created) is there once the controls have rendered
    await waitFor(() => expect(controlProps.length).toBeGreaterThan(0));
    await frames();
    act(() => {
      document.querySelector("canvas")!.dispatchEvent(new Event("webglcontextlost", { cancelable: true }));
    });
    expect(await screen.findByText("3D view unavailable, showing the 2D map.")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Embedding map/ })).toBeInTheDocument();
    expect(document.querySelector("canvas")).toBeNull();
  });

  it.each([
    [false, true],
    [true, false],
  ])("prefers-reduced-motion %s: damping %s, and the camera never turns by itself", async (reducedMotion, damping) => {
    stubMatchMedia({ reducedMotion });
    controlProps.length = 0;
    renderWithProviders(<EmbeddingMap3D {...props} points={sample(20)} />);
    await waitFor(() => expect(document.querySelector("canvas")).not.toBeNull());
    await frames();
    await waitFor(() => expect(controlProps.length).toBeGreaterThan(0));
    const controls = controlProps.at(-1)!;
    expect(controls.enableDamping).toBe(damping);
    expect(controls.autoRotate ?? false).toBe(false);
  });

  describe("picking", () => {
    // Two points on the line of sight, one behind the other, both under the middle of the canvas: the camera looks at the
    // middle of the cloud from INITIAL_POSITION's direction. The far point is listed first, so the nearer one is instance 1.
    const dir = (() => {
      const len = Math.hypot(...INITIAL_POSITION);
      return INITIAL_POSITION.map((v) => v / len);
    })();
    const at = (k: number, label: string, id: string): PcaPoint => ({
      x: dir[0] * k, y: dir[1] * k, z: dir[2] * k, label, suspicious_case_id: id, mail_subject: `Mail ${id}`, sourceRefs: [], date: "2026-10-01",
    });
    const pair = [at(-5, "SAFE", "far"), at(5, "DANGEROUS", "near")];
    const target = () => document.querySelector("canvas") as HTMLCanvasElement;
    const centre = () => {
      const r = target().getBoundingClientRect();
      return { x: r.width / 2, y: r.height / 2 };
    };
    // Real pointer input (CDP), so OrbitControls and react-three-fiber see what a user's mouse would send.
    const click = (dx = 0, dy = 0) => real.click(target(), { position: { x: centre().x + dx, y: centre().y + dy } } as never);
    const open = async (onSelectCases: (ids: string[]) => void) => {
      stubMatchMedia();
      controlProps.length = 0;
      renderWithProviders(<EmbeddingMap3D {...props} points={pair} onSelectCases={onSelectCases} />);
      await waitFor(() => expect(controlProps.length).toBeGreaterThan(0));
      await frames();
    };

    it("selects the point under the pointer: the nearer of two on the line of sight, by its instance index", async () => {
      const onSelectCases = vi.fn();
      await open(onSelectCases);
      await click();
      await waitFor(() => expect(onSelectCases).toHaveBeenCalledWith(["near"]));
      expect(onSelectCases).toHaveBeenCalledTimes(1);
    });

    it("picks a point a few pixels off its centre, not one far away", async () => {
      const onSelectCases = vi.fn();
      await open(onSelectCases);
      await click(40, 0);
      await frames();
      expect(onSelectCases).not.toHaveBeenCalled();
      await click(5, 0);
      await waitFor(() => expect(onSelectCases).toHaveBeenCalledWith(["near"]));
    });

    it("does not pick a hidden point, and the one behind it can still be picked", async () => {
      const onSelectCases = vi.fn();
      await open(onSelectCases);
      // hide the nearer one (Dangerous): it still sits, shrunk, on the ray
      await userEvent.click(screen.getByRole("button", { name: /^Dangerous/ }));
      await frames();
      await click();
      await waitFor(() => expect(onSelectCases).toHaveBeenCalledWith(["far"]));
      expect(onSelectCases).not.toHaveBeenCalledWith(["near"]);
    });

    it("treats a press that moved more than a few pixels as a drag, not a click", async () => {
      const onSelectCases = vi.fn();
      await open(onSelectCases);
      // down 6 px off the middle (still on the point's picking sphere), up on the middle: the click lands on the point, after a 6 px drag
      await real.dragAndDrop(target(), target(), {
        sourcePosition: { x: centre().x + 6, y: centre().y },
        targetPosition: { x: centre().x, y: centre().y },
      } as never);
      await frames();
      expect(onSelectCases).not.toHaveBeenCalled();
    });
  });

  describe("camera", () => {
    const rotateTwice = (group: HTMLElement) => {
      group.focus();
      fireEvent.keyDown(group, { key: "ArrowLeft" });
      fireEvent.keyDown(group, { key: "ArrowUp" });
    };
    const holder = () => screen.getByTestId("holder");

    it("Reset view brings the camera back to where it started", async () => {
      stubMatchMedia();
      controlProps.length = 0;
      renderWithProviders(<EmbeddingMap3D {...props} points={sample(30)} />);
      await waitFor(() => expect(controlProps.length).toBeGreaterThan(0));
      await frames();
      const start = camera().position.clone();
      rotateTwice(screen.getByRole("group", { name: "3D embedding map" }));
      await frames();
      expect(camera().position.distanceTo(start)).toBeGreaterThan(0.5);

      await userEvent.click(screen.getByRole("button", { name: "Reset view" }));
      await frames();
      expect(camera().position.distanceTo(start)).toBeLessThan(1e-6);
    });

    it("a resize refits the camera to the new canvas, unless the user has already turned it with the keys", async () => {
      stubMatchMedia();
      controlProps.length = 0;
      renderWithProviders(
        <div data-testid="holder" style={{ width: 600 }}>
          <EmbeddingMap3D {...props} points={sample(30)} />
        </div>
      );
      await waitFor(() => expect(controlProps.length).toBeGreaterThan(0));
      await frames();

      // not moved: a narrower (taller than wide) canvas needs the camera farther away
      const wide = camera().position.length();
      act(() => {
        holder().style.width = "300px";
      });
      await waitFor(() => expect(camera().position.length()).toBeGreaterThan(wide + 0.2));
      await frames();

      // moved with the keys: the next resize keeps that view
      rotateTwice(screen.getByRole("group", { name: "3D embedding map" }));
      await frames();
      const turned = camera().position.clone();
      act(() => {
        holder().style.width = "700px";
      });
      await frames(12);
      expect(camera().position.distanceTo(turned)).toBeLessThan(1e-6);
    });
  });
});
