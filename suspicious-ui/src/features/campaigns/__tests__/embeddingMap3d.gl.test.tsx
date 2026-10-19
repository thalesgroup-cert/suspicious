import { describe, it, expect, vi, afterEach } from "vitest";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BufferGeometry } from "three";
import { renderWithProviders } from "@/test/utils";
import { stubMatchMedia } from "@/test/matchMedia";
import type { PcaPoint } from "@/features/campaigns/api";
import EmbeddingMap from "../components/EmbeddingMap";
import EmbeddingMap3D from "../components/EmbeddingMap3D";
import { detectWebGL } from "../mapSupport";

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

  it("draws, takes colour modes, a selection, filters and keys, then frees its geometry on unmount", async () => {
    stubMatchMedia();
    const errors = vi.spyOn(console, "error");
    const disposed = vi.spyOn(BufferGeometry.prototype, "dispose");
    const user = userEvent.setup();
    const pts = sample(60);
    const { rerender, unmount } = renderWithProviders(<EmbeddingMap3D {...props} points={pts} />);

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
    const before = disposed.mock.calls.length;
    unmount();
    // R3F disposes the scene's geometries on unmount (and our own axis geometry does too)
    await waitFor(() => expect(disposed.mock.calls.length).toBeGreaterThan(before));
    expect(document.querySelector("canvas")).toBeNull();
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
    renderWithProviders(<EmbeddingMap points={sample(30)} explainedVariance={[0.3, 0.2, 0.1]} sampleLimit={1500} selectedCaseIds={[]} onSelectCases={() => {}} />);
    await waitFor(() => expect(document.querySelector("canvas")).not.toBeNull());
    await frames();
    act(() => {
      document.querySelector("canvas")!.dispatchEvent(new Event("webglcontextlost", { cancelable: true }));
    });
    expect(await screen.findByText("3D view unavailable, showing the 2D map.")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Embedding map/ })).toBeInTheDocument();
    expect(document.querySelector("canvas")).toBeNull();
  });
});
