import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { stubMatchMedia } from "@/test/matchMedia";
import type { PcaPoint } from "@/features/campaigns/api";
import EmbeddingMap from "../components/EmbeddingMap";
import Map3D from "../components/EmbeddingMap3D";
import { detectWebGL } from "../mapSupport";

vi.mock("../mapSupport", async (original) => ({ ...(await original<typeof import("../mapSupport")>()), detectWebGL: vi.fn() }));
vi.mock("../components/EmbeddingMap3D", () => ({ default: vi.fn() }));

const pt = (x: number, y: number, z: number, label: string, id: string): PcaPoint => ({
  x, y, z, label, suspicious_case_id: id, mail_subject: `Mail ${id}`, sourceRefs: [], date: "2026-10-10",
});
const points = [pt(0, 0, 0.1, "SAFE", "1"), pt(1, 1, -0.2, "DANGEROUS", "2")];
const noop = () => {};
const MESSAGE = "3D view unavailable, showing the 2D map.";

function renderMap(props: Partial<React.ComponentProps<typeof EmbeddingMap>> = {}) {
  return renderWithProviders(
    <EmbeddingMap points={points} explainedVariance={[0.24, 0.15, 0.09]} sampleLimit={1500} selectedCaseIds={[]} onSelectCases={noop} {...props} />
  );
}
const map2d = () => screen.queryByRole("img", { name: /Embedding map/ });
const caption3d = `PC1 24% + PC2 15% + PC3 9% of the variance. Sample of up to ${(1500).toLocaleString()} messages from the whole store, not limited to the selected period. Closeness is not proof of a campaign.`;
const caption2d = `PC1 24% + PC2 15% of the variance (PC3 not shown). Sample of up to ${(1500).toLocaleString()} messages from the whole store, not limited to the selected period. Closeness is not proof of a campaign.`;

describe("EmbeddingMap: 2D or 3D", () => {
  beforeEach(() => {
    stubMatchMedia();
    vi.mocked(detectWebGL).mockReturnValue(true);
    vi.mocked(Map3D).mockReset().mockImplementation((() => <div data-testid="map3d" />) as never);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("shows the 2D map and says why when WebGL is not available", () => {
    vi.mocked(detectWebGL).mockReturnValue(false);
    renderMap();
    expect(map2d()).toBeInTheDocument();
    expect(screen.getByText(MESSAGE)).toBeInTheDocument();
    expect(screen.queryByTestId("map3d")).not.toBeInTheDocument();
    expect(Map3D).not.toHaveBeenCalled();
    // no 3D to switch to
    expect(screen.queryByRole("button", { name: "3D view" })).not.toBeInTheDocument();
    expect(screen.getByText(caption2d)).toBeInTheDocument();
  });

  it("shows the 2D map, with no message, when the backend sent two components", () => {
    renderMap({ explainedVariance: [0.24, 0.15] });
    expect(map2d()).toBeInTheDocument();
    expect(screen.queryByText(MESSAGE)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "3D view" })).not.toBeInTheDocument();
    expect(Map3D).not.toHaveBeenCalled();
    expect(screen.getByText(/^PC1 24% \+ PC2 15% of the variance\. Sample/)).toBeInTheDocument();
  });

  it("loads the 3D map when WebGL and three components exist, with a placeholder meanwhile", async () => {
    renderMap({ selectedCaseIds: ["2"] });
    expect(screen.getByText("Loading the 3D map")).toBeInTheDocument();
    expect(await screen.findByTestId("map3d")).toBeInTheDocument();
    expect(screen.queryByText("Loading the 3D map")).not.toBeInTheDocument();
    expect(map2d()).not.toBeInTheDocument();
    expect(screen.queryByText(MESSAGE)).not.toBeInTheDocument();
    const props = vi.mocked(Map3D).mock.calls[0][0];
    expect(props.points).toBe(points);
    expect(props.explainedVariance).toEqual([0.24, 0.15, 0.09]);
    expect(props.selectedCaseIds).toEqual(["2"]);
    expect(screen.getByText(caption3d)).toBeInTheDocument();
  });

  it("falls back to the 2D map, with a polite message, when the 3D map throws", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(Map3D).mockImplementation((() => {
      throw new Error("WebGL context lost");
    }) as never);
    renderMap();
    const note = await screen.findByText(MESSAGE);
    expect(note.closest('[role="status"]')).not.toBeNull();
    expect(map2d()).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "3D view" })).not.toBeInTheDocument();
    expect(screen.getByText(caption2d)).toBeInTheDocument();
    vi.restoreAllMocks();
  });

  it("switches between the views with two constant buttons that carry the state in aria-pressed", async () => {
    const user = userEvent.setup();
    renderMap();
    await screen.findByTestId("map3d");
    const to2d = () => screen.getByRole("button", { name: "2D view" });
    const to3d = () => screen.getByRole("button", { name: "3D view" });
    expect(to3d()).toHaveAttribute("aria-pressed", "true");
    expect(to2d()).toHaveAttribute("aria-pressed", "false");

    await user.click(to2d());
    expect(to2d()).toHaveAttribute("aria-pressed", "true");
    expect(to3d()).toHaveAttribute("aria-pressed", "false");
    expect(map2d()).toBeInTheDocument();
    expect(screen.queryByTestId("map3d")).not.toBeInTheDocument();
    // the user chose 2D: that is not a failure
    expect(screen.queryByText(MESSAGE)).not.toBeInTheDocument();
    expect(screen.getByText(caption2d)).toBeInTheDocument();

    await user.click(to3d());
    expect(await screen.findByTestId("map3d")).toBeInTheDocument();
    expect(screen.getByText(caption3d)).toBeInTheDocument();
  });

  it("keeps the table as the text alternative in 3D", async () => {
    const user = userEvent.setup();
    renderMap();
    await screen.findByTestId("map3d");
    await user.click(screen.getByRole("button", { name: "Table view" }));
    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(screen.queryByTestId("map3d")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Table view" }));
    expect(await screen.findByTestId("map3d")).toBeInTheDocument();
  });

  it("still says so when there are no messages", () => {
    renderMap({ points: [] });
    expect(screen.getByText("No messages with an embedding in the store.")).toBeInTheDocument();
    expect(Map3D).not.toHaveBeenCalled();
    expect(within(document.body).queryByRole("button", { name: "Table view" })).not.toBeInTheDocument();
  });
});
