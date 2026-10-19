import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createTestQueryClient, renderWithProviders } from "@/test/utils";

vi.mock("@/features/settings/api", () => ({
  listAnalyzers: vi.fn(),
  updateAnalyzerWeight: vi.fn(),
}));
vi.mock("@/features/settings/unsaved", () => ({ useReportUnsaved: vi.fn() }));

import { listAnalyzers, updateAnalyzerWeight, type Analyzer } from "@/features/settings/api";
import { useReportUnsaved } from "@/features/settings/unsaved";
import { ScoringTable } from "@/features/settings/components/ScoringTable";

const A = (id: number, name: string, weight: number, is_active = true): Analyzer => ({
  id, name, weight, analyzer_cortex_id: `${name.toLowerCase()}_1_0`, is_active,
});
const THREE = [A(1, "Alpha", 0.2), A(2, "Bravo", 0.3), A(3, "Charlie", 0.5)];

function names() {
  return screen.getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell")[0].textContent ?? "");
}
const num = (name: string) => screen.getByRole("spinbutton", { name: `${name} weight value` }) as HTMLInputElement;

describe("ScoringTable", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(listAnalyzers).mockResolvedValue(THREE);
    vi.mocked(updateAnalyzerWeight).mockResolvedValue({});
  });
  afterEach(() => vi.restoreAllMocks());

  async function setup(list: Analyzer[] = THREE, queryClient = createTestQueryClient()) {
    vi.mocked(listAnalyzers).mockResolvedValue(list);
    const user = userEvent.setup();
    renderWithProviders(<ScoringTable />, { queryClient });
    await screen.findByRole("table", { name: "Analyzer weights" });
    return user;
  }

  it("explains that weights are relative and shows shares", async () => {
    await setup();
    expect(screen.getByText(/Weights are relative\. A case's score is the weighted average/)).toBeInTheDocument();
    expect(screen.getByText("20%")).toBeInTheDocument();
    expect(screen.getByText("50%")).toBeInTheDocument();
  });

  it("filters by name and by cortex id, case-insensitively", async () => {
    const user = await setup();
    const search = screen.getByRole("searchbox", { name: "Search analyzers" });
    await user.type(search, "BRAV");
    expect(names()).toEqual([expect.stringContaining("Bravo")]);
    await user.clear(search);
    await user.type(search, "charlie_1");
    expect(names()).toEqual([expect.stringContaining("Charlie")]);
  });

  it("sorts by name, weight and share with aria-sort on the active header", async () => {
    const user = await setup();
    const th = (n: string) => screen.getByRole("columnheader", { name: new RegExp(n) });
    expect(th("Analyzer")).toHaveAttribute("aria-sort", "ascending");
    expect(th("Weight")).toHaveAttribute("aria-sort", "none");

    await user.click(screen.getByRole("button", { name: /Sort by Analyzer/ }));
    expect(th("Analyzer")).toHaveAttribute("aria-sort", "descending");
    expect(names()[0]).toContain("Charlie");

    await user.click(screen.getByRole("button", { name: /Sort by Weight/ }));
    expect(th("Weight")).toHaveAttribute("aria-sort", "ascending");
    expect(th("Analyzer")).toHaveAttribute("aria-sort", "none");
    expect(names()[0]).toContain("Alpha");
    await user.click(screen.getByRole("button", { name: /Sort by Weight/ }));
    expect(th("Weight")).toHaveAttribute("aria-sort", "descending");
    expect(names()[0]).toContain("Charlie");

    await user.click(screen.getByRole("button", { name: /Sort by Share/ }));
    expect(th("Share")).toHaveAttribute("aria-sort", "ascending");
    expect(names()[0]).toContain("Alpha");
  });

  it("keeps the slider and number input in sync and clamps to 0..1 with one decimal", async () => {
    const user = await setup();
    const slider = screen.getByRole("slider", { name: "Alpha weight" });
    expect(slider).toHaveAttribute("aria-valuetext", "0.2, 20% of the total");

    fireEvent.change(num("Alpha"), { target: { value: "0.7" } });
    expect(slider).toHaveAttribute("aria-valuenow", "0.7");
    fireEvent.change(num("Alpha"), { target: { value: "5" } });
    fireEvent.blur(num("Alpha"));
    expect(num("Alpha").value).toBe("1.0");
    fireEvent.change(num("Alpha"), { target: { value: "-2" } });
    fireEvent.blur(num("Alpha"));
    expect(num("Alpha").value).toBe("0.0");
    fireEvent.change(num("Alpha"), { target: { value: "0.34" } });
    fireEvent.blur(num("Alpha"));
    expect(num("Alpha").value).toBe("0.3");

    act(() => slider.focus());
    await user.keyboard("{ArrowRight}");
    expect(num("Alpha").value).toBe("0.4");
    await user.keyboard("{End}");
    expect(num("Alpha").value).toBe("1.0");
  });

  it("marks a changed row Modified in text and filters with Modified only", async () => {
    const user = await setup();
    fireEvent.change(num("Bravo"), { target: { value: "0.9" } });
    expect(screen.getByText("Modified")).toBeInTheDocument();
    expect(screen.getByText("1 unsaved change")).toBeInTheDocument();

    const toggle = screen.getByRole("button", { name: "Modified only" });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-pressed", "true");
    expect(names()).toEqual([expect.stringContaining("Bravo")]);
  });

  it("shows Inactive as a text chip and keeps inactive weights in the shares", async () => {
    await setup([A(1, "Alpha", 0.5), A(2, "Dormant", 0.5, false)]);
    expect(screen.getByText("Inactive")).toBeInTheDocument();
    expect(screen.getAllByText("50%")).toHaveLength(2);
  });

  it("Reset to saved restores every draft", async () => {
    const user = await setup();
    fireEvent.change(num("Alpha"), { target: { value: "0.9" } });
    await user.click(screen.getByRole("button", { name: "Reset to saved" }));
    expect(num("Alpha").value).toBe("0.2");
    expect(screen.queryByText(/^\d+ unsaved change/)).not.toBeInTheDocument();
    expect(screen.getByText("No unsaved changes")).toBeInTheDocument();
  });

  it("Save all with one of three failing reports real counts and keeps the failed row modified", async () => {
    const user = await setup();
    vi.mocked(updateAnalyzerWeight).mockImplementation(async (id: number) => {
      if (id === 2) throw new Error("boom");
      return {};
    });
    fireEvent.change(num("Alpha"), { target: { value: "0.6" } });
    fireEvent.change(num("Bravo"), { target: { value: "0.7" } });
    fireEvent.change(num("Charlie"), { target: { value: "0.8" } });
    // What the server holds after the two successful saves; Bravo kept its old weight.
    vi.mocked(listAnalyzers).mockResolvedValue([A(1, "Alpha", 0.6), A(2, "Bravo", 0.3), A(3, "Charlie", 0.8)]);
    const calls = vi.mocked(listAnalyzers).mock.calls.length;

    await user.click(screen.getByRole("button", { name: "Save all" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("2 of 3 saved, 1 failed"));
    expect(updateAnalyzerWeight).toHaveBeenCalledTimes(3);
    expect(updateAnalyzerWeight).toHaveBeenCalledWith(1, 0.6);
    await waitFor(() => expect(vi.mocked(listAnalyzers).mock.calls.length).toBeGreaterThan(calls));
    await waitFor(() => expect(screen.getByText("1 unsaved change")).toBeInTheDocument());
    expect(num("Bravo").value).toBe("0.7");
  });

  it("refuses to save when every active draft is 0, without any request", async () => {
    const user = await setup([A(1, "Alpha", 0.2), A(2, "Dormant", 0.9, false)]);
    fireEvent.change(num("Alpha"), { target: { value: "0" } });
    await user.click(screen.getByRole("button", { name: "Save all" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "At least one active analyzer needs a weight above 0, otherwise no case can be scored.",
    );
    expect(updateAnalyzerWeight).not.toHaveBeenCalled();
  });

  it("allows one analyzer at 0 while another is above 0", async () => {
    const user = await setup();
    fireEvent.change(num("Alpha"), { target: { value: "0" } });
    await user.click(screen.getByRole("button", { name: "Save all" }));
    await waitFor(() => expect(updateAnalyzerWeight).toHaveBeenCalledWith(1, 0));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says Nothing to save when nothing is modified", async () => {
    const user = await setup();
    await user.click(screen.getByRole("button", { name: "Save all" }));
    expect(screen.getByRole("status")).toHaveTextContent("Nothing to save");
    expect(updateAnalyzerWeight).not.toHaveBeenCalled();
  });

  it("reports unsaved changes while modified and clears them after saving", async () => {
    const user = await setup();
    expect(vi.mocked(useReportUnsaved)).toHaveBeenLastCalledWith("scoring", false);
    fireEvent.change(num("Alpha"), { target: { value: "0.9" } });
    expect(vi.mocked(useReportUnsaved)).toHaveBeenLastCalledWith("scoring", true);
    vi.mocked(listAnalyzers).mockResolvedValue([A(1, "Alpha", 0.9), A(2, "Bravo", 0.3), A(3, "Charlie", 0.5)]);
    await user.click(screen.getByRole("button", { name: "Save all" }));
    await waitFor(() => expect(vi.mocked(useReportUnsaved)).toHaveBeenLastCalledWith("scoring", false));
  });

  it("uses no literal red, amber or green in its source", async () => {
    const src = (await import("../ScoringTable?raw")).default as string;
    expect(src).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(src).not.toMatch(/palette\.(error|warning|success)/);
  });

  it("renders one row per analyzer for 26 analyzers", async () => {
    const many = Array.from({ length: 26 }, (_, i) => A(i + 1, `Analyzer${String(i).padStart(2, "0")}`, 0.1));
    await setup(many);
    expect(screen.getAllByRole("row")).toHaveLength(27);
  });

  it("sends the raise before the cut so a valid swap passes the server guard", async () => {
    const user = await setup([A(1, "Aa", 0.5), A(2, "Bb", 0)]);
    fireEvent.change(num("Aa"), { target: { value: "0" } });
    fireEvent.change(num("Bb"), { target: { value: "0.5" } });
    await user.click(screen.getByRole("button", { name: "Save all" }));
    await waitFor(() => expect(updateAnalyzerWeight).toHaveBeenCalledTimes(2));
    expect(vi.mocked(updateAnalyzerWeight).mock.calls).toEqual([[2, 0.5], [1, 0]]);
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("2 of 2 saved"));
  });

  it("keeps a newer edit made while the save was in flight", async () => {
    const user = await setup();
    let release: () => void = () => undefined;
    vi.mocked(updateAnalyzerWeight).mockImplementation(
      () => new Promise((resolve) => { release = () => resolve({}); }),
    );
    fireEvent.change(num("Alpha"), { target: { value: "0.6" } });
    vi.mocked(listAnalyzers).mockResolvedValue([A(1, "Alpha", 0.6), A(2, "Bravo", 0.3), A(3, "Charlie", 0.5)]);
    await user.click(screen.getByRole("button", { name: "Save all" }));
    await waitFor(() => expect(updateAnalyzerWeight).toHaveBeenCalledWith(1, 0.6));
    fireEvent.change(num("Alpha"), { target: { value: "0.9" } });
    release();
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("1 of 1 saved"));
    await waitFor(() => expect(screen.getByRole("button", { name: "Save all" })).toBeEnabled());
    expect(num("Alpha").value).toBe("0.9");
    expect(screen.getByText("1 unsaved change")).toBeInTheDocument();
  });

  it("adds the server message to the status when exactly one row fails", async () => {
    const user = await setup();
    const guard = "At least one active analyzer must keep a weight above 0.";
    vi.mocked(updateAnalyzerWeight).mockImplementation(async (id: number) => {
      if (id === 2) throw { response: { data: { weight: [guard] } } };
      return {};
    });
    fireEvent.change(num("Alpha"), { target: { value: "0.6" } });
    fireEvent.change(num("Bravo"), { target: { value: "0.7" } });
    await user.click(screen.getByRole("button", { name: "Save all" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(`1 of 2 saved, 1 failed: ${guard}`));
  });

  it("counts and saves a modified row that search or Modified only hides", async () => {
    const user = await setup();
    fireEvent.change(num("Alpha"), { target: { value: "0.9" } });
    await user.type(screen.getByRole("searchbox", { name: "Search analyzers" }), "bravo");
    expect(names()).toEqual([expect.stringContaining("Bravo")]);
    expect(screen.getByText("1 unsaved change")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Modified only" }));
    expect(screen.getByText("No analyzers match.")).toBeInTheDocument();
    expect(screen.getByText("1 unsaved change")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save all" }));
    await waitFor(() => expect(updateAnalyzerWeight).toHaveBeenCalledWith(1, 0.9));
  });

  it("does not let a background refetch overwrite an unsaved draft", async () => {
    const qc = createTestQueryClient();
    await setup(THREE, qc);
    fireEvent.change(num("Alpha"), { target: { value: "0.9" } });
    vi.mocked(listAnalyzers).mockResolvedValue([A(1, "Alpha", 0.4), A(2, "Bravo", 0.3), A(3, "Charlie", 0.5)]);
    await act(() => qc.invalidateQueries({ queryKey: ["settings", "scoring"] }));
    expect(num("Alpha").value).toBe("0.9");
    expect(screen.getByText("1 unsaved change")).toBeInTheDocument();
  });

  it("keeps explicit table roles so the phone layout does not drop the semantics", async () => {
    await setup();
    const table = screen.getByRole("table", { name: "Analyzer weights" });
    expect(table).toHaveAttribute("role", "table");
    const roleOf = (sel: string) => [...table.querySelectorAll(sel)].map((el) => el.getAttribute("role"));
    expect(roleOf("thead, tbody")).toEqual(["rowgroup", "rowgroup"]);
    expect(new Set(roleOf("tr"))).toEqual(new Set(["row"]));
    expect(new Set(roleOf("th"))).toEqual(new Set(["columnheader"]));
    expect(new Set(roleOf("td"))).toEqual(new Set(["cell"]));
  });
});
