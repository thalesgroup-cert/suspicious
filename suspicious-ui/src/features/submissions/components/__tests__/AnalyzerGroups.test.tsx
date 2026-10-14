import { describe, it, expect, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { AnalyzerGroups } from "../AnalyzerGroups";

const rep = (id: number, name: string) => ({
  id, cortex_job_id: `j${id}`, type: "domain", status: "Success", analyzer_name: name, analyzer_id: name,
  level: "info", confidence: 20, score: 2, category: null, categories: [], target: { kind: "DOMAIN", id: null, value: "d.example" },
});

describe("AnalyzerGroups", () => {
  it("builds the extra details only for an expanded row", async () => {
    const extra = vi.fn((_r: { id: number }) => <span>extra-facts</span>);
    renderWithProviders(<AnalyzerGroups reports={[rep(1, "One"), rep(2, "Two")] as never} isLoading={false} isError={false} extraDetails={extra} />);
    expect(screen.getByText("One")).toBeInTheDocument();
    expect(extra).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: /^One/ }));
    expect(extra).toHaveBeenCalled();
    expect(extra.mock.calls.every(([r]) => r.id === 1)).toBe(true);
    expect(await screen.findByText("extra-facts")).toBeInTheDocument();
  });

  it("labels the list Observables by default and takes a listLabel", () => {
    const { unmount } = renderWithProviders(<AnalyzerGroups reports={[rep(1, "One")] as never} isLoading={false} isError={false} />);
    expect(screen.getByRole("list", { name: "Observables" })).toBeInTheDocument();
    unmount();
    renderWithProviders(<AnalyzerGroups reports={[rep(1, "One")] as never} isLoading={false} isError={false} listLabel="Analyzed items" />);
    expect(screen.getByRole("list", { name: "Analyzed items" })).toBeInTheDocument();
  });
});
