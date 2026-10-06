import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { renderWithProviders } from "@/test/utils";
import { listAnalyzers, type Analyzer } from "@/features/settings/api";
import { ScoringPanel } from "../ScoringPanel";

vi.mock("@/features/settings/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/features/settings/api")>();
  return { ...actual, listAnalyzers: vi.fn(), updateAnalyzerWeight: vi.fn() };
});

const ANALYZERS: Analyzer[] = [
  { id: 1, name: "ActiveOne", weight: 1, analyzer_cortex_id: "a", is_active: true },
  { id: 2, name: "SleepyTwo", weight: 1, analyzer_cortex_id: "b", is_active: false },
];

describe("ScoringPanel status filter", () => {
  it("shows every analyzer, then only active, then only inactive", async () => {
    vi.mocked(listAnalyzers).mockResolvedValue(ANALYZERS);
    const user = userEvent.setup();
    renderWithProviders(<ScoringPanel />);

    await waitFor(() => expect(screen.getByText("ActiveOne")).toBeInTheDocument());
    expect(screen.getByText("SleepyTwo")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Active" }));
    expect(screen.getByText("ActiveOne")).toBeInTheDocument();
    expect(screen.queryByText("SleepyTwo")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Inactive" }));
    expect(screen.queryByText("ActiveOne")).not.toBeInTheDocument();
    expect(screen.getByText("SleepyTwo")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "All" }));
    expect(screen.getByText("ActiveOne")).toBeInTheDocument();
    expect(screen.getByText("SleepyTwo")).toBeInTheDocument();
  });
});
