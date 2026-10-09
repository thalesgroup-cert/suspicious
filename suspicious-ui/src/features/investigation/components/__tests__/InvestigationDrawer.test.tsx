import { describe, it, expect, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { InvestigationDrawer, type InvestigationDrawerProps } from "../InvestigationDrawer";

const idle = { isPending: false, isError: false, mutate: vi.fn(), mutateAsync: vi.fn() };

function props(over: Partial<InvestigationDrawerProps> = {}): InvestigationDrawerProps {
  return {
    open: true,
    onClose: vi.fn(),
    drawerRow: undefined,
    selectedIdNum: 7,
    hasNumericSelectedId: true,
    detailsQuery: { data: undefined, isLoading: true, isError: false, isFetching: false, isPlaceholderData: false } as never,
    detailsReady: false,
    theHiveEnabled: false,
    pushMutation: idle as never,
    editMutation: idle as never,
    editMode: false,
    setEditMode: vi.fn(),
    editScore: "",
    setEditScore: vi.fn(),
    editConfidence: "",
    setEditConfidence: vi.fn(),
    editClassification: "UNKNOWN",
    setEditClassification: vi.fn(),
    onRedo: vi.fn(),
    commentsQuery: { data: [], isLoading: false } as never,
    addCommentMutation: idle as never,
    expandedGroups: {},
    setExpandedGroups: vi.fn(),
    expandedAnalyzerIds: {},
    setExpandedAnalyzerIds: vi.fn(),
    copyEmail: vi.fn(),
    ...over,
  };
}

describe("InvestigationDrawer", () => {
  it("shows the empty state without a row", () => {
    renderWithProviders(<InvestigationDrawer {...props()} />);
    expect(screen.getByText("Select a row.")).toBeInTheDocument();
  });

  it("shows the ID and calls onClose from Close", async () => {
    const p = props({
      drawerRow: { id: 7, status: "DONE", type: "MAIL", result: "SAFE", tests_done: 3, info: "x", created_at: "2026-01-01T00:00:00Z" } as never,
    });
    renderWithProviders(<InvestigationDrawer {...p} />);
    expect(screen.getAllByText("#7").length).toBeGreaterThan(0); // header + summary strip
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(p.onClose).toHaveBeenCalled();
  });
});
