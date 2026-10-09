import { describe, it, expect, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { SubmissionDrawer, type SubmissionDrawerProps } from "../SubmissionDrawer";

const row = {
  id: 18, status: "DONE", artifact: "http://x.example", created_at: "2026-09-21T10:00:00Z",
  tests_done: 3, type: "URL", result: "Dangerous",
} as never;

const base = (over: Partial<SubmissionDrawerProps> = {}): SubmissionDrawerProps => ({
  open: true,
  onClose: vi.fn(),
  row,
  submissionId: 18,
  details: { data: undefined, isLoading: false, isError: false } as never,
  comments: { data: [], isLoading: false } as never,
  onAddComment: vi.fn().mockResolvedValue(undefined),
  isAddingComment: false,
  expandedGroups: {},
  setExpandedGroups: vi.fn(),
  expandedAnalyzerIds: {},
  setExpandedAnalyzerIds: vi.fn(),
  ...over,
});

describe("SubmissionDrawer", () => {
  it("shows the id and calls onClose from Close", async () => {
    const props = base();
    renderWithProviders(<SubmissionDrawer {...props} />);
    expect(await screen.findByText("#18")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(props.onClose).toHaveBeenCalled();
  });

  it("asks for a row when none is selected", async () => {
    renderWithProviders(<SubmissionDrawer {...base({ row: undefined })} />);
    expect(await screen.findByText("Select a row.")).toBeInTheDocument();
  });
});
