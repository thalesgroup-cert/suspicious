import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";

vi.mock("@/features/settings/api", () => ({
  listItems: vi.fn(),
  addItems: vi.fn(),
  removeItem: vi.fn(),
  addFromFile: vi.fn(),
}));

import { addItems, listItems } from "@/features/settings/api";
import { EditableListPanel } from "@/features/settings/components/EditableListPanel";

const mockList = vi.mocked(listItems);
const mockAdd = vi.mocked(addItems);

describe("EditableListPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockList.mockResolvedValue([
      { id: "1", value: "evil.com" },
      { id: "2", value: "phish.net" },
    ]);
  });

  it("renders fetched items and the total count", async () => {
    renderWithProviders(
      <EditableListPanel section="domains_allow" placeholder="Add domains" />
    );

    expect(await screen.findByText("evil.com")).toBeInTheDocument();
    expect(screen.getByText("phish.net")).toBeInTheDocument();
    expect(screen.getByText("2 total")).toBeInTheDocument();
  });

  it("shows the empty state when the list has no items", async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(
      <EditableListPanel section="domains_allow" placeholder="Add domains" />
    );

    expect(await screen.findByText("No items yet.")).toBeInTheDocument();
  });

  it("parses multi-value input and submits it through addItems", async () => {
    const user = userEvent.setup();
    mockAdd.mockResolvedValue({ created: ["3", "4"], duplicates: [], watcher_conflicts: [] });

    renderWithProviders(
      <EditableListPanel section="domains_allow" placeholder="Add domains" />
    );
    await screen.findByText("evil.com");

    await user.type(screen.getByPlaceholderText("Add domains"), "a.com, b.com");
    await user.click(screen.getByRole("button", { name: /^add$/i }));

    await waitFor(() => {
      expect(mockAdd).toHaveBeenCalledWith("domains_allow", ["a.com", "b.com"]);
    });
  });

  it("does not call addItems when the input is empty", async () => {
    renderWithProviders(
      <EditableListPanel section="domains_allow" placeholder="Add domains" />
    );
    await screen.findByText("evil.com");

    // The Add button is disabled until there is input.
    expect(screen.getByRole("button", { name: /^add$/i })).toBeDisabled();
    expect(mockAdd).not.toHaveBeenCalled();
  });
});
