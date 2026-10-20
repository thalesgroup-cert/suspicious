import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";

vi.mock("@/features/settings/api", () => ({
  listItems: vi.fn(),
  addItems: vi.fn(),
  removeItem: vi.fn(),
  addFromFile: vi.fn(),
  fetchListHistory: vi.fn(),
}));

import { addItems, fetchListHistory, listItems, removeItem } from "@/features/settings/api";
import { EditableListPanel } from "@/features/settings/components/EditableListPanel";

const mockList = vi.mocked(listItems);
const mockAdd = vi.mocked(addItems);
const mockRemove = vi.mocked(removeItem);
const mockHistory = vi.mocked(fetchListHistory);

const panel = () =>
  renderWithProviders(<EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />);

const page = (results: unknown[], next: string | null = null) =>
  ({ count: results.length, next, previous: null, results }) as Awaited<ReturnType<typeof fetchListHistory>>;

const ev = (id: number, action: "added" | "removed", value: string, username: string) => ({
  id, action, value, username, created_at: "2026-10-20T09:00:00Z",
});

const historyButton = () => screen.getByRole("button", { name: /history/i });

describe("EditableListPanel authorship", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockHistory.mockResolvedValue(page([]));
  });

  it("shows the date and the author under each entry", async () => {
    mockList.mockResolvedValue([{ id: "1", value: "evil.com", created_at: "2026-10-20T09:00:00Z", added_by: "alice" }]);
    panel();
    const row = (await screen.findByText("evil.com")).closest("li")!;
    expect(within(row).getByText(/^Added .+ by alice$/)).toBeInTheDocument();
  });

  it("never prints 'by null' when the author is unknown", async () => {
    mockList.mockResolvedValue([{ id: "1", value: "evil.com", created_at: "2026-10-20T09:00:00Z", added_by: null }]);
    panel();
    const row = (await screen.findByText("evil.com")).closest("li")!;
    expect(within(row).getByText(/^Added /)).toBeInTheDocument();
    expect(row.textContent).not.toMatch(/by|null/);
  });

  it("keeps the row control names", async () => {
    mockList.mockResolvedValue([{ id: "1", value: "evil.com", created_at: "2026-10-20T09:00:00Z", added_by: "alice" }]);
    panel();
    await screen.findByText("evil.com");
    expect(screen.getByRole("checkbox", { name: "Select evil.com" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete evil.com" })).toBeInTheDocument();
  });
});

describe("EditableListPanel history", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockList.mockResolvedValue([{ id: "1", value: "evil.com", created_at: "2026-10-20T09:00:00Z", added_by: "alice" }]);
    mockHistory.mockResolvedValue(page([]));
  });

  it("is collapsed and makes no request until opened", async () => {
    panel();
    await screen.findByText("evil.com");
    expect(historyButton()).toHaveAttribute("aria-expanded", "false");
    expect(mockHistory).not.toHaveBeenCalled();
  });

  it("lists events newest first with removed and added wording", async () => {
    const user = userEvent.setup();
    mockHistory.mockResolvedValue(page([ev(2, "removed", "old.com", "bob"), ev(1, "added", "old.com", "alice")]));
    panel();
    await screen.findByText("evil.com");

    await user.click(historyButton());

    expect(historyButton()).toHaveAttribute("aria-expanded", "true");
    expect(mockHistory).toHaveBeenCalledWith("domains_allow", 1);
    const items = within(await screen.findByRole("list", { name: "Change history" })).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(within(items[0]).getByText(/^Removed .+ by bob$/)).toBeInTheDocument();
    expect(within(items[1]).getByText(/^Added .+ by alice$/)).toBeInTheDocument();
  });

  it("says so when nothing has been recorded", async () => {
    const user = userEvent.setup();
    panel();
    await screen.findByText("evil.com");
    await user.click(historyButton());
    expect(
      await screen.findByText("No changes recorded yet. History starts when this version is installed.")
    ).toBeInTheDocument();
  });

  it("shows an error when the history cannot be loaded", async () => {
    const user = userEvent.setup();
    mockHistory.mockRejectedValue(new Error("boom"));
    panel();
    await screen.findByText("evil.com");
    await user.click(historyButton());
    expect(await screen.findByText("Failed to load history.")).toBeInTheDocument();
  });

  it("loads the next page on Load more and hides the button at the end", async () => {
    const user = userEvent.setup();
    mockHistory
      .mockResolvedValueOnce(page([ev(2, "added", "two.com", "alice")], "next"))
      .mockResolvedValueOnce(page([ev(1, "added", "one.com", "bob")]));
    panel();
    await screen.findByText("evil.com");
    await user.click(historyButton());
    await screen.findByText("two.com");

    await user.click(screen.getByRole("button", { name: "Load more" }));

    expect(await screen.findByText("one.com")).toBeInTheDocument();
    expect(mockHistory).toHaveBeenLastCalledWith("domains_allow", 2);
    expect(screen.queryByRole("button", { name: "Load more" })).not.toBeInTheDocument();
  });

  it("refreshes an open history after Undo restores an entry", async () => {
    const user = userEvent.setup();
    mockRemove.mockResolvedValue(undefined);
    mockAdd.mockResolvedValue({ created: ["9"], duplicates: [], watcher_conflicts: [] });
    panel();
    await screen.findByText("evil.com");
    await user.click(historyButton());
    await waitFor(() => expect(mockHistory).toHaveBeenCalledTimes(1));

    await user.click(screen.getByRole("button", { name: "Delete evil.com" }));
    await waitFor(() => expect(mockHistory).toHaveBeenCalledTimes(2));
    mockHistory.mockClear();

    await user.click(await screen.findByRole("button", { name: "Undo" }));
    await waitFor(() => expect(mockHistory).toHaveBeenCalled());
  });

  it("does not refetch a closed history after a removal", async () => {
    const user = userEvent.setup();
    mockRemove.mockResolvedValue(undefined);
    panel();
    await screen.findByText("evil.com");
    await user.click(screen.getByRole("button", { name: "Delete evil.com" }));
    await screen.findByRole("button", { name: "Undo" });
    expect(mockHistory).not.toHaveBeenCalled();
  });
});
