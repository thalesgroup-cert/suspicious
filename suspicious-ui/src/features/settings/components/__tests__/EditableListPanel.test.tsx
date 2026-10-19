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

import { addItems, listItems, removeItem } from "@/features/settings/api";
import { EditableListPanel } from "@/features/settings/components/EditableListPanel";

const mockList = vi.mocked(listItems);
const mockAdd = vi.mocked(addItems);
const mockRemove = vi.mocked(removeItem);

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
      <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
    );

    expect(await screen.findByText("evil.com")).toBeInTheDocument();
    expect(screen.getByText("phish.net")).toBeInTheDocument();
    expect(screen.getByText("2 total")).toBeInTheDocument();
  });

  it("shows the empty state when the list has no items", async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(
      <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
    );

    expect(await screen.findByText("No items yet.")).toBeInTheDocument();
  });

  it("parses multi-value input and submits it through addItems", async () => {
    const user = userEvent.setup();
    mockAdd.mockResolvedValue({ created: ["3", "4"], duplicates: [], watcher_conflicts: [] });

    renderWithProviders(
      <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
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
      <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
    );
    await screen.findByText("evil.com");

    expect(screen.getByRole("button", { name: /^add$/i })).toBeDisabled();
    expect(mockAdd).not.toHaveBeenCalled();
  });

  it("describes why Add is disabled while the input is empty", async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
    );
    await screen.findByText("evil.com");

    const add = screen.getByRole("button", { name: /^add$/i });
    expect(add).toHaveAccessibleDescription("Enter at least one value");
    expect(screen.getByText("Enter at least one value")).toBeVisible();

    await user.type(screen.getByPlaceholderText("Add domains"), "a.com");
    expect(add).toBeEnabled();
    expect(screen.queryByText("Enter at least one value")).not.toBeInTheDocument();
  });

  describe("single removal", () => {
    it("removes without a dialog and offers Undo that re-adds the value once", async () => {
      const user = userEvent.setup();
      mockRemove.mockResolvedValue(undefined);
      mockAdd.mockResolvedValue({ created: ["9"], duplicates: [], watcher_conflicts: [] });
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");
      mockList.mockClear();

      await user.click(screen.getAllByRole("button", { name: "Delete" })[0]);

      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      await waitFor(() => expect(mockRemove).toHaveBeenCalledWith("domains_allow", "1"));
      const undo = await screen.findByRole("button", { name: "Undo" });
      await waitFor(() => expect(mockList).toHaveBeenCalled());

      mockList.mockClear();
      await user.click(undo);

      await waitFor(() => expect(mockAdd).toHaveBeenCalledTimes(1));
      expect(mockAdd).toHaveBeenCalledWith("domains_allow", ["evil.com"]);
      await waitFor(() => expect(mockList).toHaveBeenCalled());
    });

    it("says so when Undo fails and does not claim the value was restored", async () => {
      const user = userEvent.setup();
      mockRemove.mockResolvedValue(undefined);
      mockAdd.mockRejectedValue(new Error("boom"));
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");

      await user.click(screen.getAllByRole("button", { name: "Delete" })[0]);
      await user.click(await screen.findByRole("button", { name: "Undo" }));

      expect(await screen.findByText("Could not restore evil.com")).toBeInTheDocument();
      expect(screen.queryByText(/restored\./i)).not.toBeInTheDocument();
    });
  });

  describe("bulk delete", () => {
    beforeEach(() => {
      mockList.mockResolvedValue([
        { id: "1", value: "a.com" },
        { id: "2", value: "b.com" },
        { id: "3", value: "c.com" },
      ]);
    });

    async function selectAll(user: ReturnType<typeof userEvent.setup>) {
      await screen.findByText("a.com");
      for (const b of screen.getAllByRole("button", { name: "Select" })) await user.click(b);
    }

    it("asks with the selected count and list title, and Cancel does nothing", async () => {
      const user = userEvent.setup();
      renderWithProviders(
        <EditableListPanel section="domains_deny" title="Domains denylist" placeholder="Add domains" />
      );
      await selectAll(user);

      await user.click(screen.getByRole("button", { name: "Delete 3" }));
      const dialog = await screen.findByRole("dialog");
      expect(dialog).toHaveTextContent("Delete 3 entries from Domains denylist? This cannot be undone.");

      await user.click(screen.getByRole("button", { name: "Cancel" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      expect(mockRemove).not.toHaveBeenCalled();
    });

    it("reports a partial failure, keeps the failed id selected and refreshes without an unhandled rejection", async () => {
      const user = userEvent.setup();
      const rejections: unknown[] = [];
      const onRejection = (e: PromiseRejectionEvent) => { rejections.push(e.reason); e.preventDefault(); };
      window.addEventListener("unhandledrejection", onRejection);
      try {
        mockRemove.mockImplementation(async (_s, id) => { if (id === "2") throw new Error("nope"); });
        renderWithProviders(
          <EditableListPanel section="domains_deny" title="Domains denylist" placeholder="Add domains" />
        );
        await selectAll(user);
        mockList.mockClear();

        await user.click(screen.getByRole("button", { name: "Delete 3" }));
        await user.click(await screen.findByRole("button", { name: "Delete" }));

        expect(mockRemove).toHaveBeenCalledTimes(3);
        const status = await screen.findByRole("status");
        expect(status).toHaveTextContent("2 of 3 deleted, 1 failed");
        expect(screen.getByText("1 selected")).toBeInTheDocument();
        await waitFor(() => expect(mockList).toHaveBeenCalled());
        await new Promise((r) => setTimeout(r, 50));
        expect(rejections).toEqual([]);
      } finally {
        window.removeEventListener("unhandledrejection", onRejection);
      }
    });
  });

  it("uses the shared empty state with the filter text", async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
    );
    await screen.findByText("evil.com");
    await user.click(screen.getByRole("button", { name: "Search items" }));
    await user.type(screen.getByPlaceholderText("Filter items…"), "zzz");
    expect(await screen.findByText('No items matching "zzz"')).toBeInTheDocument();
  });
});
