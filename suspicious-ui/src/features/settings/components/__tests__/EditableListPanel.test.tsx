import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";

vi.mock("@/features/settings/api", () => ({
  listItems: vi.fn(),
  addItems: vi.fn(),
  removeItem: vi.fn(),
  addFromFile: vi.fn(),
  fetchListHistory: vi.fn(),
}));

import { addItems, listItems, removeItem } from "@/features/settings/api";
import { EditableListPanel } from "@/features/settings/components/EditableListPanel";

const mockList = vi.mocked(listItems);
const mockAdd = vi.mocked(addItems);
const mockRemove = vi.mocked(removeItem);

// Row controls carry the value in their name; the bulk bar's "Delete 3" and select-all are not rows.
const rowDeletes = () => screen.getAllByRole("button", { name: /^Delete (?!\d+$)\S/ });
const rowSelects = () => screen.getAllByRole("checkbox", { name: /^Select (?!all$)/ });

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

    expect(await screen.findByText("No entries yet. Paste values above or import a file.")).toBeInTheDocument();
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

      await user.click(rowDeletes()[0]);

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

      await user.click(rowDeletes()[0]);
      await user.click(await screen.findByRole("button", { name: "Undo" }));

      expect(await screen.findByText("Could not restore evil.com")).toBeInTheDocument();
      expect(screen.queryByText(/restored\./i)).not.toBeInTheDocument();
    });
  });

  describe("undo outcome", () => {
    async function removeThenUndo(user: ReturnType<typeof userEvent.setup>) {
      mockRemove.mockResolvedValue(undefined);
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");
      await user.click(rowDeletes()[0]);
      await user.click(await screen.findByRole("button", { name: "Undo" }));
    }

    it("does not say Restored when nothing was created because it is already in the list", async () => {
      const user = userEvent.setup();
      mockAdd.mockResolvedValue({ created: [], duplicates: ["evil.com"], watcher_conflicts: [] });
      await removeThenUndo(user);
      expect(
        await screen.findByText("evil.com was not restored (already in the list or in the Watcher list)")
      ).toBeInTheDocument();
      expect(screen.queryByText("Restored evil.com.")).not.toBeInTheDocument();
    });

    it("does not say Restored when the value is in the Watcher list", async () => {
      const user = userEvent.setup();
      mockAdd.mockResolvedValue({ created: [], duplicates: [], watcher_conflicts: ["evil.com"] });
      await removeThenUndo(user);
      expect(
        await screen.findByText("evil.com was not restored (already in the list or in the Watcher list)")
      ).toBeInTheDocument();
    });

    it("calls addItems once and reports once on a fast double click", async () => {
      const user = userEvent.setup();
      mockAdd.mockImplementation(
        () => new Promise((r) => setTimeout(() => r({ created: ["9"], duplicates: [], watcher_conflicts: [] }), 150))
      );
      mockRemove.mockResolvedValue(undefined);
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");
      await user.click(rowDeletes()[0]);
      const undo = await screen.findByRole("button", { name: "Undo" });
      await user.dblClick(undo);
      await screen.findByText("Restored evil.com.");
      await new Promise((r) => setTimeout(r, 300));
      expect(mockAdd).toHaveBeenCalledTimes(1);
      expect(screen.getAllByText("Restored evil.com.")).toHaveLength(1);
    });

    it("keeps the Undo snackbar past notistack's 5 s default (the app default is 3 s)", async () => {
      const user = userEvent.setup();
      mockRemove.mockResolvedValue(undefined);
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");
      await user.click(rowDeletes()[0]);
      await screen.findByRole("button", { name: "Undo" });
      await new Promise((r) => setTimeout(r, 5600));
      expect(screen.getByRole("button", { name: "Undo" })).toBeInTheDocument();
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
      for (const b of rowSelects()) await user.click(b);
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

  describe("bulk delete bookkeeping", () => {
    beforeEach(() => {
      mockList.mockResolvedValue([
        { id: "1", value: "a.com" },
        { id: "2", value: "b.com" },
        { id: "3", value: "c.com" },
      ]);
    });

    it("keeps selected ids that the filter hides after a bulk run", async () => {
      const user = userEvent.setup();
      mockRemove.mockResolvedValue(undefined);
      renderWithProviders(
        <EditableListPanel section="domains_deny" title="Domains denylist" placeholder="Add domains" />
      );
      await screen.findByText("a.com");
      for (const b of rowSelects()) await user.click(b);
      await user.type(screen.getByPlaceholderText("Filter entries…"), "a.com");

      await user.click(screen.getByRole("button", { name: "Delete 1" }));
      expect(await screen.findByRole("dialog")).toHaveTextContent("Delete 1 entry from Domains denylist?");
      await user.click(screen.getByRole("button", { name: "Delete" }));
      await waitFor(() => expect(mockRemove).toHaveBeenCalledTimes(1));
      expect(mockRemove).toHaveBeenCalledWith("domains_deny", "1");

      await user.clear(screen.getByPlaceholderText("Filter entries…"));
      expect(await screen.findByText("2 selected")).toBeInTheDocument();
    });

    it("shows the bulk result once, inline, even when the list ends up empty", async () => {
      const user = userEvent.setup();
      mockRemove.mockResolvedValue(undefined);
      renderWithProviders(
        <EditableListPanel section="domains_deny" title="Domains denylist" placeholder="Add domains" />
      );
      await screen.findByText("a.com");
      for (const b of rowSelects()) await user.click(b);
      mockList.mockResolvedValue([]);
      await user.click(screen.getByRole("button", { name: "Delete 3" }));
      await user.click(await screen.findByRole("button", { name: "Delete" }));

      await screen.findByText("No entries yet. Paste values above or import a file.");
      expect(screen.getAllByText("3 of 3 deleted")).toHaveLength(1);
      // The closing dialog keeps the page aria-hidden for a moment, so wait for the region to be reachable.
      expect(await screen.findByRole("status")).toHaveTextContent("3 of 3 deleted");
    });

    it("clears a stale bulk result when the selection changes", async () => {
      const user = userEvent.setup();
      mockRemove.mockImplementation(async (_s, id) => { if (id === "2") throw new Error("x"); });
      renderWithProviders(
        <EditableListPanel section="domains_deny" title="Domains denylist" placeholder="Add domains" />
      );
      await screen.findByText("a.com");
      for (const b of rowSelects()) await user.click(b);
      await user.click(screen.getByRole("button", { name: "Delete 3" }));
      await user.click(await screen.findByRole("button", { name: "Delete" }));
      expect(await screen.findByText("2 of 3 deleted, 1 failed")).toBeInTheDocument();

      await user.click(await screen.findByRole("button", { name: "Clear" }));
      expect(screen.queryByText("2 of 3 deleted, 1 failed")).not.toBeInTheDocument();
    });

    it("disables every row Delete while a bulk run is in progress", async () => {
      const user = userEvent.setup();
      let release!: () => void;
      mockRemove.mockImplementation(() => new Promise<void>((r) => { release = r; }));
      renderWithProviders(
        <EditableListPanel section="domains_deny" title="Domains denylist" placeholder="Add domains" />
      );
      await screen.findByText("a.com");
      // Select only the first row so the other two rows are idle during the run.
      await user.click(rowSelects()[0]);
      await user.click(screen.getByRole("button", { name: "Delete 1" }));
      await user.click(await screen.findByRole("button", { name: "Delete" }));

      await waitFor(() => expect(mockRemove).toHaveBeenCalledTimes(1));
      await waitFor(() => expect(rowDeletes()).toHaveLength(3));
      for (const b of rowDeletes()) expect(b).toBeDisabled();

      release();
      await screen.findByText("1 of 1 deleted");
    });
  });

  describe("redesigned rows and toolbar", () => {
    it("shows the purpose sentence only when one is given", async () => {
      const { unmount } = renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" purpose="Listed domains are treated as safe." />
      );
      expect(await screen.findByText("Listed domains are treated as safe.")).toBeInTheDocument();
      unmount();
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");
      expect(screen.queryByText("Listed domains are treated as safe.")).not.toBeInTheDocument();
    });

    it("shows the added date in a time element when created_at exists and omits it otherwise", async () => {
      const iso = "2026-03-04T10:00:00Z";
      mockList.mockResolvedValue([
        { id: "1", value: "dated.com", created_at: iso },
        { id: "2", value: "plain.com" },
      ]);
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("dated.com");
      expect(screen.getByText(`Added ${new Date(iso).toLocaleDateString()}`)).toBeInTheDocument();
      expect(screen.getAllByText(/^Added /)).toHaveLength(1);
      const time = document.querySelector("time")!;
      expect(time).toHaveAttribute("datetime", iso);
      expect(time).toHaveAttribute("title", new Date(iso).toLocaleString());
    });

    it("renders nothing for an invalid created_at instead of Invalid Date", async () => {
      mockList.mockResolvedValue([{ id: "1", value: "odd.com", created_at: "not-a-date" }]);
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("odd.com");
      expect(screen.queryByText(/Added/)).not.toBeInTheDocument();
      expect(screen.queryByText(/Invalid Date/)).not.toBeInTheDocument();
      expect(document.querySelector("time")).toBeNull();
    });

    it("keeps the empty bulk status in the accessibility tree before any result", async () => {
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");
      // getByRole skips display:none nodes, so finding it is itself the check; assert the style too.
      const status = screen.getByRole("status");
      expect(status).toBeEmptyDOMElement();
      expect(getComputedStyle(status).display).not.toBe("none");
    });

    it("filters rows by the typed text and shows only the matches", async () => {
      const user = userEvent.setup();
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");
      await user.type(screen.getByPlaceholderText("Filter entries…"), "phish");
      expect(screen.getByText("phish.net")).toBeInTheDocument();
      expect(screen.queryByText("evil.com")).not.toBeInTheDocument();
    });

    it("names each row control after its value so the accessible names are unique", async () => {
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");
      expect(screen.getByRole("button", { name: "Delete evil.com" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Delete phish.net" })).toBeInTheDocument();
      expect(screen.getByRole("checkbox", { name: "Select evil.com" })).not.toBeChecked();
    });

    it("keeps the search field, Import file and the count in the toolbar without a toggle", async () => {
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");
      expect(screen.getByPlaceholderText("Filter entries…")).toBeVisible();
      expect(screen.getByText("Import file")).toBeInTheDocument();
      expect(screen.getByText("2 total")).toBeInTheDocument();
    });

    it("select-all checks every row and the same control clears it", async () => {
      const user = userEvent.setup();
      renderWithProviders(
        <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
      );
      await screen.findByText("evil.com");
      await user.click(screen.getByRole("checkbox", { name: "Select all" }));
      for (const c of rowSelects()) expect(c).toBeChecked();
      expect(screen.getByText("2 selected")).toBeInTheDocument();
      await user.click(screen.getByRole("checkbox", { name: "Deselect all" }));
      for (const c of rowSelects()) expect(c).not.toBeChecked();
    });
  });

  it("uses the shared empty state with the filter text", async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="Add domains" />
    );
    await screen.findByText("evil.com");
    await user.type(screen.getByPlaceholderText("Filter entries…"), "zzz");
    expect(await screen.findByText('No entries matching "zzz"')).toBeInTheDocument();
  });
});
