import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { stubMatchMedia } from "@/test/matchMedia";

vi.mock("@/features/settings/api", () => ({
  listItems: vi.fn(),
  addItems: vi.fn(),
  removeItem: vi.fn(),
  addFromFile: vi.fn(),
}));

import { listItems } from "@/features/settings/api";
import { CisoUsersPanel } from "@/features/settings/components/CisoUsersPanel";
import { DomainPairPanel } from "@/features/settings/components/ReadOnlyListPanel";

const USERS = [
  { id: "1", username: "adaeze", email: "a@x.io", scope: "EMEA", function: "CISO", gbu: "Cyber", country: "GB", region: "EMEA" },
  { id: "2", username: "jordan", email: "j@x.io", function: "Analyst", gbu: "Retail", country: "US", region: "NORAM" },
];

describe("CisoUsersPanel", () => {
  beforeEach(() => { vi.clearAllMocks(); stubMatchMedia(); });
  afterEach(() => vi.unstubAllGlobals());

  it("renders a captioned table with the six columns under the page h2", async () => {
    vi.mocked(listItems).mockResolvedValue(USERS as never);
    renderWithProviders(
      <>
        <h2>CISO users</h2>
        <CisoUsersPanel />
      </>
    );
    const table = await screen.findByRole("table", { name: "CISO users" });
    for (const h of ["User", "Function", "Scope", "GBU", "Country", "Region"]) {
      expect(within(table).getByRole("columnheader", { name: h })).toBeInTheDocument();
    }
    // One h2 and no per-user heading: the table is the structure.
    expect(screen.queryAllByRole("heading", { level: 3 })).toHaveLength(0);
  });

  it("puts the username with the email below it and the other facts in their cells", async () => {
    vi.mocked(listItems).mockResolvedValue(USERS as never);
    renderWithProviders(<CisoUsersPanel />);
    const row = (await screen.findByRole("row", { name: /adaeze/ }));
    const cells = within(row).getAllByRole("cell");
    expect(cells[0]).toHaveTextContent("adaeze");
    expect(cells[0]).toHaveTextContent("a@x.io");
    expect(cells[1]).toHaveTextContent("CISO");
    expect(cells[2]).toHaveTextContent("EMEA");
    expect(cells[3]).toHaveTextContent("Cyber");
    expect(cells[4]).toHaveTextContent("GB");
    expect(cells[5]).toHaveTextContent("EMEA");
  });

  it("says No scope in words when a user has none", async () => {
    vi.mocked(listItems).mockResolvedValue(USERS as never);
    renderWithProviders(<CisoUsersPanel />);
    const row = await screen.findByRole("row", { name: /jordan/ });
    expect(within(row).getByText("No scope")).toBeInTheDocument();
  });

  it("filters by search text and shows N / M", async () => {
    const user = userEvent.setup();
    vi.mocked(listItems).mockResolvedValue(USERS as never);
    renderWithProviders(<CisoUsersPanel />);
    await screen.findByRole("table", { name: "CISO users" });
    expect(screen.getByText("2 / 2")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox"), "noram");
    expect(screen.getByText("1 / 2")).toBeInTheDocument();
    expect(screen.queryByRole("row", { name: /adaeze/ })).not.toBeInTheDocument();
  });

  it("uses stacked cards instead of a table on a phone", async () => {
    stubMatchMedia({ phone: true });
    vi.mocked(listItems).mockResolvedValue(USERS as never);
    renderWithProviders(
      <>
        <h2>CISO users</h2>
        <CisoUsersPanel />
      </>
    );
    const list = await screen.findByRole("list", { name: "CISO users" });
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    const cards = within(list).getAllByRole("listitem");
    expect(cards).toHaveLength(2);
    expect(cards[0]).toHaveTextContent("adaeze");
    expect(cards[0]).toHaveTextContent("a@x.io");
    expect(cards[0]).toHaveTextContent("EMEA");
    expect(within(cards[1]).getByText("No scope")).toBeInTheDocument();
    expect(screen.queryAllByRole("heading", { level: 3 })).toHaveLength(0);
  });

  it("uses the shared empty state when there are no users", async () => {
    vi.mocked(listItems).mockResolvedValue([]);
    renderWithProviders(<CisoUsersPanel />);
    expect(await screen.findByText("No CISO users.")).toBeInTheDocument();
  });

  it("keeps the error copy when loading fails", async () => {
    vi.mocked(listItems).mockRejectedValue(new Error("x"));
    renderWithProviders(<CisoUsersPanel />);
    expect(await screen.findByText("Failed to load CISO users.")).toBeInTheDocument();
  });
});

describe("DomainPairPanel", () => {
  beforeEach(() => vi.clearAllMocks());

  function mockLists(
    watcher: { id: string; value: string; created_at?: string }[],
    watcherSection = "watcher_monitored_domains",
  ) {
    vi.mocked(listItems).mockImplementation(async (section: string) =>
      section === watcherSection ? watcher : [{ id: "1", value: "evil.com" }]
    );
  }

  it("titles the Watcher block as read-only with an h3 and the synced count", async () => {
    mockLists([{ id: "w1", value: "watched.example" }, { id: "w2", value: "other.example" }]);
    renderWithProviders(<DomainPairPanel editableSection="domains_deny" title="Domains denylist" />);
    expect(await screen.findByRole("heading", { level: 3, name: "Synced from Watcher (read-only)" })).toBeInTheDocument();
    expect(await screen.findByText("2 synced")).toBeInTheDocument();
  });

  it("keeps the Watcher block read-only and shows its synced entries on request", async () => {
    const user = userEvent.setup();
    mockLists([{ id: "w1", value: "watched.example", created_at: "2026-03-04T10:00:00Z" }]);
    renderWithProviders(<DomainPairPanel editableSection="domains_deny" title="Domains denylist" />);

    await user.click(await screen.findByRole("button", { name: "Show list" }));
    expect(await screen.findByText("watched.example")).toBeInTheDocument();
    // Only the editable list's row offers deletion, and the block itself has no edit controls.
    expect(await screen.findAllByRole("button", { name: /^Delete / })).toHaveLength(1);
    const block = screen.getByRole("region", { name: "Synced from Watcher (read-only)" });
    expect(within(block).queryByRole("button", { name: /delete|add|import/i })).not.toBeInTheDocument();
    expect(within(block).queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("says when nothing has synced yet", async () => {
    const user = userEvent.setup();
    mockLists([], "watcher_legit_domains");
    renderWithProviders(<DomainPairPanel editableSection="domains_allow" title="Domains allowlist" />);
    await user.click(await screen.findByRole("button", { name: "Show list" }));
    expect(await screen.findByText("No synced entries yet.")).toBeInTheDocument();
  });
});
