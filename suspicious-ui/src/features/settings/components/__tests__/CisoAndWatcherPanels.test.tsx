import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";

vi.mock("@/features/settings/api", () => ({
  listItems: vi.fn(),
  addItems: vi.fn(),
  removeItem: vi.fn(),
  addFromFile: vi.fn(),
}));

import { listItems } from "@/features/settings/api";
import { CisoUsersPanel } from "@/features/settings/components/CisoUsersPanel";
import { DomainPairPanel } from "@/features/settings/components/ReadOnlyListPanel";

describe("CisoUsersPanel", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders each user name as an h3 so it nests under the panel h2", async () => {
    vi.mocked(listItems).mockResolvedValue([
      { id: "1", username: "adaeze", email: "a@x.io", scope: "EMEA" },
    ] as never);
    renderWithProviders(
      <>
        <h2>CISO users</h2>
        <CisoUsersPanel />
      </>
    );
    expect(await screen.findByRole("heading", { level: 3, name: "adaeze" })).toBeInTheDocument();
  });

  it("uses the shared empty state when there are no users", async () => {
    vi.mocked(listItems).mockResolvedValue([]);
    renderWithProviders(<CisoUsersPanel />);
    expect(await screen.findByText("No CISO users.")).toBeInTheDocument();
  });
});

describe("DomainPairPanel", () => {
  beforeEach(() => vi.clearAllMocks());

  it("keeps the Watcher panel read-only and shows its synced entries on request", async () => {
    const user = userEvent.setup();
    vi.mocked(listItems).mockImplementation(async (section: string) =>
      section === "watcher_monitored_domains"
        ? [{ id: "w1", value: "watched.example" }]
        : [{ id: "1", value: "evil.com" }]
    );
    renderWithProviders(<DomainPairPanel editableSection="domains_deny" title="Domains denylist" />);

    expect(await screen.findByText("Watcher monitored domains")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show list" }));
    expect(await screen.findByText("watched.example")).toBeInTheDocument();
    // Only the editable list's row offers deletion.
    expect(await screen.findAllByRole("button", { name: "Delete" })).toHaveLength(1);
  });
});
