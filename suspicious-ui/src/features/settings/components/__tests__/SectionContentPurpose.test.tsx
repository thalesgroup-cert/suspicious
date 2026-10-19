import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";

vi.mock("@/features/settings/api", async (orig) => ({
  ...(await orig<typeof import("@/features/settings/api")>()),
  listItems: vi.fn().mockResolvedValue([]),
}));

import { SECTIONS, SectionContent } from "../sections";

const PURPOSES: Record<string, string> = {
  domains_allow: "URLs on these domains are treated as safe and skip analysis.",
  domains_deny: "A domain on this list is marked dangerous when it appears in a submitted email.",
  emails_files_allow: "Files with these hashes are treated as safe and skip analysis.",
  filetypes_allow: "Files of these types are treated as safe and skip analysis.",
};

describe("list purpose sentence", () => {
  beforeEach(() => vi.clearAllMocks());

  // The backend also unions campaign domains into the deny-listed set, so no sentence is the honest one.
  it("states no purpose for the campaign domains list", async () => {
    const section = SECTIONS.find((s) => s.key === "campaign_domains_allow")!;
    renderWithProviders(<SectionContent section={section} />);
    expect(await screen.findByText("No entries yet. Paste values above or import a file.")).toBeInTheDocument();
    expect(screen.queryByText(/campaign detection/i)).not.toBeInTheDocument();
  });

  for (const [key, sentence] of Object.entries(PURPOSES)) {
    it(`renders the documented sentence for ${key}`, async () => {
      const section = SECTIONS.find((s) => s.key === key)!;
      renderWithProviders(<SectionContent section={section} />);
      expect(await screen.findByText(sentence)).toBeInTheDocument();
      // The page already renders the h2; the panel must not add a second one.
      expect(screen.queryAllByRole("heading", { level: 2 })).toHaveLength(0);
    });
  }
});
