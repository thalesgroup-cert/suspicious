import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import {
  fixtureMe,
  fixtureCampaignSummary,
  fixtureClassificationCounts,
  fixtureMailVolume,
  fixtureNeighbours,
  fixturePca,
} from "@/test/fixtures";
import pageSource from "../CampaignsPage.tsx?raw";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/features/campaigns/api", () => ({
  getCampaignSummary: vi.fn(),
  getClassificationCounts: vi.fn(),
  getMailVolume: vi.fn(),
  getNeighbours: vi.fn(),
  getPca: vi.fn(),
}));

import { getMe } from "@/api/auth";
import {
  getCampaignSummary,
  getClassificationCounts,
  getMailVolume,
  getNeighbours,
  getPca,
} from "@/features/campaigns/api";
import CampaignsPage from "../CampaignsPage";

// Tests run in a real browser whose default viewport is narrow: pin the breakpoint explicitly.
const stub = (phone: boolean) =>
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: phone ? query.includes("max-width") : query.includes("min-width"),
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    onchange: null,
    dispatchEvent: () => false,
  }));

const T = { timeout: 5000 };
const region = (name: string) => screen.findByRole("region", { name }, T);

describe("CampaignsPage", () => {
  beforeEach(() => {
    stub(false);
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(getCampaignSummary).mockReset().mockResolvedValue(fixtureCampaignSummary);
    vi.mocked(getClassificationCounts).mockResolvedValue(fixtureClassificationCounts);
    vi.mocked(getMailVolume).mockReset().mockResolvedValue(fixtureMailVolume);
    vi.mocked(getNeighbours).mockReset().mockResolvedValue(fixtureNeighbours);
    vi.mocked(getPca).mockReset().mockResolvedValue(fixturePca);
  });

  afterEach(() => vi.unstubAllGlobals());

  describe("header", () => {
    it("has the title and subtitle, and no decorative Live chip", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(await screen.findByRole("heading", { level: 1, name: "Campaigns" }, T)).toBeInTheDocument();
      expect(screen.getByText("Organisation-wide, from the message store.")).toBeInTheDocument();
      expect(screen.getByText(/messages sharing the same source references \(inferred\)/)).toBeInTheDocument();
      expect(screen.queryByText("Live")).not.toBeInTheDocument();
    });

    it("asks for 15 days by default and refetches with the chosen period", async () => {
      const user = userEvent.setup();
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      await waitFor(() => expect(getCampaignSummary).toHaveBeenCalledWith(15));
      expect(getMailVolume).toHaveBeenCalledWith(15);

      await user.click(await screen.findByRole("combobox", { name: "Period" }, T));
      await user.click(await screen.findByRole("option", { name: "Last 30 days" }));
      await waitFor(() => expect(getCampaignSummary).toHaveBeenCalledWith(30));
      expect(getMailVolume).toHaveBeenCalledWith(30);
    });

    it("has no react-grid-layout on the page", () => {
      expect(pageSource).not.toMatch(/react-grid-layout|react-resizable/);
    });
  });

  describe("indicators", () => {
    it("shows messages with the delta to the previous period and the unclassified note", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      const card = await region("Messages");
      expect(within(card).getByText("34")).toBeInTheDocument();
      expect(within(card).getByText("vs previous 15 days: +14 (+70%) from 20")).toBeInTheDocument();
      expect(within(card).getByText("2 without a classification")).toBeInTheDocument();
    });

    it("says no data when the previous period is empty, and — for a null share", async () => {
      vi.mocked(getCampaignSummary).mockResolvedValue({
        ...fixtureCampaignSummary,
        previous_messages: 0,
        previous_dangerous: 0,
        previous_dangerous_share: null,
      });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(within(await region("Messages")).getByText("vs previous 15 days: no data")).toBeInTheDocument();
      expect(within(await region("Dangerous share")).getByText("vs previous 15 days: no data")).toBeInTheDocument();
    });

    it("shows the dangerous share delta in points", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      const card = await region("Dangerous share");
      // 4/34 = 12%, 1/20 = 5%
      expect(within(card).getByText("12%")).toBeInTheDocument();
      expect(within(card).getByText("vs previous 15 days: +7 points from 5%")).toBeInTheDocument();
    });

    it("shows active campaigns of N, the largest campaign and the peak day", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      const active = await region("Active campaigns");
      expect(within(active).getByText("of 2 in this period")).toBeInTheDocument();
      expect(within(active).getByText("active = seen in the last 48 hours")).toBeInTheDocument();
      const largest = await region("Largest campaign");
      expect(within(largest).getByText("12")).toBeInTheDocument();
      expect(within(largest).getByText(fixtureCampaignSummary.largest_campaign!.name)).toBeInTheDocument();
      const peak = await region("Peak day");
      expect(within(peak).getByText("15")).toBeInTheDocument();
      expect(within(peak).getByText("12 Oct")).toBeInTheDocument();
    });

    it("shows — for a null share and no peak day", async () => {
      vi.mocked(getCampaignSummary).mockResolvedValue({
        ...fixtureCampaignSummary,
        dangerous_share: null,
        peak_day: null,
      });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(within(await region("Dangerous share")).getByText("—")).toBeInTheDocument();
      expect(within(await region("Peak day")).getByText("—")).toBeInTheDocument();
    });
  });

  describe("states", () => {
    it("keeps the other panels when one query fails, with a plain error and Retry", async () => {
      const user = userEvent.setup();
      vi.mocked(getNeighbours).mockRejectedValueOnce(new Error("boom"));
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });

      const side = await region("Messages to review");
      expect(await within(side).findByText("Could not load the review lists.", {}, T)).toBeInTheDocument();
      expect(screen.queryByText(/API routes/i)).not.toBeInTheDocument();
      expect(await region("Messages")).toBeInTheDocument();
      expect(await region("Campaigns in this period")).toBeInTheDocument();

      await user.click(within(side).getByRole("button", { name: "Retry" }));
      expect(await within(side).findByText("Reset your password", {}, T)).toBeInTheDocument();
    });

    it("shows the empty state instead of zero-filled panels when the period has no messages", async () => {
      vi.mocked(getCampaignSummary).mockResolvedValue({
        ...fixtureCampaignSummary,
        messages: 0,
        dangerous: 0,
        dangerous_share: null,
        peak_day: null,
        mix: { SAFE: 0, UNWANTED: 0, SUSPICIOUS: 0, DANGEROUS: 0 },
        unclassified: 0,
        campaigns: [],
        active_campaigns: 0,
        largest_campaign: null,
      });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(await screen.findByText("No messages in this period.", {}, T)).toBeInTheDocument();
      expect(screen.queryByRole("region", { name: "Messages" })).not.toBeInTheDocument();
      expect(screen.queryByRole("region", { name: "Messages per day" })).not.toBeInTheDocument();
    });
  });

  describe("campaigns and map", () => {
    it("Show in map selects the campaign's cases in the map", async () => {
      const user = userEvent.setup();
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      const table = await region("Campaigns in this period");
      const row = (await within(table).findByText(fixtureCampaignSummary.campaigns[0].name, {}, T)).closest("tr")!;
      await user.click(within(row as HTMLElement).getByRole("button", { name: "Show in map" }));
      expect(within(await region("Embedding map")).getByText("2 selected")).toBeInTheDocument();
    });

    it("shows the variance caption on the map", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(await screen.findByText(/Components explain 48% of the variance\./, {}, T)).toBeInTheDocument();
    });
  });
});
