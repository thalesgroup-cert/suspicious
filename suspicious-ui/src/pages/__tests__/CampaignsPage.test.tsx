import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { stubMatchMedia } from "@/test/matchMedia";
import {
  fixtureMe,
  fixtureCampaignSummary,
  fixtureMailVolume,
  fixtureNeighbours,
  fixturePca,
} from "@/test/fixtures";
import pageSource from "../CampaignsPage.tsx?raw";
import { detectWebGL } from "@/features/campaigns/mapSupport";
import EmbeddingMap3D from "@/features/campaigns/components/EmbeddingMap3D";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/features/campaigns/api", () => ({
  getCampaignSummary: vi.fn(),
  getMailVolume: vi.fn(),
  getNeighbours: vi.fn(),
  getPca: vi.fn(),
}));

// The page is tested against a stub 3D map: what it passes in is what matters here (embeddingMap3d.test.tsx
// covers the map itself, the real renderer is in embeddingMap3d.gl.test.tsx).
vi.mock("@/features/campaigns/mapSupport", async (original) => ({
  ...(await original<typeof import("@/features/campaigns/mapSupport")>()),
  detectWebGL: vi.fn(),
}));
vi.mock("@/features/campaigns/components/EmbeddingMap3D", () => ({ default: vi.fn() }));

import { getMe } from "@/api/auth";
import {
  getCampaignSummary,
  getMailVolume,
  getNeighbours,
  getPca,
} from "@/features/campaigns/api";
import CampaignsPage from "../CampaignsPage";

const T = { timeout: 5000 };
const region = (name: string) => screen.findByRole("region", { name }, T);

describe("CampaignsPage", () => {
  beforeEach(() => {
    stubMatchMedia();
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(getCampaignSummary).mockReset().mockResolvedValue(fixtureCampaignSummary);
    vi.mocked(getMailVolume).mockReset().mockResolvedValue(fixtureMailVolume);
    vi.mocked(getNeighbours).mockReset().mockResolvedValue(fixtureNeighbours);
    vi.mocked(getPca).mockReset().mockResolvedValue(fixturePca);
    vi.mocked(detectWebGL).mockReturnValue(true);
    vi.mocked(EmbeddingMap3D)
      .mockReset()
      .mockImplementation((() => <div data-testid="map3d" />) as never);
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
      expect(within(largest).getByText("messages")).toBeInTheDocument();
      expect(within(largest).getByText(fixtureCampaignSummary.largest_campaign!.name)).toBeInTheDocument();
      const peak = await region("Peak day");
      expect(within(peak).getByText("15")).toBeInTheDocument();
      expect(within(peak).getByText("12 Oct")).toBeInTheDocument();
    });

    it("says how many campaigns the period has from the count before the backend's cut, not from the list it got", async () => {
      vi.mocked(getCampaignSummary).mockResolvedValue({ ...fixtureCampaignSummary, campaigns_total: 412, active_campaigns: 3 });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(within(await region("Active campaigns")).getByText("of 412 in this period")).toBeInTheDocument();
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

  describe("a selection when the review lists are not available", () => {
    const sample = () => [
      { ...fixturePca.points[0], suspicious_case_id: "17", mail_subject: "Reset your password" },
      { ...fixturePca.points[1], mail_subject: "URGENT" },
    ];
    const pick = async (id: string) => {
      await screen.findByTestId("map3d", {}, T);
      act(() => vi.mocked(EmbeddingMap3D).mock.calls.at(-1)![0].onSelectCases([id]));
    };

    it.each([
      ["the request failed", () => vi.mocked(getNeighbours).mockRejectedValue(new Error("boom"))],
      ["the request is still pending", () => vi.mocked(getNeighbours).mockReturnValue(new Promise(() => {}))],
    ])("still shows the selected message and its case link when %s", async (_n, arrange) => {
      arrange();
      vi.mocked(getPca).mockResolvedValue({ ...fixturePca, points: sample() });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      await pick("17");
      const side = await region("Review lists");
      const selected = await within(side).findByRole("region", { name: "Selected message" }, T);
      expect(within(selected).getByRole("link", { name: "Case 17" })).toHaveAttribute("href", "/investigation?open=17");
      expect(within(side).getByRole("heading", { name: "Nearest in this 3D view" })).toBeInTheDocument();
      // the lists themselves are what is missing, and say so
      expect(within(side).queryByRole("heading", { name: "Near known bad" })).not.toBeInTheDocument();
    });
  });

  describe("changing the period", () => {
    it("words the empty state with the period of the data on screen while a new one loads", async () => {
      const user = userEvent.setup();
      vi.mocked(getCampaignSummary).mockResolvedValueOnce({ ...fixtureCampaignSummary, messages: 0, campaigns: [], campaigns_total: 0, active_campaigns: 0, largest_campaign: null, peak_day: null, dangerous_share: null });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(await screen.findByText("The message store has no mail dated in the last 15 days.", {}, T)).toBeInTheDocument();

      vi.mocked(getCampaignSummary).mockReturnValueOnce(new Promise(() => {}));
      await user.click(await screen.findByRole("combobox", { name: "Period" }, T));
      await user.click(await screen.findByRole("option", { name: "Last 30 days" }));
      expect(await screen.findByRole("progressbar", { name: "Loading the last 30 days" }, T)).toBeInTheDocument();
      // still the 15-day data, so still the 15-day wording
      expect(screen.getByText("The message store has no mail dated in the last 15 days.")).toBeInTheDocument();
      expect(screen.queryByText(/last 30 days\./)).not.toBeInTheDocument();
    });

    it("keeps the previous numbers on screen and says it is loading the new period", async () => {
      const user = userEvent.setup();
      let resolve!: (v: typeof fixtureCampaignSummary) => void;
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(await within(await region("Messages")).findByText("34", {}, T)).toBeInTheDocument();
      expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
      expect(document.querySelector('[aria-busy="true"]')).toBeNull();

      vi.mocked(getCampaignSummary).mockReturnValueOnce(new Promise((r) => (resolve = r)));
      await user.click(await screen.findByRole("combobox", { name: "Period" }, T));
      await user.click(await screen.findByRole("option", { name: "Last 30 days" }));

      expect(await screen.findByRole("progressbar", { name: "Loading the last 30 days" }, T)).toBeInTheDocument();
      expect(document.querySelector('[aria-busy="true"]')).not.toBeNull();
      // The 15-day numbers stay until the 30-day ones arrive.
      expect(within(screen.getByRole("region", { name: "Messages" })).getByText("34")).toBeInTheDocument();

      resolve({ ...fixtureCampaignSummary, days: 30, messages: 80 });
      expect(await within(await region("Messages")).findByText("80", {}, T)).toBeInTheDocument();
      await waitFor(() => expect(screen.queryByRole("progressbar")).not.toBeInTheDocument());
      expect(document.querySelector('[aria-busy="true"]')).toBeNull();
    });
  });

  describe("campaigns and map", () => {
    it("Show in map selects the campaign's cases in the map and says how many the sample holds", async () => {
      const user = userEvent.setup();
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      const table = await region("Campaigns in this period");
      const row = (await within(table).findByText(fixtureCampaignSummary.campaigns[0].name, {}, T)).closest("tr")!;
      await user.click(within(row as HTMLElement).getByRole("button", { name: "Show in map" }));
      const map = await region("Embedding map");
      expect(within(map).getByText("2 selected")).toBeInTheDocument();
      // The sample holds cases 1 and 2; the campaign's are 41 and 40.
      expect(within(map).getByText("0 in the map sample")).toBeInTheDocument();
    });

    it("draws Show in map as disabled for a campaign with no case ids, not in the accent the page gives the others", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      const table = await region("Campaigns in this period");
      const buttons = await within(table).findAllByRole("button", { name: "Show in map" }, T);
      const off = buttons.find((b) => (b as HTMLButtonElement).disabled)!;
      const on = buttons.find((b) => !(b as HTMLButtonElement).disabled)!;
      expect(off).toBeDefined();
      expect(getComputedStyle(off).color).not.toBe(getComputedStyle(on).color);
      expect(getComputedStyle(off).borderColor).not.toBe(getComputedStyle(on).borderColor);
    });

    it.each([
      [false, "smooth"],
      [true, "auto"],
    ])("scrolls the map into view (reduced motion: %s -> %s)", async (reducedMotion, behavior) => {
      stubMatchMedia({ reducedMotion });
      const scroll = vi.spyOn(Element.prototype, "scrollIntoView").mockImplementation(() => {});
      const user = userEvent.setup();
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      const table = await region("Campaigns in this period");
      const row = (await within(table).findByText(fixtureCampaignSummary.campaigns[0].name, {}, T)).closest("tr")!;
      await user.click(within(row as HTMLElement).getByRole("button", { name: "Show in map" }));
      expect(scroll).toHaveBeenCalledWith({ behavior, block: "start" });
      scroll.mockRestore();
    });

    it("explains the variance of the three plotted components and what the sample is", async () => {
      vi.mocked(getPca).mockResolvedValue({ ...fixturePca, explained_variance: [0.25, 0.1, 0.05] });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(
        await screen.findByText(
          `PC1 25% + PC2 10% + PC3 5% of the variance. Sample of up to ${(1500).toLocaleString()} messages from the whole store, not limited to the selected period. Closeness is not proof of a campaign.`,
          {},
          T
        )
      ).toBeInTheDocument();
      expect(await screen.findByTestId("map3d", {}, T)).toBeInTheDocument();
    });

    it("explains the two plotted components when it has to draw the 2D map", async () => {
      vi.mocked(detectWebGL).mockReturnValue(false);
      vi.mocked(getPca).mockResolvedValue({ ...fixturePca, explained_variance: [0.25, 0.1, 0.05] });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(
        await screen.findByText(
          `PC1 25% + PC2 10% of the variance (PC3 not shown). Sample of up to ${(1500).toLocaleString()} messages from the whole store, not limited to the selected period. Closeness is not proof of a campaign.`,
          {},
          T
        )
      ).toBeInTheDocument();
      expect(screen.getByText("3D view unavailable, showing the 2D map.")).toBeInTheDocument();
    });

    it("does not mention PC3 when the backend sent two components", async () => {
      vi.mocked(getPca).mockResolvedValue({ ...fixturePca, explained_variance: [0.3, 0.2] });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(await screen.findByText(/^PC1 30% \+ PC2 20% of the variance\. Sample of up to/, {}, T)).toBeInTheDocument();
      expect(screen.queryByText(/PC3/)).not.toBeInTheDocument();
    });

    it("gives the 3D map the points, the period's campaigns and the selection", async () => {
      const user = userEvent.setup();
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      await screen.findByTestId("map3d", {}, T);
      const first = vi.mocked(EmbeddingMap3D).mock.calls.at(-1)![0];
      expect(first.points).toEqual(fixturePca.points);
      expect(first.campaigns).toEqual(fixtureCampaignSummary.campaigns);
      expect(first.selectedCaseIds).toEqual([]);

      const table = await region("Campaigns in this period");
      const row = (await within(table).findByText(fixtureCampaignSummary.campaigns[0].name, {}, T)).closest("tr")!;
      await user.click(within(row as HTMLElement).getByRole("button", { name: "Show in map" }));
      await waitFor(() => expect(vi.mocked(EmbeddingMap3D).mock.calls.at(-1)![0].selectedCaseIds).toEqual(["41", "40"]));
    });

    it("shows the selected message and its nearest neighbours in the review panel when a list row is chosen", async () => {
      const user = userEvent.setup();
      const sample = [
        { ...fixturePca.points[0], suspicious_case_id: "17", mail_subject: "Reset your password" },
        { ...fixturePca.points[1], mail_subject: "URGENT" },
      ];
      vi.mocked(getPca).mockResolvedValue({ ...fixturePca, points: sample });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      const side = await region("Review lists");
      expect(within(side).queryByRole("region", { name: "Selected message" })).not.toBeInTheDocument();
      await user.click(await within(side).findByRole("button", { name: /Reset your password/ }, T));
      const selected = await within(side).findByRole("region", { name: "Selected message" }, T);
      expect(within(selected).getByRole("link", { name: "Case 17" })).toHaveAttribute("href", "/investigation?open=17");
      expect(within(side).getByRole("heading", { name: "Nearest in this 3D view" })).toBeInTheDocument();
      expect(within(side).getByRole("list", { name: "Nearest messages" })).toHaveTextContent("URGENT");
    });

    it("keeps the review lists in a named, focusable region", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(await screen.findByRole("region", { name: "Review lists" }, T)).toHaveAttribute("tabindex", "0");
    });
  });
});
