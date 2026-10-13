import { describe, it, expect, vi, afterEach } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { fixtureCampaignSummary, fixtureMailVolume, fixtureNeighbours } from "@/test/fixtures";
import type { PcaPoint } from "@/features/campaigns/api";
import VolumeChart from "../components/VolumeChart";
import MixBar from "../components/MixBar";
import CampaignTable from "../components/CampaignTable";
import SidePanel from "../components/SidePanel";
import PointTable from "../components/PointTable";

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

afterEach(() => vi.unstubAllGlobals());

describe("VolumeChart", () => {
  it("names both areas in a legend, summarises in its label and toggles a table", async () => {
    stub(false);
    const user = userEvent.setup();
    renderWithProviders(<VolumeChart volume={fixtureMailVolume} campaigns={fixtureCampaignSummary.campaigns} />);
    const legend = screen.getByRole("list", { name: "Legend" });
    expect(within(legend).getByText("Other")).toBeInTheDocument();
    expect(within(legend).getByText("Dangerous")).toBeInTheDocument();
    // 34 messages (30 other + 4 dangerous), peak 15 on 12 Oct
    expect(
      screen.getByRole("img", { name: "Messages per day: 34 messages, 4 dangerous, peak 12 Oct" })
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "View as table" }));
    const table = screen.getByRole("table", { name: "Messages per day" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(4);
    expect(within(rows[2]).getAllByRole("cell").map((c) => c.textContent)).toEqual(["12 Oct", "12", "3"]);
    expect(screen.queryByRole("img", { name: /Messages per day/ })).not.toBeInTheDocument();
  });

  it("says when campaign windows are shaded", () => {
    stub(false);
    renderWithProviders(<VolumeChart volume={fixtureMailVolume} campaigns={fixtureCampaignSummary.campaigns} />);
    expect(screen.getByText(/Shaded bands: first to last day seen for 1 campaign/)).toBeInTheDocument();
  });
});

describe("MixBar", () => {
  it("lists the four classes with counts and percentages of the classified total, and the unclassified line", () => {
    renderWithProviders(<MixBar mix={fixtureCampaignSummary.mix} unclassified={2} />);
    const rows = screen.getAllByRole("listitem").map((li) => li.textContent);
    // 20, 6, 2, 4 of 32: largest remainder keeps the sum at 100
    expect(rows).toEqual(["Safe2063%", "Unwanted619%", "Suspicious26%", "Dangerous412%"]);
    expect(screen.getByText("Unclassified: 2 (not in the percentages)")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Safe 20, Unwanted 6, Suspicious 2, Dangerous 4/ })).toBeInTheDocument();
  });

  it("hides the unclassified line at zero", () => {
    renderWithProviders(<MixBar mix={fixtureCampaignSummary.mix} unclassified={0} />);
    expect(screen.queryByText(/Unclassified/)).not.toBeInTheDocument();
  });
});

describe("CampaignTable", () => {
  const [first, second] = fixtureCampaignSummary.campaigns;

  it("sorts by last seen descending by default and re-sorts with aria-sort", async () => {
    stub(false);
    const user = userEvent.setup();
    renderWithProviders(<CampaignTable campaigns={[second, first]} onSelectCases={() => {}} />);
    const header = (name: RegExp) => screen.getByRole("columnheader", { name });
    expect(header(/Last seen/)).toHaveAttribute("aria-sort", "descending");
    const names = () => screen.getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell")[0].textContent);
    expect(names()).toEqual([first.name, second.name]);

    await user.click(within(header(/Messages/)).getByRole("button"));
    expect(header(/Messages/)).toHaveAttribute("aria-sort", "descending");
    expect(header(/Last seen/)).not.toHaveAttribute("aria-sort");
    await user.click(within(header(/Messages/)).getByRole("button"));
    expect(header(/Messages/)).toHaveAttribute("aria-sort", "ascending");
    expect(names()).toEqual([second.name, first.name]);
  });

  it("shows full names, status text, sample subject, the case link and Show in map", async () => {
    stub(false);
    const user = userEvent.setup();
    const onSelect = vi.fn();
    renderWithProviders(<CampaignTable campaigns={[first, second]} onSelectCases={onSelect} />);
    const row = screen.getByText(first.name).closest("tr")!;
    expect(within(row).getByText("Active")).toBeInTheDocument();
    expect(within(row).getByText("Your invoice is overdue")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: "Open latest case" })).toHaveAttribute("href", "/investigation?open=41");
    await user.click(within(row).getByRole("button", { name: "Show in map" }));
    expect(onSelect).toHaveBeenCalledWith(["41", "40"]);

    const ended = screen.getByText(second.name).closest("tr")!;
    expect(within(ended).getByText("Ended")).toBeInTheDocument();
    expect(within(ended).queryByRole("link")).not.toBeInTheDocument();
    expect(within(ended).getByRole("button", { name: "Show in map" })).toBeDisabled();
    expect(screen.getByText(/Campaigns are inferred from shared source references/)).toBeInTheDocument();
  });

  it("renders a card list on a phone, without a table", () => {
    stub(true);
    renderWithProviders(<CampaignTable campaigns={[first, second]} onSelectCases={() => {}} />);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    const cards = screen.getAllByRole("listitem");
    expect(cards).toHaveLength(2);
    expect(within(cards[0]).getByText(first.name)).toBeInTheDocument();
    expect(within(cards[0]).getByRole("button", { name: "Show in map" })).toBeInTheDocument();
  });
});

describe("SidePanel", () => {
  it("shows similarity for near-known-bad rows and selects the case on click", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    renderWithProviders(<SidePanel neighbours={fixtureNeighbours} onSelectCases={onSelect} />);
    expect(screen.getByText("Closeness in the embedding space is a hint, not proof of a campaign.")).toBeInTheDocument();
    expect(screen.getByText(/similarity 0\.62 to the nearest dangerous mail/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Case 17" })).toHaveAttribute("href", "/investigation?open=17");
    await user.click(screen.getByRole("button", { name: /Reset your password/ }));
    expect(onSelect).toHaveBeenCalledWith(["17"]);
  });

  it("says when a list is empty", () => {
    renderWithProviders(
      <SidePanel neighbours={{ ...fixtureNeighbours, near_known_bad: [], novel: [] }} onSelectCases={() => {}} />
    );
    expect(screen.getAllByText("Nothing to review in this sample.")).toHaveLength(2);
  });
});

describe("PointTable", () => {
  const pts: PcaPoint[] = Array.from({ length: 250 }, (_, i) => ({
    x: i, y: -i, z: 0, label: i % 2 ? "SAFE" : "DANGEROUS",
    suspicious_case_id: String(i), mail_subject: `Mail ${String(i).padStart(3, "0")}`, sourceRefs: [], date: null,
  }));

  it("caps the rows at 200, sorts with aria-sort and links the case", async () => {
    const user = userEvent.setup();
    renderWithProviders(<PointTable points={pts} />);
    expect(screen.getByText("Showing 200 of 250")).toBeInTheDocument();
    expect(screen.getAllByRole("row")).toHaveLength(201);

    const pc1 = screen.getByRole("columnheader", { name: /PC1/ });
    await user.click(within(pc1).getByRole("button"));
    expect(pc1).toHaveAttribute("aria-sort", "ascending");
    await user.click(within(pc1).getByRole("button"));
    expect(pc1).toHaveAttribute("aria-sort", "descending");
    const firstRow = screen.getAllByRole("row")[1];
    expect(within(firstRow).getByRole("link", { name: "249" })).toHaveAttribute("href", "/investigation?open=249");
  });
});
