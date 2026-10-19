import { describe, it, expect, vi, afterEach } from "vitest";
import { useClassColors } from "@/features/campaigns/utils";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { stubMatchMedia } from "@/test/matchMedia";
import { fixtureCampaignSummary, fixtureMailVolume, fixtureNeighbours } from "@/test/fixtures";
import type { CampaignRow, PcaPoint } from "@/features/campaigns/api";
import VolumeChart from "../components/VolumeChart";
import MixBar from "../components/MixBar";
import CampaignTable from "../components/CampaignTable";
import SidePanel from "../components/SidePanel";
import PointTable from "../components/PointTable";

const stub = (phone: boolean) => stubMatchMedia({ phone });

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

    const toggle = screen.getByRole("button", { name: "Table view" });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    await user.click(toggle);
    expect(screen.getByRole("button", { name: "Table view" })).toHaveAttribute("aria-pressed", "true");
    const table = screen.getByRole("table", { name: "Messages per day" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(4);
    expect(within(rows[2]).getAllByRole("cell").map((c) => c.textContent)).toEqual(["12 Oct", "12", "3"]);
    expect(screen.queryByRole("img", { name: /Messages per day/ })).not.toBeInTheDocument();
  });

  it("reads a campaign's days in UTC, not from the text of an offset timestamp", () => {
    stub(false);
    // 00:30 and 01:30 at +02:00 are 22:30 and 23:30 UTC on the 11th.
    const offset: CampaignRow = {
      ...fixtureCampaignSummary.campaigns[0],
      first_seen: "2026-10-12T00:30:00+02:00",
      last_seen: "2026-10-12T01:30:00+02:00",
    };
    renderWithProviders(<VolumeChart volume={fixtureMailVolume} campaigns={[offset]} />);
    expect(screen.getByText(`${offset.name} · 11 Oct`)).toBeInTheDocument();
  });

  it("keeps two campaigns with the same truncated name apart", () => {
    stub(false);
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const [a] = fixtureCampaignSummary.campaigns;
    renderWithProviders(<VolumeChart volume={fixtureMailVolume} campaigns={[a, { ...a, first_seen: "2026-10-12T08:00:00Z" }]} />);
    expect(screen.getAllByText(new RegExp(`^${a.name}`))).toHaveLength(2);
    expect(error.mock.calls.flat().join(" ")).not.toMatch(/same key/);
    error.mockRestore();
  });

  it("says when campaign windows are shaded", () => {
    stub(false);
    renderWithProviders(<VolumeChart volume={fixtureMailVolume} campaigns={fixtureCampaignSummary.campaigns} />);
    expect(screen.getByText(/Campaign windows: first to last day seen for 1 campaign/)).toBeInTheDocument();
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

  const many = (n: number): CampaignRow[] =>
    Array.from({ length: n }, (_, i) => ({
      ...first,
      name: `campaign-${i}.example`,
      last_seen: new Date(Date.UTC(2026, 0, 1) + i * 3_600_000).toISOString(),
    }));

  it("shows the first 100 campaigns in the current order and says how many there are", () => {
    stub(false);
    renderWithProviders(<CampaignTable campaigns={many(120)} onSelectCases={() => {}} />);
    expect(screen.getByText("Showing 100 of 120 campaigns")).toBeInTheDocument();
    const rows = screen.getAllByRole("row");
    expect(rows).toHaveLength(101);
    // Last seen descending: the newest 100 of the 120, not the first 100 received.
    expect(within(rows[1]).getAllByRole("cell")[0]).toHaveTextContent("campaign-119.example");
    expect(within(rows[100]).getAllByRole("cell")[0]).toHaveTextContent("campaign-20.example");
  });

  it("caps the phone cards at 100 too, and says nothing when there are fewer", () => {
    stub(true);
    const { unmount } = renderWithProviders(<CampaignTable campaigns={many(120)} onSelectCases={() => {}} />);
    expect(screen.getByText("Showing 100 of 120 campaigns")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(100);
    unmount();
    renderWithProviders(<CampaignTable campaigns={many(3)} onSelectCases={() => {}} />);
    expect(screen.queryByText(/Showing/)).not.toBeInTheDocument();
  });

  it.each([false, true])("keeps two campaigns with the same truncated name apart (phone: %s)", (phone) => {
    stub(phone);
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const twin = { ...first, first_seen: "2026-10-05T08:00:00Z" };
    renderWithProviders(<CampaignTable campaigns={[first, twin]} onSelectCases={() => {}} />);
    expect(screen.getAllByText(first.name)).toHaveLength(2);
    expect(error.mock.calls.flat().join(" ")).not.toMatch(/same key/);
    error.mockRestore();
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

  it("draws a label in the same colour as the map and the mix, not the verdict chip's", () => {
    function Probe() {
      return <output data-testid="unwanted">{useClassColors().UNWANTED}</output>;
    }
    renderWithProviders(
      <>
        <Probe />
        <SidePanel neighbours={fixtureNeighbours} onSelectCases={() => {}} />
      </>
    );
    const rgb = (hex: string) => {
      const d = document.createElement("div");
      d.style.color = hex;
      document.body.append(d);
      const c = getComputedStyle(d).color;
      d.remove();
      return c;
    };
    // fixtureNeighbours: the novel item is UNWANTED, in the class name used everywhere else on the page.
    const chip = screen.getByText("Unwanted").closest(".MuiChip-root")!;
    expect(getComputedStyle(chip).borderColor).toBe(rgb(screen.getByTestId("unwanted").textContent!));
    expect(screen.queryByText("UNWANTED")).not.toBeInTheDocument();
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
