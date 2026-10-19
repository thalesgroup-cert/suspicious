import { describe, it, expect, vi, afterEach } from "vitest";
import { useClassColors } from "@/features/campaigns/utils";
import { fireEvent, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { stubMatchMedia } from "@/test/matchMedia";
import { fixtureCampaignSummary, fixtureMailVolume, fixtureNeighbours } from "@/test/fixtures";
import type { CampaignRow, PcaPoint } from "@/features/campaigns/api";
import VolumeChart from "../components/VolumeChart";
import MixBar from "../components/MixBar";
import CampaignTable from "../components/CampaignTable";
import SidePanel, { SelectedPanel } from "../components/SidePanel";
import PointTable from "../components/PointTable";
import { ThemeProvider } from "@mui/material/styles";
import { themes } from "@/styles/themes";
import { contrastRatio, flatten } from "@/shared/lib/contrast";

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

describe("PointTable: selecting a message", () => {
  const row = (id: string | null, subject: string | null): PcaPoint => ({ x: 1, y: 2, z: 3, label: "SAFE", suspicious_case_id: id, mail_subject: subject, sourceRefs: [], date: null });
  const rows = [row("7", "Bonjour"), row(null, "Orphan"), row("9", null)];

  it("has a Select button on every row that selects that case", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    renderWithProviders(<PointTable points={rows} selectedCaseIds={[]} onSelectCases={onSelect} />);
    expect(screen.getByRole("columnheader", { name: "Select" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /^Select / })).toHaveLength(3);
    await user.click(screen.getByRole("button", { name: "Select Bonjour" }));
    expect(onSelect).toHaveBeenCalledExactlyOnceWith(["7"]);
    // a message with no subject is still named: by its case
    await user.click(screen.getByRole("button", { name: "Select case 9" }));
    expect(onSelect).toHaveBeenLastCalledWith(["9"]);
  });

  it("shows which rows are selected with aria-pressed, and a second press takes that case out of the selection", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    renderWithProviders(<PointTable points={rows} selectedCaseIds={["7", "9"]} onSelectCases={onSelect} />);
    expect(screen.getByRole("button", { name: "Select Bonjour" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Select case 9" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Select Orphan" })).toHaveAttribute("aria-pressed", "false");
    // the rows say so too, not only the buttons' attribute
    const rowOf = (name: string) => screen.getByRole("button", { name }).closest("tr")!;
    expect(rowOf("Select Bonjour")).toHaveClass("Mui-selected");
    expect(rowOf("Select Orphan")).not.toHaveClass("Mui-selected");
    await user.click(screen.getByRole("button", { name: "Select Bonjour" }));
    expect(onSelect).toHaveBeenCalledExactlyOnceWith(["9"]);
  });

  it("keeps the button for a message without a case id focusable, inert, and describes why", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    renderWithProviders(<PointTable points={rows} selectedCaseIds={[]} onSelectCases={onSelect} />);
    const orphan = screen.getByRole("button", { name: "Select Orphan" });
    // aria-disabled, not disabled: a disabled button leaves the tab order, and with it the reason.
    expect(orphan).toHaveAttribute("aria-disabled", "true");
    expect(orphan).not.toBeDisabled();
    expect(orphan).toHaveAccessibleDescription("This message has no case id, so it cannot be selected.");
    orphan.focus();
    expect(orphan).toHaveFocus();
    await user.click(orphan);
    await user.keyboard("{Enter}");
    expect(onSelect).not.toHaveBeenCalled();
    // an ordinary row is not marked
    expect(screen.getByRole("button", { name: "Select Bonjour" })).not.toHaveAttribute("aria-disabled");
  });

  it.each(["light", "midnight"] as const)("draws the inert Select in a colour that reads at 4.5:1 on the card in %s, without fading it", (name) => {
    renderWithProviders(
      <ThemeProvider theme={themes[name]}>
        <PointTable points={rows} selectedCaseIds={[]} onSelectCases={() => {}} />
      </ThemeProvider>
    );
    const orphan = screen.getByRole("button", { name: "Select Orphan" });
    const paper = themes[name].palette.background.paper;
    expect(getComputedStyle(orphan).opacity).toBe("1");
    expect(contrastRatio(flatten(getComputedStyle(orphan).color, paper), paper)).toBeGreaterThanOrEqual(4.5);
  });

  it("has no Select column when nothing can be selected", () => {
    renderWithProviders(<PointTable points={rows} />);
    expect(screen.queryByRole("columnheader", { name: "Select" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Select / })).not.toBeInTheDocument();
  });
});

describe("SelectedPanel", () => {
  const at = (x: number, id: string | null, label = "SAFE", subject: string | null = `Mail ${id}`): PcaPoint => ({
    x, y: 0, z: 0, label, suspicious_case_id: id, mail_subject: subject, sourceRefs: [], date: "2026-10-05",
  });
  // The selected message is at the origin; the others sit 1, 2, ... 9 away on PC1.
  const sample = [at(0, "3", "DANGEROUS", "URGENT: pay now"), ...Array.from({ length: 9 }, (_, i) => at(i + 1, i === 0 ? null : `1${i}`))];
  const camp = (name: string, messages: number, case_ids: string[]) => ({ ...fixtureCampaignSummary.campaigns[0], name, messages, case_ids });
  const base = { points: sample, campaigns: [camp("small.example", 2, ["3"]), camp("invoice-relay.example", 9, ["3", "11"])] };
  const block = () => screen.getByRole("region", { name: "Selected message" });

  it("shows the subject, case link, class, day and campaign of the one selected message", () => {
    renderWithProviders(<SelectedPanel {...base} selectedCaseIds={["3"]} onSelectCases={() => {}} />);
    expect(within(block()).getByRole("heading", { name: "Selected message" })).toBeInTheDocument();
    expect(within(block()).getByText("URGENT: pay now")).toBeInTheDocument();
    expect(within(block()).getByRole("link", { name: "Case 3" })).toHaveAttribute("href", "/investigation?open=3");
    expect(within(block()).getByText("Dangerous")).toBeInTheDocument();
    expect(within(block()).getByText("5 Oct 2026")).toBeInTheDocument();
    // in two campaigns: the larger one
    expect(within(block()).getByText("Campaign: invoice-relay.example")).toBeInTheDocument();
    expect(within(block()).queryByText(/small\.example/)).not.toBeInTheDocument();
  });

  it("encodes the case id in the link and omits the campaign line when there is none", () => {
    const odd = [at(0, "a b/1", "SAFE", "Odd"), at(1, "2")];
    renderWithProviders(<SelectedPanel points={odd} campaigns={[]} selectedCaseIds={["a b/1"]} onSelectCases={() => {}} />);
    expect(within(block()).getByRole("link", { name: "Case a b/1" })).toHaveAttribute("href", "/investigation?open=a%20b%2F1");
    expect(within(block()).queryByText(/^Campaign:/)).not.toBeInTheDocument();
  });

  it("lists the 8 nearest in the 3-component view with their distances, nearest first, and says what the distance is", () => {
    renderWithProviders(<SelectedPanel {...base} selectedCaseIds={["3"]} onSelectCases={() => {}} />);
    const heading = screen.getByRole("heading", { name: "Nearest in this 3D view" });
    expect(heading).toBeInTheDocument();
    expect(screen.getByText("Distance in the 3-component view, not the full embedding.")).toBeInTheDocument();
    const list = screen.getByRole("list", { name: "Nearest messages" });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(8);
    expect(items[0]).toHaveTextContent("distance 1.000");
    expect(items[7]).toHaveTextContent("distance 8.000");
    // never the message itself
    expect(within(list).queryByText("URGENT: pay now")).not.toBeInTheDocument();
  });

  it("selects a neighbour on click, and cannot select one without a case id", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    renderWithProviders(<SelectedPanel {...base} selectedCaseIds={["3"]} onSelectCases={onSelect} />);
    const list = screen.getByRole("list", { name: "Nearest messages" });
    await user.click(within(list).getByRole("button", { name: /Mail 11/ }));
    expect(onSelect).toHaveBeenCalledWith(["11"]);
    // the nearest message (distance 1) has no case id
    expect(within(list).getAllByRole("button")[0]).toBeDisabled();
  });

  it.each([
    ["nothing is selected", []],
    ["several messages are selected", ["3", "11"]],
    ["the selected case is not in the sample", ["404"]],
  ])("shows no block when %s", (_n, ids) => {
    renderWithProviders(<SelectedPanel {...base} selectedCaseIds={ids} onSelectCases={() => {}} />);
    expect(screen.queryByRole("region", { name: "Selected message" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Nearest in this 3D view" })).not.toBeInTheDocument();
  });

  it("says when the sample is too small for neighbours", () => {
    renderWithProviders(<SelectedPanel {...base} points={[sample[0]]} selectedCaseIds={["3"]} onSelectCases={() => {}} />);
    expect(screen.getByText("No other message in the sample.")).toBeInTheDocument();
  });
});
