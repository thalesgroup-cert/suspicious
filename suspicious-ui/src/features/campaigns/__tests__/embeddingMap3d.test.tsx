import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { stubMatchMedia } from "@/test/matchMedia";
import { fixtureCampaignSummary } from "@/test/fixtures";
import type { CampaignRow, PcaPoint } from "@/features/campaigns/api";
import EmbeddingMap3D from "../components/EmbeddingMap3D";
import MapTooltip from "../components/MapTooltip";

// WebGL is not what these tests are about: the canvas is a stub, so the scene (which needs a GL context)
// never runs here. The real renderer is exercised in embeddingMap3d.gl.test.tsx.
vi.mock("@react-three/fiber", async (original) => ({
  ...(await original<typeof import("@react-three/fiber")>()),
  Canvas: () => <div data-testid="gl-canvas" />,
}));

const pt = (id: string | null, label: string, date: string | null, subject: string | null = `Mail ${id}`, x = Number(id) || 0): PcaPoint => ({
  x, y: x / 2, z: -x / 3, label, suspicious_case_id: id, mail_subject: subject, sourceRefs: [], date,
});
const points = [
  pt("1", "SAFE", "2026-10-01"),
  pt("2", "SAFE", "2026-10-03"),
  pt("3", "DANGEROUS", "2026-10-05", "URGENT: pay now"),
  pt("4", "DANGEROUS", "2026-10-09"),
  pt("5", "UNWANTED", null),
];
const row = (over: Partial<CampaignRow>): CampaignRow => ({ ...fixtureCampaignSummary.campaigns[0], ...over });
const campaigns = [
  row({ name: "invoice-relay.example, cdn-pay.example, login-portal.example", messages: 12, case_ids: ["3", "4"] }),
  row({ name: "newsletter.example", messages: 5, case_ids: ["1"] }),
];

function renderMap(props: Partial<React.ComponentProps<typeof EmbeddingMap3D>> = {}) {
  const onSelectCases = vi.fn();
  const view = renderWithProviders(
    <EmbeddingMap3D points={points} explainedVariance={[0.24, 0.15, 0.09]} campaigns={campaigns} selectedCaseIds={[]} onSelectCases={onSelectCases} {...props} />
  );
  return { onSelectCases, ...view };
}
const group = () => screen.getByRole("group", { name: "3D embedding map" });
const chip = (name: RegExp) => screen.getByRole("button", { name });
const shown = (text: string) => expect(screen.getByText(text)).toBeInTheDocument();

beforeEach(() => stubMatchMedia());
afterEach(() => vi.unstubAllGlobals());

describe("EmbeddingMap3D: accessible wrapper", () => {
  it("is a named, described, focusable group around the canvas", () => {
    renderMap();
    const g = group();
    expect(g).toHaveAttribute("tabindex", "0");
    expect(within(g).getByTestId("gl-canvas")).toBeInTheDocument();
    const description = document.getElementById(g.getAttribute("aria-describedby")!)!;
    expect(description).toHaveTextContent("5 messages: Safe 2, Unwanted 1, Dangerous 2. Rotate with the arrow keys, zoom with + and -, reset with 0.");
    // visible text, not hidden from sighted keyboard users
    expect(description).toBeVisible();
  });

  it("has a Skip map link before the group that moves focus past it", async () => {
    const user = userEvent.setup();
    renderMap();
    const skip = screen.getByRole("link", { name: "Skip map" });
    expect(skip.compareDocumentPosition(group()) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await user.click(skip);
    const target = document.activeElement as HTMLElement;
    expect(target).toHaveAccessibleName("Map key");
    expect(group().compareDocumentPosition(target) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("puts the canvas inside a margin the page can still be scrolled from on touch", () => {
    renderMap();
    // The canvas is the only element that stops the browser scrolling; the group around it pads it by at least 24px.
    const pad = getComputedStyle(group());
    expect(parseFloat(pad.paddingLeft)).toBeGreaterThanOrEqual(24);
    expect(parseFloat(pad.paddingRight)).toBeGreaterThanOrEqual(24);
    expect(pad.touchAction).not.toBe("none");
    expect(screen.getByText(/Scroll the page from the margins/)).toBeInTheDocument();
  });

  it("handles the keys on the group: Escape clears the selection, arrows are taken, Tab is not", () => {
    const { onSelectCases } = renderMap({ selectedCaseIds: ["3"] });
    const g = group();
    g.focus();
    expect(fireEvent.keyDown(g, { key: "Escape" })).toBe(false);
    expect(onSelectCases).toHaveBeenCalledWith([]);
    expect(fireEvent.keyDown(g, { key: "ArrowLeft" })).toBe(false);
    expect(fireEvent.keyDown(g, { key: "Tab" })).toBe(true);
    expect(fireEvent.keyDown(g, { key: "a" })).toBe(true);
  });

  it("states the real range of each axis as text, since the canvas shows a normalised box", () => {
    renderMap();
    expect(screen.getByText("Axis ranges: PC1 1.00 to 5.00, PC2 0.50 to 2.50, PC3 -1.67 to -0.33.")).toBeInTheDocument();
  });

  it("has a Reset view button that is safe before the scene exists", async () => {
    const user = userEvent.setup();
    renderMap();
    await user.click(screen.getByRole("button", { name: "Reset view" }));
  });
});

describe("EmbeddingMap3D: categories", () => {
  it("lists the classes present with counts as toggles, and says how many messages are shown", async () => {
    const user = userEvent.setup();
    renderMap();
    expect(chip(/^Safe 2/)).toHaveAttribute("aria-pressed", "true");
    expect(chip(/^Unwanted 1/)).toHaveAttribute("aria-pressed", "true");
    expect(chip(/^Dangerous 2/)).toHaveAttribute("aria-pressed", "true");
    expect(screen.queryByRole("button", { name: /Unclassified/ })).not.toBeInTheDocument();
    shown("5 of 5 messages shown");

    await user.click(chip(/^Dangerous 2/));
    expect(chip(/^Dangerous 2/)).toHaveAttribute("aria-pressed", "false");
    shown("3 of 5 messages shown");
    await user.click(chip(/^Dangerous 2/));
    shown("5 of 5 messages shown");
  });

  it("announces the count politely", () => {
    renderMap();
    const live = screen.getByText("5 of 5 messages shown");
    expect(live.closest("[aria-live]")).toHaveAttribute("aria-live", "polite");
    expect(live.closest("[role=status]")).not.toBeNull();
  });

  it("has an Unclassified chip only when such messages exist", () => {
    renderMap({ points: [...points, pt("6", "weird", "2026-10-02")] });
    expect(chip(/^Unclassified 1/)).toHaveAttribute("aria-pressed", "true");
  });

  it("explains the shaded clouds only when one is drawn", () => {
    const text = "Shaded clouds: 2 standard deviations around each category's average position, computed from the points shown.";
    const { unmount } = renderMap();
    expect(screen.queryByText(text)).not.toBeInTheDocument();
    unmount();
    renderMap({ points: Array.from({ length: 6 }, (_, i) => pt(String(i + 10), "SAFE", "2026-10-02", null, i)) });
    expect(screen.getByText(text)).toBeInTheDocument();
  });
});

describe("EmbeddingMap3D: date range", () => {
  it("filters by day with From and To, shows the chosen days and announces the count", () => {
    renderMap();
    const from = screen.getByLabelText("From") as HTMLInputElement;
    const to = screen.getByLabelText("To") as HTMLInputElement;
    expect(from).toHaveAttribute("type", "range");
    expect(to).toHaveAttribute("type", "range");
    // four distinct days -> positions 0..3
    expect([from.min, from.max, from.value, to.value]).toEqual(["0", "3", "0", "3"]);
    expect(screen.getByText("1 Oct 2026")).toBeInTheDocument();
    expect(screen.getByText("9 Oct 2026")).toBeInTheDocument();

    fireEvent.change(from, { target: { value: "1" } });
    expect(screen.getByText("3 Oct 2026")).toBeInTheDocument();
    // 3, 5 and 9 Oct are in; the message without a date is not
    shown("3 of 5 messages shown");

    fireEvent.change(to, { target: { value: "2" } });
    shown("2 of 5 messages shown");
  });

  it("keeps From from passing To", () => {
    renderMap();
    const from = screen.getByLabelText("From") as HTMLInputElement;
    const to = screen.getByLabelText("To") as HTMLInputElement;
    fireEvent.change(to, { target: { value: "1" } });
    fireEvent.change(from, { target: { value: "3" } });
    expect(from.value).toBe("1");
    expect(to.value).toBe("1");
  });

  it("says that messages without a date are hidden once the range is narrowed", () => {
    renderMap();
    expect(screen.queryByText(/without a date are hidden/)).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "1" } });
    expect(screen.getByText("1 message without a date is hidden while the range is narrowed.")).toBeInTheDocument();
  });

  it("has no range when the sample has no dates, and says so", () => {
    renderMap({ points: points.map((p) => ({ ...p, date: null })) });
    expect(screen.queryByLabelText("From")).not.toBeInTheDocument();
    shown("5 of 5 messages shown");
    expect(screen.getByText("No message in this sample has a date.")).toBeInTheDocument();
  });
});

describe("EmbeddingMap3D: colour modes", () => {
  const mode = (name: string) => within(screen.getByRole("group", { name: "Colour by" })).getByRole("button", { name });

  it("offers Category, Campaign and Age, Category first and pressed", () => {
    renderMap();
    const buttons = within(screen.getByRole("group", { name: "Colour by" })).getAllByRole("button");
    expect(buttons.map((b) => b.textContent)).toEqual(["Category", "Campaign", "Age"]);
    expect(mode("Category")).toHaveAttribute("aria-pressed", "true");
    expect(mode("Campaign")).toHaveAttribute("aria-pressed", "false");
    expect(mode("Age")).toHaveAttribute("aria-pressed", "false");
  });

  it("Campaign: lists each coloured campaign by its full name, and what the grey means", async () => {
    const user = userEvent.setup();
    renderMap();
    await user.click(mode("Campaign"));
    expect(mode("Campaign")).toHaveAttribute("aria-pressed", "true");
    expect(mode("Category")).toHaveAttribute("aria-pressed", "false");
    const legend = screen.getByRole("list", { name: "Campaigns" });
    const items = within(legend).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("invoice-relay.example, cdn-pay.example, login-portal.example");
    expect(items[0]).toHaveTextContent("12 messages");
    expect(items[1]).toHaveTextContent("newsletter.example");
    expect(items[2]).toHaveTextContent("Not in a listed campaign");
    expect(screen.getByText(/Colours cover the case ids the summary lists, up to 20 per campaign/)).toBeInTheDocument();
  });

  it("Campaign: caps the colours at the six largest campaigns", async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: 8 }, (_, i) => row({ name: `camp-${i}.example`, messages: 20 - i, case_ids: [String(i + 1)] }));
    renderMap({ campaigns: many });
    await user.click(mode("Campaign"));
    const items = within(screen.getByRole("list", { name: "Campaigns" })).getAllByRole("listitem");
    expect(items).toHaveLength(7); // six campaigns and the grey
    expect(items[5]).toHaveTextContent("camp-5.example");
    expect(screen.queryByText("camp-6.example")).not.toBeInTheDocument();
  });

  it("Campaign: says when there are none", async () => {
    const user = userEvent.setup();
    renderMap({ campaigns: [] });
    await user.click(mode("Campaign"));
    expect(screen.getByText("No campaigns in the selected period.")).toBeInTheDocument();
  });

  it("Age: shows the oldest and newest day of the sample and a swatch for no date", async () => {
    const user = userEvent.setup();
    renderMap();
    await user.click(mode("Age"));
    expect(mode("Age")).toHaveAttribute("aria-pressed", "true");
    const legend = screen.getByRole("group", { name: "Age scale" });
    expect(within(legend).getByText("Oldest 1 Oct 2026")).toBeInTheDocument();
    expect(within(legend).getByText("Newest 9 Oct 2026")).toBeInTheDocument();
    expect(within(legend).getByText("No date")).toBeInTheDocument();
  });

  it("Age: leaves out the no date swatch when every message has a date", async () => {
    const user = userEvent.setup();
    renderMap({ points: points.slice(0, 4) });
    await user.click(mode("Age"));
    expect(screen.queryByText("No date")).not.toBeInTheDocument();
  });

  it("goes back to the category key", async () => {
    const user = userEvent.setup();
    renderMap();
    await user.click(mode("Age"));
    await user.click(mode("Category"));
    expect(screen.queryByRole("group", { name: "Age scale" })).not.toBeInTheDocument();
    expect(chip(/^Safe 2/)).toBeInTheDocument();
  });
});

describe("EmbeddingMap3D: degenerate samples", () => {
  it.each([
    ["no points", []],
    ["one point", [pt("1", "SAFE", "2026-10-01")]],
    ["two identical points", [pt("1", "SAFE", "2026-10-01", "a", 0), pt("2", "SAFE", "2026-10-01", "b", 0)]],
  ])("renders %s without failing", (_n, pts) => {
    renderMap({ points: pts });
    expect(group()).toBeInTheDocument();
    shown(`${pts.length} of ${pts.length} messages shown`);
  });
});

describe("MapTooltip", () => {
  it("shows the subject, case, category and day", () => {
    renderWithProviders(<MapTooltip point={points[2]} />);
    expect(screen.getByText("URGENT: pay now")).toBeInTheDocument();
    expect(screen.getByText("Case 3")).toBeInTheDocument();
    expect(screen.getByText("Dangerous")).toBeInTheDocument();
    expect(screen.getByText("5 Oct 2026")).toBeInTheDocument();
  });

  it("leaves out what the point does not have", () => {
    renderWithProviders(<MapTooltip point={{ ...points[0], mail_subject: null, suspicious_case_id: null, date: null, label: "x" }} />);
    expect(screen.getByText("Unclassified")).toBeInTheDocument();
    expect(screen.getByText("No subject")).toBeInTheDocument();
    expect(screen.queryByText(/^Case/)).not.toBeInTheDocument();
    expect(screen.queryByText(/2026/)).not.toBeInTheDocument();
  });
});
