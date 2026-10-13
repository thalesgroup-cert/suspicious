import { describe, it, expect } from "vitest";
import { screen, within } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { fixtureDashboardSummary } from "@/test/fixtures";
import { Sparkline } from "../components/Sparkline";
import KpiTrendPanels from "../components/KpiTrendPanels";
import OutcomesPanel from "../components/OutcomesPanel";
import ByTypePanel from "../components/ByTypePanel";

const summary = fixtureDashboardSummary;

describe("Sparkline", () => {
  it("is an image whose label lists the values", () => {
    renderWithProviders(<Sparkline values={[3, 5, 2, 9]} label="Reports per week" />);
    const img = screen.getByRole("img", { name: "Reports per week: 3, 5, 2, 9" });
    expect(img.tagName.toLowerCase()).toBe("svg");
    expect(img.querySelector("polyline")).toHaveAttribute("stroke", "currentColor");
  });

  it("shows a single value as text instead of a line", () => {
    renderWithProviders(<Sparkline values={[7]} label="Reports per week" />);
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(screen.getByText("Reports per week: 7")).toBeInTheDocument();
  });

  it("renders nothing without values", () => {
    const { container } = renderWithProviders(<Sparkline values={[]} label="Reports per week" />);
    expect(container.querySelector("svg")).toBeNull();
    expect(screen.queryByText(/Reports per week/)).not.toBeInTheDocument();
  });
});

describe("KpiTrendPanels", () => {
  it("shows reports with the delta and the previous value", () => {
    renderWithProviders(<KpiTrendPanels summary={summary} />);
    const reports = screen.getByRole("region", { name: "Reports" });
    expect(within(reports).getByText("512")).toBeInTheDocument();
    expect(within(reports).getByText("vs September: +32 (+7%) from 480")).toBeInTheDocument();
    expect(within(reports).getByRole("img", { name: "Reports per week: 90, 130" })).toBeInTheDocument();
  });

  it("says no data, with no arrow, when the previous month has no reports", () => {
    const empty = { safe: 0, inconclusive: 0, suspicious: 0, dangerous: 0, failure: 0 };
    renderWithProviders(<KpiTrendPanels summary={{ ...summary, previous: { reports: 0, outcomes: empty } }} />);
    expect(within(screen.getByRole("region", { name: "Reports" })).getByText("vs September: no data")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Dangerous" })).getByText("vs September: no data")).toBeInTheDocument();
    expect(document.querySelector('[data-testid^="Trending"]')).toBeNull();
  });

  it("shows dangerous cases, their share of finished cases and the delta", () => {
    renderWithProviders(<KpiTrendPanels summary={summary} />);
    const card = screen.getByRole("region", { name: "Dangerous" });
    expect(within(card).getByText("60")).toBeInTheDocument();
    expect(within(card).getByText("12% of 491 finished cases")).toBeInTheDocument();
    expect(within(card).getByText("vs September: +5 (+9%) from 55")).toBeInTheDocument();
    // No weekly series exists for dangerous cases: no sparkline is invented.
    expect(within(card).queryByRole("img")).not.toBeInTheDocument();
  });

  it("rounds the dangerous share the same way as the Outcomes panel", () => {
    // 17 / 35 = 48.57: plain rounding says 49, the Outcomes rows (summing to 100) say 48.
    const outcomes = { safe: 10, inconclusive: 5, suspicious: 2, dangerous: 17, failure: 1 };
    renderWithProviders(
      <>
        <KpiTrendPanels summary={{ ...summary, outcomes }} />
        <OutcomesPanel outcomes={outcomes} inProgress={0} />
      </>
    );
    expect(screen.getByText("48% of 35 finished cases")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")[3]).toHaveTextContent("Dangerous1748%");
  });

  it("names the previous month across a year boundary", () => {
    renderWithProviders(<KpiTrendPanels summary={{ ...summary, month: 1, year: 2027 }} />);
    expect(screen.getByText("vs December: +32 (+7%) from 480")).toBeInTheDocument();
  });

  it("shows reporters and new users only when there are some", () => {
    const { unmount } = renderWithProviders(<KpiTrendPanels summary={summary} />);
    const card = screen.getByRole("region", { name: "Reporters" });
    expect(within(card).getByText("128")).toBeInTheDocument();
    expect(within(card).getByText("4 new users in October")).toBeInTheDocument();
    unmount();
    renderWithProviders(<KpiTrendPanels summary={{ ...summary, new_users: 0 }} />);
    expect(screen.queryByText(/new users/)).not.toBeInTheDocument();
  });
});

describe("OutcomesPanel", () => {
  it("lists five outcomes with counts and percentages that sum to 100", () => {
    renderWithProviders(<OutcomesPanel outcomes={summary.outcomes} inProgress={21} />);
    const panel = screen.getByRole("region", { name: "Outcomes" });
    const rows = within(panel).getAllByRole("listitem");
    expect(rows.map((r) => r.textContent)).toEqual([
      "Safe20041%",
      "Inconclusive8016%",
      "Suspicious15031%",
      "Dangerous6012%",
      "Failure1<1%",
    ]);
    const total = rows
      .map((r) => r.lastElementChild!.textContent!.match(/^(\d+)%$/)?.[1])
      .reduce((sum, p) => sum + Number(p ?? 0), 0);
    expect(total).toBe(100);
    expect(within(panel).getByRole("img", { name: /^Outcomes of 491 finished cases/ })).toBeInTheDocument();
  });

  it("shows in-progress cases on their own line, outside the outcomes", () => {
    renderWithProviders(<OutcomesPanel outcomes={summary.outcomes} inProgress={21} />);
    expect(screen.getByText("In progress: 21")).toBeInTheDocument();
    expect(screen.getByText(/not counted in the outcomes/)).toBeInTheDocument();
    expect(screen.getAllByRole("listitem").map((r) => r.textContent)).not.toContain(expect.stringMatching(/progress/i));
  });

  it("marks Failure with a neutral pattern, not the Dangerous colour", () => {
    renderWithProviders(<OutcomesPanel outcomes={summary.outcomes} inProgress={0} />);
    const dangerous = getComputedStyle(document.querySelector('[data-outcome-marker="dangerous"]')!);
    const failure = getComputedStyle(document.querySelector('[data-outcome-marker="failure"]')!);
    const red = dangerous.backgroundColor;
    expect(red).not.toBe("rgba(0, 0, 0, 0)");
    expect(failure.backgroundColor).not.toBe(red);
    expect(failure.backgroundImage).toContain("repeating-linear-gradient");
    expect(failure.backgroundImage).not.toContain(red.replace("rgb(", "").replace(")", ""));
    expect(failure.borderTopColor).not.toBe(red);
  });

  it("hides percentages when nothing has finished", () => {
    const zero = { safe: 0, inconclusive: 0, suspicious: 0, dangerous: 0, failure: 0 };
    renderWithProviders(<OutcomesPanel outcomes={zero} inProgress={3} />);
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
    expect(screen.getByText("In progress: 3")).toBeInTheDocument();
  });
});

describe("ByTypePanel", () => {
  it("lists reported types with friendly labels and omits zeros", () => {
    renderWithProviders(
      <ByTypePanel byType={{ MAIL: 400, FILE: 50, URL: 0, IP: 10, HASH: 0, IOC: 5, UNKNOWN: 2 }} />
    );
    const panel = screen.getByRole("region", { name: "What was reported" });
    expect(within(panel).getAllByRole("listitem").map((r) => r.textContent)).toEqual([
      "Emails400",
      "Files50",
      "IP addresses10",
      "Indicator groups5",
      "Other2",
    ]);
    expect(within(panel).queryByText("URLs")).not.toBeInTheDocument();
    expect(within(panel).queryByText("Hashes")).not.toBeInTheDocument();
  });

  it("renders nothing when every type is zero", () => {
    const { container } = renderWithProviders(
      <ByTypePanel byType={{ MAIL: 0, FILE: 0, URL: 0, IP: 0, HASH: 0, IOC: 0, UNKNOWN: 0 }} />
    );
    expect(container.querySelector('[role="region"]')).toBeNull();
  });
});
