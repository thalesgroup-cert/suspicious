import { describe, it, expect } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import type { PcaPoint } from "@/features/campaigns/api";
import Embedding2D from "../components/Embedding2D";
import EmbeddingMap from "../components/EmbeddingMap";

const pt = (x: number, y: number, label: string, id: string | null = null): PcaPoint => ({
  x, y, z: 0, label, suspicious_case_id: id, mail_subject: null, sourceRefs: [], date: null,
});

const map = () => screen.getByRole("img", { name: /Embedding map/ });
const dots = () => map().querySelectorAll("circle").length;
const ticks = (axis: "x" | "y") =>
  Array.from(document.querySelectorAll(`.recharts-${axis}Axis-tick-labels .recharts-cartesian-axis-tick-value`)).map((t) => t.textContent ?? "");
const chip = (name: RegExp) => screen.getByRole("button", { name });

describe("Embedding2D", () => {
  it("draws unclassified points as their own series, counts them and lets them be toggled", async () => {
    const user = userEvent.setup();
    const points = [pt(0, 0, "SAFE"), pt(1, 1, "SAFE"), pt(2, 2, "DANGEROUS"), pt(3, 3, "UNKNOWN"), pt(4, 4, "UNKNOWN")];
    renderWithProviders(<Embedding2D points={points} selectedCaseIds={[]} />);

    expect(chip(/^Safe 2/)).toHaveAttribute("aria-pressed", "true");
    expect(chip(/^Unclassified 2/)).toHaveAttribute("aria-pressed", "true");
    expect(map()).toHaveAttribute("aria-label", expect.stringContaining("5 messages"));
    expect(map()).toHaveAttribute("aria-label", expect.stringContaining("Unclassified 2"));
    await waitFor(() => expect(dots()).toBe(5));

    await user.click(chip(/^Unclassified 2/));
    expect(chip(/^Unclassified 2/)).toHaveAttribute("aria-pressed", "false");
    await waitFor(() => expect(dots()).toBe(3));
  });

  it("has no Unclassified chip when every point has one of the four classes", () => {
    renderWithProviders(<Embedding2D points={[pt(0, 0, "SAFE"), pt(1, 1, "UNWANTED")]} selectedCaseIds={[]} />);
    expect(screen.queryByRole("button", { name: /Unclassified/ })).not.toBeInTheDocument();
    expect(map().getAttribute("aria-label")).not.toMatch(/Unclassified/);
  });

  it("toggles a class with aria-pressed and removes its points", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Embedding2D points={[pt(0, 0, "SAFE"), pt(1, 1, "SAFE"), pt(2, 2, "DANGEROUS")]} selectedCaseIds={[]} />);
    await waitFor(() => expect(dots()).toBe(3));
    await user.click(chip(/^Safe 2/));
    expect(chip(/^Safe 2/)).toHaveAttribute("aria-pressed", "false");
    await waitFor(() => expect(dots()).toBe(1));
  });

  it("fits the axes to the visible points only", async () => {
    const user = userEvent.setup();
    // One far dangerous point and one far unclassified point; the safe points sit in 0..1.
    const points = [pt(0, 0, "SAFE"), pt(1, 1, "SAFE"), pt(100, 100, "DANGEROUS"), pt(-50, -50, "UNKNOWN")];
    renderWithProviders(<Embedding2D points={points} selectedCaseIds={[]} />);
    const span = () => {
      const v = ticks("x").map(Number);
      return Math.max(...v) - Math.min(...v);
    };
    await waitFor(() => expect(span()).toBeGreaterThan(140));

    await user.click(chip(/^Dangerous/));
    await waitFor(() => expect(span()).toBeLessThan(60));
    await user.click(chip(/^Unclassified/));
    await waitFor(() => expect(span()).toBeLessThan(1.2));
    expect(Math.max(...ticks("y").map(Number))).toBeLessThan(1.1);
  });

  it("titles the axes PC1 and PC2", async () => {
    renderWithProviders(<Embedding2D points={[pt(0, 0, "SAFE"), pt(1, 1, "SAFE")]} selectedCaseIds={[]} />);
    expect(await screen.findByText("PC1")).toBeInTheDocument();
    expect(screen.getByText("PC2")).toBeInTheDocument();
  });

  it("keeps the five tick labels distinct on a narrow span", async () => {
    renderWithProviders(<Embedding2D points={[pt(0, 0, "SAFE"), pt(0.2, 0.15, "SAFE")]} selectedCaseIds={[]} />);
    await waitFor(() => expect(ticks("x")).toHaveLength(5));
    expect(new Set(ticks("x")).size).toBe(5);
    expect(new Set(ticks("y")).size).toBe(5);
  });

  it("uses no decimals on a wide span", async () => {
    renderWithProviders(<Embedding2D points={[pt(0, 0, "SAFE"), pt(2000, 1500, "SAFE")]} selectedCaseIds={[]} />);
    await waitFor(() => expect(ticks("x")).toHaveLength(5));
    expect(ticks("x").join(" ")).not.toContain(".");
  });
});

describe("EmbeddingMap", () => {
  const points = [pt(0, 0, "SAFE", "1"), pt(1, 1, "DANGEROUS", "2")];
  const noop = () => {};

  it("swaps the map for a table with one constant, pressed-state button", async () => {
    const user = userEvent.setup();
    renderWithProviders(<EmbeddingMap points={points} explainedVariance={[0.2, 0.1]} selectedCaseIds={[]} onSelectCases={noop} />);
    const toggle = screen.getByRole("button", { name: "Table view" });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByRole("img", { name: /Embedding map/ })).toBeInTheDocument();

    await user.click(toggle);
    expect(screen.getByRole("button", { name: "Table view" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: /Embedding map/ })).not.toBeInTheDocument();

    await user.click(toggle);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Embedding map/ })).toBeInTheDocument();
  });

  it("announces the selection politely and says how many selected cases the sample holds", () => {
    renderWithProviders(<EmbeddingMap points={points} explainedVariance={[0.2, 0.1]} selectedCaseIds={["1", "40", "41"]} onSelectCases={noop} />);
    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(within(status).getByText("3 selected")).toBeInTheDocument();
    expect(within(status).getByText("1 in the map sample")).toBeInTheDocument();
  });

  it("keeps the live region mounted, empty, when nothing is selected", () => {
    renderWithProviders(<EmbeddingMap points={points} explainedVariance={[0.2, 0.1]} selectedCaseIds={[]} onSelectCases={noop} />);
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
  });

  it("does not repeat the sample count when every selected case is in it", () => {
    renderWithProviders(<EmbeddingMap points={points} explainedVariance={[0.2, 0.1]} selectedCaseIds={["1", "2"]} onSelectCases={noop} />);
    expect(screen.getByText("2 selected")).toBeInTheDocument();
    expect(screen.queryByText(/in the map sample/)).not.toBeInTheDocument();
  });
});
