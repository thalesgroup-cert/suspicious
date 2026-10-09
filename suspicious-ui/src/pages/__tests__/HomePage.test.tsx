import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { fixtureMe, fixtureDashboardSummary } from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/api/client", () => ({
  api: {
    get: vi.fn().mockResolvedValue({ data: { count: 0, results: [] } }),
    post: vi.fn().mockResolvedValue({ data: {} }),
    patch: vi.fn().mockResolvedValue({ data: {} }),
  },
}));

vi.mock("@/features/dashboard/api", () => ({
  getDashboardSummary: vi.fn(),
}));


import { getMe } from "@/api/auth";
import { api } from "@/api/client";
import { getDashboardSummary } from "@/features/dashboard/api";
import HomePage from "../HomePage";

type Counts = { safe: number; inconclusive: number; suspicious: number; dangerous: number };
const ZERO: Counts = { safe: 0, inconclusive: 0, suspicious: 0, dangerous: 0 };

function mockSummary(monthly: Record<string, number>, danger_counts: Counts) {
  vi.mocked(api.get).mockImplementation((url: string) =>
    url === "/home/summary/"
      ? Promise.resolve({
          data: {
            show_scope_modal: false,
            monthly,
            danger_counts,
            spotlight: {
              title: "Your monthly activity",
              description: "You have submitted 5 items this month.",
              cta_label: "Submit an item",
              cta_path: "/submit",
            },
          },
        })
      : Promise.resolve({ data: { count: 0, results: [] } }),
  );
}

describe("HomePage - Test Suite", () => {
  beforeEach(() => {
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(getDashboardSummary).mockResolvedValue(fixtureDashboardSummary);
  });

  describe("Page Navigation and Access", () => {
    it("renders without crashing on the home route", async () => {
      const { container } = renderWithProviders(<HomePage />, { initialPath: "/" });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
    });

    it("fetches the authenticated user on mount", async () => {
      renderWithProviders(<HomePage />, { initialPath: "/" });
      await waitFor(() => expect(getMe).toHaveBeenCalled());
    });
  });

  describe("Display", () => {
    it("keeps the page mounted while data is loading", async () => {
      const { container } = renderWithProviders(<HomePage />, { initialPath: "/" });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
    });
  });

  describe("Empty chart", () => {
    it("shows the spinner, not the empty message, while the home summary is loading", async () => {
      vi.mocked(api.get).mockImplementation((url: string) =>
        url === "/home/summary/"
          ? new Promise(() => {})
          : Promise.resolve({ data: { count: 0, results: [] } }),
      );
      renderWithProviders(<HomePage />, { initialPath: "/" });
      await screen.findByText("Threat distribution");
      expect(screen.getAllByRole("progressbar").length).toBeGreaterThan(0);
      expect(screen.queryByText("No submissions this month")).toBeNull();
    });
  });

  describe("Share card and threat distribution", () => {
    beforeEach(() => {
      vi.mocked(getMe).mockResolvedValue({ ...fixtureMe, groups: [] });
    });

    it("counts the user's own submissions, not the verdict buckets", async () => {
      mockSummary({ user_items: 5, everyone_items: 182 }, ZERO);
      renderWithProviders(<HomePage />, { initialPath: "/" });
      await screen.findByText("You have submitted 5 items this month.");
      const share = screen.getByText(/of 182 org submissions this month/);
      expect(share).toBeInTheDocument();
      expect(screen.getByText("5")).toBeInTheDocument();
      expect(screen.getByText(/3% yours/)).toBeInTheDocument();
    });

    it("all-zero counts show the empty state, no legend rows, and no console errors", async () => {
      const errors = vi.spyOn(console, "error").mockImplementation(() => {});
      mockSummary({ user_items: 0, everyone_items: 182 }, ZERO);
      renderWithProviders(<HomePage />, { initialPath: "/" });
      await screen.findByText("No submissions this month");
      expect(screen.getByText("Verdicts appear here once something is analysed this month.")).toBeInTheDocument();
      expect(screen.queryByText("Dangerous")).toBeNull();
      expect(errors).not.toHaveBeenCalled();
      errors.mockRestore();
    });

    it("says no verdicts yet when the user submitted items but none has a verdict", async () => {
      mockSummary({ user_items: 60, everyone_items: 182 }, ZERO);
      renderWithProviders(<HomePage />, { initialPath: "/" });
      await screen.findByText("No verdicts yet this month");
      expect(screen.getByText("Verdicts appear here once your submissions are analysed.")).toBeInTheDocument();
      expect(screen.queryByText("No submissions this month")).toBeNull();
    });

    it("non-zero counts render the legend", async () => {
      mockSummary({ user_items: 3, everyone_items: 182 }, { safe: 1, inconclusive: 0, suspicious: 1, dangerous: 1 });
      renderWithProviders(<HomePage />, { initialPath: "/" });
      expect(await screen.findByText("Dangerous")).toBeInTheDocument();
      expect(screen.queryByText("No submissions this month")).toBeNull();
    });

    it("has a single primary action: the spotlight CTA", async () => {
      mockSummary({ user_items: 5, everyone_items: 182 }, ZERO);
      renderWithProviders(<HomePage />, { initialPath: "/" });
      await screen.findByText("You have submitted 5 items this month.");
      expect(screen.getAllByRole("button", { name: "Submit an item" })).toHaveLength(1);
      expect(screen.queryByRole("button", { name: "Submit" })).toBeNull();
      expect(screen.queryByText("Spotlight")).toBeNull();
    });
  });

  describe("Greeting heading", () => {
    it("does not squeeze letters so tightly that the word gap after the comma closes", async () => {
      renderWithProviders(<HomePage />, { initialPath: "/" });
      const h = await screen.findByText(/^Welcome,/);
      // Audit H4: -0.6px at 14px (about -0.043em) at weight 980 closed "Welcome,Elena".
      // Floor in em so the heading size can change; -0.02em is the plan's floor for h1-h3.
      const cs = getComputedStyle(h);
      const em = (parseFloat(cs.letterSpacing) || 0) / parseFloat(cs.fontSize);
      expect(em).toBeGreaterThanOrEqual(-0.02);
      expect(parseFloat(cs.fontWeight)).toBeLessThanOrEqual(800);
    });
  });

  describe("Management", () => {
    it("renders the home route under a Suspense-friendly tree", async () => {
      const { container } = renderWithProviders(<HomePage />, { initialPath: "/" });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
    });
  });
});
