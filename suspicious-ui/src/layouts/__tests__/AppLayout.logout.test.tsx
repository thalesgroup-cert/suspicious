import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { QueryClient } from "@tanstack/react-query";
import { renderWithProviders } from "@/test/utils";
import { fixtureMe } from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
  logout: vi.fn(),
}));

import { getMe, logout } from "@/api/auth";
import AppLayout from "../AppLayout";

// gcTime Infinity: unobserved queries must not vanish on their own, or the test proves nothing.
function seededClient() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } } });
  qc.setQueryData(["dashboardSummary", 10, 2026, "OWN_SCOPE"], { top_reporters: [{ label: "someone", value: 3 }] });
  qc.setQueryData(["dashboardScopes"], { default: "OWN_SCOPE", options: [] });
  return qc;
}

describe("AppLayout logout", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.stubGlobal("matchMedia", (query: string) => ({
      matches: query.includes("min-width"),
      media: query,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      onchange: null,
      dispatchEvent: () => false,
    }));
  });
  afterEach(() => vi.unstubAllGlobals());

  for (const outcome of ["succeeds", "fails"] as const) {
    it(`clears every cached query (dashboard summaries, scopes) when the logout request ${outcome}`, async () => {
      if (outcome === "succeeds") vi.mocked(logout).mockResolvedValue(undefined as never);
      else vi.mocked(logout).mockRejectedValue(new Error("network"));
      const qc = seededClient();
      renderWithProviders(<AppLayout />, { initialPath: "/dashboard", queryClient: qc });
      // A bare click event: a pointer hover expands the slim sidebar and swaps the button mid-click.
      // Let the profile load settle the sidebar first, so the button is not re-mounted under the click.
      await screen.findByRole("button", { name: "Logout" }, { timeout: 5000 });
      await new Promise((r) => setTimeout(r, 500));
      fireEvent.click(screen.getByRole("button", { name: "Logout" }));
      await waitFor(() => expect(logout).toHaveBeenCalledTimes(1));
      await waitFor(() => expect(qc.getQueryData(["dashboardScopes"])).toBeUndefined());
      expect(qc.getQueryData(["dashboardSummary", 10, 2026, "OWN_SCOPE"])).toBeUndefined();
    });
  }
});
