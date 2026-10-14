import { describe, it, expect, vi, beforeEach } from "vitest";
import { waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { fixtureMe } from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
  logout: vi.fn(),
}));

import { getMe } from "@/api/auth";
import AppLayout from "../AppLayout";

describe("AppLayout mobile app bar", () => {
  beforeEach(() => {
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
  });

  it("sits below modal drawers (page drawers must cover it on phones)", async () => {
    const { container } = renderWithProviders(<AppLayout />, { initialPath: "/submissions" });
    await waitFor(() => expect(container.querySelector("header")).toBeTruthy());
    const z = Number(getComputedStyle(container.querySelector("header")!).zIndex);
    expect(z).toBeLessThan(1200); // MUI theme.zIndex.drawer
  });
});
