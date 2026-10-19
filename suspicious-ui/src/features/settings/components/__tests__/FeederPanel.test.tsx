import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";

vi.mock("@/features/settings/api", () => ({
  getFeederStatus: vi.fn(),
  setFeederStatus: vi.fn(),
  getFeederHealth: vi.fn(),
}));

import { getFeederStatus, getFeederHealth, setFeederStatus } from "@/features/settings/api";
import { contrastRatio } from "@/shared/lib/contrast";
import { useColorStore } from "@/styles/colorStore";
import { FeederPanel } from "@/features/settings/components/FeederPanel";

describe("FeederPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getFeederHealth).mockResolvedValue({
      online: true, last_successful_poll: null, emails_processed_total: 0, errors_total: 0,
      stale_seconds: 0, stale: false, checked_at: 0, error: null,
    });
    vi.mocked(setFeederStatus).mockResolvedValue({ enabled: false } as never);
  });

  it("asks before turning the feeder off and leaves it on on Cancel", async () => {
    const user = userEvent.setup();
    vi.mocked(getFeederStatus).mockResolvedValue({ enabled: true } as never);
    renderWithProviders(<FeederPanel />);
    const sw = await screen.findByRole("switch", { name: "Email feeder" });
    await waitFor(() => expect(sw).toBeChecked());

    await user.click(sw);
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("The feeder stops ingesting mail immediately. Existing cases are unaffected.");
    expect(setFeederStatus).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(sw).toBeChecked();
    expect(setFeederStatus).not.toHaveBeenCalled();
  });

  it("turns the feeder off after confirmation", async () => {
    const user = userEvent.setup();
    vi.mocked(getFeederStatus).mockResolvedValue({ enabled: true } as never);
    renderWithProviders(<FeederPanel />);
    const sw = await screen.findByRole("switch", { name: "Email feeder" });
    await waitFor(() => expect(sw).toBeChecked());

    await user.click(sw);
    await user.click(await screen.findByRole("button", { name: "Turn off" }));
    await waitFor(() => expect(setFeederStatus).toHaveBeenCalledWith(false));
  });

  it("turns the feeder on without a dialog", async () => {
    const user = userEvent.setup();
    vi.mocked(getFeederStatus).mockResolvedValue({ enabled: false } as never);
    vi.mocked(setFeederStatus).mockResolvedValue({ enabled: true } as never);
    renderWithProviders(<FeederPanel />);
    const sw = await screen.findByRole("switch", { name: "Email feeder" });
    await waitFor(() => expect(sw).toBeEnabled());

    await user.click(sw);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await waitFor(() => expect(setFeederStatus).toHaveBeenCalledWith(true));
  });

  it.each([[true, "Enabled"], [false, "Disabled"]])("shows the state as text when enabled=%s", async (enabled, text) => {
    vi.mocked(getFeederStatus).mockResolvedValue({ enabled } as never);
    renderWithProviders(<FeederPanel />);
    expect(await screen.findByText(text)).toBeInTheDocument();
  });

  it("takes the enabled colour from the result palette, not a literal", async () => {
    useColorStore.getState().setResultColor("safe", "#123456");
    try {
      vi.mocked(getFeederStatus).mockResolvedValue({ enabled: true } as never);
      renderWithProviders(<FeederPanel />);
      await screen.findByText("Enabled");
      // Emotion writes sx into style tags; the tint is the palette colour at 12%.
      const css = Array.from(document.querySelectorAll("style")).map((s) => s.textContent).join("");
      expect(css).toContain("rgba(18, 52, 86, 0.12)");
    } finally {
      useColorStore.getState().reset();
    }
  });

  it("keeps the Enabled label readable on its tint", async () => {
    vi.mocked(getFeederStatus).mockResolvedValue({ enabled: true } as never);
    renderWithProviders(<FeederPanel />);
    const label = await screen.findByText("Enabled");
    const chip = label.closest(".MuiChip-root") as HTMLElement;
    const over = (c: string) => c.match(/[\d.]+/g)!.map(Number);
    const hex = (v: number[]) => "#" + v.map((x) => x.toString(16).padStart(2, "0")).join("");
    // The chip animates from its disabled look, so poll until the transition settles.
    await waitFor(() => {
      const style = getComputedStyle(chip);
      const [fr, fg, fb] = over(style.color);
      const [br, bg, bb, ba = 1] = over(style.backgroundColor);
      const page = over(getComputedStyle(document.body).backgroundColor);
      const blend = [br, bg, bb].map((v, i) => Math.round(v * ba + page[i] * (1 - ba)));
      expect(ba).toBeCloseTo(0.12, 2);
      expect(contrastRatio(hex([fr, fg, fb]), hex(blend))).toBeGreaterThanOrEqual(4.5);
    });
  });
});
