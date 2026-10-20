import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";

vi.mock("@/features/settings/api", () => ({
  getFeederStatus: vi.fn(),
  setFeederStatus: vi.fn(),
  getFeederHealth: vi.fn(),
}));

import { getFeederStatus, getFeederHealth, setFeederStatus, type FeederHealth } from "@/features/settings/api";
import FeederHealthBadge from "@/shared/components/FeederHealthBadge";
import { contrastRatio } from "@/shared/lib/contrast";
import { themes } from "@/styles/themes";
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

  it("shows an error with Retry, not Disabled, when the status cannot be loaded", async () => {
    const user = userEvent.setup();
    vi.mocked(getFeederStatus).mockRejectedValueOnce(new Error("boom"));
    renderWithProviders(<FeederPanel />);

    expect(await screen.findByText("Could not load the email feeder status.")).toBeInTheDocument();
    expect(screen.queryByText("Disabled")).not.toBeInTheDocument();
    expect(screen.queryByRole("switch", { name: "Email feeder" })).not.toBeInTheDocument();

    vi.mocked(getFeederStatus).mockResolvedValue({ enabled: true } as never);
    await user.click(screen.getByRole("button", { name: "Retry" }));
    const sw = await screen.findByRole("switch", { name: "Email feeder" });
    await waitFor(() => expect(sw).toBeChecked());
    expect(screen.queryByText("Could not load the email feeder status.")).not.toBeInTheDocument();
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

  it("returns focus to the switch once turning off has settled", async () => {
    const user = userEvent.setup();
    vi.mocked(getFeederStatus).mockResolvedValue({ enabled: true } as never);
    vi.mocked(setFeederStatus).mockImplementation(
      () => new Promise((r) => setTimeout(() => r({ enabled: false } as never), 150))
    );
    renderWithProviders(<FeederPanel />);
    const sw = await screen.findByRole("switch", { name: "Email feeder" });
    await waitFor(() => expect(sw).toBeChecked());

    await user.click(sw);
    await user.click(await screen.findByRole("button", { name: "Turn off" }));
    await waitFor(() => expect(setFeederStatus).toHaveBeenCalledWith(false));
    await waitFor(() => expect(sw).toHaveFocus(), { timeout: 2000 });
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

  it.each(["light", "midnight"] as const)("keeps the state label readable on the %s paper", async (theme) => {
    localStorage.setItem("suspicious.theme", theme);
    try {
      vi.mocked(getFeederStatus).mockResolvedValue({ enabled: true } as never);
      renderWithProviders(<FeederPanel />);
      const label = await screen.findByText("Enabled");
      const icon = label.parentElement!.querySelector("svg")!;
      const paper = themes[theme].palette.background.paper;
      expect(contrastRatio(getComputedStyle(label).color, paper)).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(getComputedStyle(icon).color, paper)).toBeGreaterThanOrEqual(3);
    } finally {
      localStorage.removeItem("suspicious.theme");
    }
  });

  describe("status card", () => {
    const NOW = 1_800_000_000;
    const health = (over: Partial<FeederHealth> = {}): FeederHealth => ({
      online: true, last_successful_poll: Math.floor(Date.now() / 1000) - 300, emails_processed_total: 42, errors_total: 3,
      stale_seconds: 300, stale: false, checked_at: NOW, error: null, ...over,
    });
    const fact = (key: string) => screen.queryByText(key, { selector: "dt" });
    const valueOf = (key: string) => fact(key)!.nextElementSibling as HTMLElement;

    beforeEach(() => vi.mocked(getFeederStatus).mockResolvedValue({ enabled: true } as never));

    it.each([[true, "Enabled"], [false, "Disabled"]])("shows enabled=%s as an icon and the word %s", async (enabled, word) => {
      vi.mocked(getFeederStatus).mockResolvedValue({ enabled } as never);
      renderWithProviders(<FeederPanel />);
      const label = await screen.findByText(word);
      expect(label.parentElement!.querySelector("svg")).not.toBeNull();
      expect(label.closest(".MuiChip-root")).toBeNull();
    });

    it.each([
      ["online", health(), "Online", "ok"],
      ["stale", health({ stale: true }), "Stale", "warning"],
      ["offline", health({ online: false, error: "unreachable: ConnectionError" }), "Offline", "danger"],
    ])("shows %s health as an icon and a word with its tone", async (_n, payload, word, tone) => {
      vi.mocked(getFeederHealth).mockResolvedValue(payload);
      renderWithProviders(<FeederPanel />);
      const label = await screen.findByText(word);
      expect(label.parentElement!.querySelector("svg")).toHaveAttribute("data-tone", tone);
    });

    it("renders no Last poll row for a timestamp that is not a valid date", async () => {
      vi.mocked(getFeederHealth).mockResolvedValue(health({ last_successful_poll: 1e20 }));
      renderWithProviders(<FeederPanel />);
      await screen.findByText("Online");
      expect(fact("Last poll")).toBeNull();
      expect(valueOf("Errors")).toHaveTextContent("3");
    });

    it("shows a neutral word while the health loads and when it cannot be read", async () => {
      vi.mocked(getFeederHealth).mockReturnValue(new Promise(() => {}));
      const first = renderWithProviders(<FeederPanel />);
      expect(await screen.findByText("Checking")).toBeInTheDocument();
      first.unmount();
      vi.mocked(getFeederHealth).mockRejectedValue(new Error("boom"));
      renderWithProviders(<FeederPanel />);
      expect(await screen.findByText("Status unavailable")).toBeInTheDocument();
    });

    it("lists last poll as relative text in a time element with the exact time, plus the counts", async () => {
      const ts = Math.floor(Date.now() / 1000) - 300;
      vi.mocked(getFeederHealth).mockResolvedValue(health({ last_successful_poll: ts }));
      renderWithProviders(<FeederPanel />);
      await screen.findByText("Online");
      const time = valueOf("Last poll").querySelector("time")!;
      expect(time).toHaveTextContent("5 min ago");
      expect(time.getAttribute("datetime")).toBe(new Date(ts * 1000).toISOString());
      expect(time.getAttribute("title")).toBe(new Date(ts * 1000).toLocaleString());
      expect(valueOf("Emails processed")).toHaveTextContent("42");
      expect(valueOf("Errors")).toHaveTextContent("3");
      expect(fact("Reason")).toBeNull();
    });

    it("omits Last poll when the feeder has never polled, and any count the payload lacks", async () => {
      vi.mocked(getFeederHealth).mockResolvedValue(
        health({ last_successful_poll: null, emails_processed_total: undefined as never }),
      );
      renderWithProviders(<FeederPanel />);
      await screen.findByText("Online");
      expect(fact("Last poll")).toBeNull();
      expect(fact("Emails processed")).toBeNull();
      expect(valueOf("Errors")).toHaveTextContent("3");
    });

    it("shows the reason when offline and no counts the feeder could not report", async () => {
      vi.mocked(getFeederHealth).mockResolvedValue(
        health({ online: false, last_successful_poll: null, emails_processed_total: 0, errors_total: 0, error: "unreachable: ConnectionError" }),
      );
      renderWithProviders(<FeederPanel />);
      await screen.findByText("Offline");
      expect(valueOf("Reason")).toHaveTextContent("unreachable: ConnectionError");
      expect(fact("Emails processed")).toBeNull();
      expect(fact("Errors")).toBeNull();
      expect(fact("Last poll")).toBeNull();
    });

    it("runs one health request when the status strip badge and the panel are both mounted", async () => {
      vi.mocked(getFeederHealth).mockResolvedValue(health());
      renderWithProviders(<><FeederHealthBadge /><FeederPanel /></>);
      await screen.findByText("Online");
      await screen.findByText("Feeder: Online");
      expect(getFeederHealth).toHaveBeenCalledTimes(1);
    });
  });
});
