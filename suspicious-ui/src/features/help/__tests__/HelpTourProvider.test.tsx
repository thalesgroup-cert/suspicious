import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";

const start = vi.fn();
vi.mock("react-joyride", () => ({
  useJoyride: () => ({ controls: { start }, on: () => () => {}, state: {}, Tour: null }),
}));

const getProfile = vi.fn();
const updatePreferences = vi.fn().mockResolvedValue({});
vi.mock("@/features/profile/api", () => ({
  getProfile: () => getProfile(),
  updatePreferences: (p: unknown) => updatePreferences(p),
}));

import { HelpTourProvider } from "../HelpTourProvider";
import { useHelpTour } from "../useHelpTour";

function Consumer() {
  const { start: startTour } = useHelpTour();
  return <button onClick={startTour}>go</button>;
}

describe("HelpTourProvider", () => {
  beforeEach(() => {
    start.mockClear();
    updatePreferences.mockClear();
  });

  it("auto-starts the tour once and persists tour_completed when unset", async () => {
    getProfile.mockResolvedValue({ tour_completed: false });
    renderWithProviders(
      <HelpTourProvider><div>content</div></HelpTourProvider>
    );
    await waitFor(() => expect(start).toHaveBeenCalledTimes(1));
    expect(updatePreferences).toHaveBeenCalledWith({ tour_completed: true });
  });

  it("does not auto-start when tour_completed is already true", async () => {
    getProfile.mockResolvedValue({ tour_completed: true });
    renderWithProviders(
      <HelpTourProvider><div>content</div></HelpTourProvider>
    );
    await waitFor(() => expect(screen.getByText("content")).toBeInTheDocument());
    expect(start).not.toHaveBeenCalled();
    expect(updatePreferences).not.toHaveBeenCalled();
  });

  it("exposes start() through context for manual launch", async () => {
    getProfile.mockResolvedValue({ tour_completed: true });
    renderWithProviders(
      <HelpTourProvider><Consumer /></HelpTourProvider>
    );
    await userEvent.click(screen.getByText("go"));
    expect(start).toHaveBeenCalledTimes(1);
  });
});
