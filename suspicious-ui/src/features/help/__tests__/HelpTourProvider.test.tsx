import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";

// Mock the library: capture the controls.start spy, render nothing for Tour.
const start = vi.fn();
vi.mock("react-joyride", () => ({
  useJoyride: () => ({ controls: { start }, on: () => () => {}, state: {}, Tour: null }),
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
    localStorage.clear();
  });

  it("auto-starts the tour once when the seen flag is unset", () => {
    renderWithProviders(
      <HelpTourProvider><div>content</div></HelpTourProvider>
    );
    expect(start).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem("suspicious.tour.seen")).toBe("1");
  });

  it("does not auto-start when the seen flag is already set", () => {
    localStorage.setItem("suspicious.tour.seen", "1");
    renderWithProviders(
      <HelpTourProvider><div>content</div></HelpTourProvider>
    );
    expect(start).not.toHaveBeenCalled();
  });

  it("exposes start() through context for manual launch", async () => {
    localStorage.setItem("suspicious.tour.seen", "1"); // suppress auto-run
    renderWithProviders(
      <HelpTourProvider><Consumer /></HelpTourProvider>
    );
    await userEvent.click(screen.getByText("go"));
    expect(start).toHaveBeenCalledTimes(1);
  });
});
