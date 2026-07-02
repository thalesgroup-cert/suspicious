import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AvatarPanel } from "@/features/profile/AvatarPanel";
import { getStyleCategories } from "@/features/profile/avatar";

function renderPanel(options: Record<string, string[]>, setOptions = vi.fn()) {
  render(
    <AvatarPanel
      style="avataaars"
      seed="abc123"
      setStyle={vi.fn()}
      setSeed={vi.fn()}
      options={options}
      setOptions={setOptions}
      firstName="Al"
      lastName="Ice"
      dirtyBar={null}
    />,
  );
  return setOptions;
}

describe("AvatarPanel categories", () => {
  it("pins the first value of a category when Next is clicked from Auto", async () => {
    const eyes = getStyleCategories("avataaars").find((c) => c.key === "eyes")!;
    const setOptions = renderPanel({});
    await userEvent.click(screen.getByLabelText("Eyes next option"));
    expect(setOptions).toHaveBeenCalledWith({ eyes: [eyes.values[0]] });
  });

  it("clears a pinned category back to random", async () => {
    const eyes = getStyleCategories("avataaars").find((c) => c.key === "eyes")!;
    const setOptions = renderPanel({ eyes: [eyes.values[1]] });
    await userEvent.click(screen.getByLabelText("Eyes use random"));
    expect(setOptions).toHaveBeenCalledWith({});
  });
});
