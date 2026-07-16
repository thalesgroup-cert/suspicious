import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AvatarPanel } from "@/features/profile/AvatarPanel";
import { getStyleCategories } from "@/features/profile/avatar";

function renderPanel(
  overrides: Partial<React.ComponentProps<typeof AvatarPanel>> = {},
) {
  const setOptions = vi.fn();
  const setSeed = vi.fn();
  render(
    <AvatarPanel
      style="avataaars"
      seed="abc123"
      setStyle={vi.fn()}
      setSeed={setSeed}
      options={{}}
      setOptions={setOptions}
      firstName="Al"
      lastName="Ice"
      dirtyBar={null}
      {...overrides}
    />,
  );
  return { setOptions, setSeed };
}

describe("AvatarPanel style options (enum categories)", () => {
  it("pins a value when a thumbnail is clicked after expanding the category", async () => {
    const eyes = getStyleCategories("avataaars").find((c) => c.key === "eyes")!;
    const { setOptions } = renderPanel();
    await userEvent.click(screen.getByLabelText("Eyes options"));
    await userEvent.click(screen.getByLabelText(`Eyes ${eyes.values[0]}`));
    expect(setOptions).toHaveBeenCalledWith({ eyes: [eyes.values[0]] });
  });

  it("clears a pinned category back to random via the Auto tile", async () => {
    const eyes = getStyleCategories("avataaars").find((c) => c.key === "eyes")!;
    const { setOptions } = renderPanel({ options: { eyes: [eyes.values[1]] } });
    await userEvent.click(screen.getByLabelText("Eyes options"));
    await userEvent.click(screen.getByLabelText("Eyes Auto"));
    expect(setOptions).toHaveBeenCalledWith({});
  });
});

describe("AvatarPanel colors", () => {
  it("pins a swatch color", async () => {
    const skin = getStyleCategories("avataaars").find((c) => c.key === "skinColor")!;
    const { setOptions } = renderPanel();
    await userEvent.click(screen.getByLabelText(`${skin.label} ${skin.values[0]}`));
    expect(setOptions).toHaveBeenCalledWith({ skinColor: [skin.values[0]] });
  });

  it("clears a pinned color back to random", async () => {
    const skin = getStyleCategories("avataaars").find((c) => c.key === "skinColor")!;
    const { setOptions } = renderPanel({ options: { skinColor: [skin.values[0]] } });
    await userEvent.click(screen.getByLabelText(`${skin.label} use random`));
    expect(setOptions).toHaveBeenCalledWith({});
  });

  it("renders a Background color group for styles that support it", () => {
    const bg = getStyleCategories("avataaars").find((c) => c.key === "backgroundColor")!;
    renderPanel();
    expect(screen.getByText("Background")).toBeInTheDocument();
    expect(screen.getByLabelText(`${bg.label} ${bg.values[0]}`)).toBeInTheDocument();
  });
});

describe("AvatarPanel initials style", () => {
  it("randomizes colors instead of reseeding", async () => {
    const { setOptions, setSeed } = renderPanel({ style: "initials", seed: "AL" });
    await userEvent.click(screen.getByRole("button", { name: /randomize/i }));
    expect(setSeed).not.toHaveBeenCalled();
    expect(setOptions).toHaveBeenCalledTimes(1);
    const arg = setOptions.mock.calls[0][0] as Record<string, string[]>;
    expect(Object.keys(arg).sort()).toEqual(["backgroundColor", "textColor"]);
  });

  it("shows the locked-seed hint instead of a raw seed value", () => {
    renderPanel({ style: "initials", seed: "AL" });
    expect(screen.getByText(/always your initials/i)).toBeInTheDocument();
  });
});

describe("AvatarPanel styles with no color fields", () => {
  it("hides the Colors and Background groups for notionists", () => {
    renderPanel({ style: "notionists" });
    expect(screen.queryByText("Colors")).not.toBeInTheDocument();
    expect(screen.queryByText("Background")).not.toBeInTheDocument();
  });
});
