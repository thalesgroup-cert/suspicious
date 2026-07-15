import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ColorField } from "@/features/profile/components/ColorField";

const PALETTE = ["614335", "d08b5b", "edb98a"];

describe("ColorField", () => {
  it("calls onChange with the clicked swatch's hex", async () => {
    const onChange = vi.fn();
    render(
      <ColorField label="Skin Color" palette={PALETTE} onChange={onChange} onReset={vi.fn()} />,
    );
    await userEvent.click(screen.getByLabelText("Skin Color 614335"));
    expect(onChange).toHaveBeenCalledWith("614335");
  });

  it("marks the current value's swatch as pressed", () => {
    render(
      <ColorField label="Skin Color" palette={PALETTE} value="d08b5b" onChange={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByLabelText("Skin Color d08b5b")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByLabelText("Skin Color 614335")).toHaveAttribute("aria-pressed", "false");
  });

  it("strips the # and lowercases when a custom hex is picked", () => {
    const onChange = vi.fn();
    render(
      <ColorField label="Skin Color" palette={PALETTE} onChange={onChange} onReset={vi.fn()} />,
    );
    const input = screen.getByLabelText("Skin Color custom color");
    fireEvent.change(input, { target: { value: "#ABCDEF" } });
    expect(onChange).toHaveBeenCalledWith("abcdef");
  });

  it("calls onReset from the use-random control, disabled when no value is set", async () => {
    const onReset = vi.fn();
    const { rerender } = render(
      <ColorField label="Skin Color" palette={PALETTE} onChange={vi.fn()} onReset={onReset} />,
    );
    expect(screen.getByLabelText("Skin Color use random")).toBeDisabled();

    rerender(
      <ColorField label="Skin Color" palette={PALETTE} value="614335" onChange={vi.fn()} onReset={onReset} />,
    );
    await userEvent.click(screen.getByLabelText("Skin Color use random"));
    expect(onReset).toHaveBeenCalled();
  });
});
