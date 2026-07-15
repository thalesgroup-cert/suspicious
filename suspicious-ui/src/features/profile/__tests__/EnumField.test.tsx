import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EnumField } from "@/features/profile/components/EnumField";

const VALUES = ["closed", "happy", "wink"];

function renderThumb(v: string) {
  return `data:image/svg+xml;utf8,<svg>${v}</svg>`;
}

describe("EnumField", () => {
  it("starts collapsed and does not render thumbnails until expanded", () => {
    render(
      <EnumField label="Eyes" values={VALUES} onChange={vi.fn()} onReset={vi.fn()} renderThumb={renderThumb} />,
    );
    expect(screen.queryByLabelText("Eyes closed")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Eyes options")).toHaveTextContent("Auto");
  });

  it("expands on click and shows a tile per value plus Auto", async () => {
    render(
      <EnumField label="Eyes" values={VALUES} onChange={vi.fn()} onReset={vi.fn()} renderThumb={renderThumb} />,
    );
    await userEvent.click(screen.getByLabelText("Eyes options"));
    for (const v of VALUES) {
      expect(screen.getByLabelText(`Eyes ${v}`)).toBeInTheDocument();
    }
    expect(screen.getByLabelText("Eyes Auto")).toBeInTheDocument();
  });

  it("calls onChange when a value tile is clicked", async () => {
    const onChange = vi.fn();
    render(
      <EnumField label="Eyes" values={VALUES} onChange={onChange} onReset={vi.fn()} renderThumb={renderThumb} />,
    );
    await userEvent.click(screen.getByLabelText("Eyes options"));
    await userEvent.click(screen.getByLabelText("Eyes happy"));
    expect(onChange).toHaveBeenCalledWith("happy");
  });

  it("calls onReset when the Auto tile is clicked", async () => {
    const onReset = vi.fn();
    render(
      <EnumField label="Eyes" values={VALUES} value="wink" onChange={vi.fn()} onReset={onReset} renderThumb={renderThumb} />,
    );
    await userEvent.click(screen.getByLabelText("Eyes options"));
    await userEvent.click(screen.getByLabelText("Eyes Auto"));
    expect(onReset).toHaveBeenCalled();
  });

  it("shows the current value and option count in the collapsed summary", () => {
    render(
      <EnumField label="Eyes" values={VALUES} value="wink" onChange={vi.fn()} onReset={vi.fn()} renderThumb={renderThumb} />,
    );
    expect(screen.getByLabelText("Eyes options")).toHaveTextContent("wink");
    expect(screen.getByLabelText("Eyes options")).toHaveTextContent("3");
  });
});
