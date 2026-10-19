import { describe, it, expect } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { contrastRatio, flatten } from "@/shared/lib/contrast";
import { SERIES } from "../utils";
import ClassChip from "../components/ClassChip";

const dot = (name: string) => screen.getByText(name).closest(".MuiChip-root")!.querySelector(".MuiChip-icon") as HTMLElement;

describe("ClassChip", () => {
  it("shows on and off by shape as well as colour: a filled dot when on, a hollow ring when off", () => {
    renderWithProviders(
      <>
        <ClassChip k="SAFE" label="On" on />
        <ClassChip k="SAFE" label="Off" on={false} />
      </>
    );
    const filled = getComputedStyle(dot("On"));
    const ring = getComputedStyle(dot("Off"));
    expect(filled.backgroundColor).not.toBe("rgba(0, 0, 0, 0)");
    expect(ring.backgroundColor).toBe("rgba(0, 0, 0, 0)");
    expect(parseFloat(ring.borderTopWidth)).toBeGreaterThanOrEqual(1.5);
  });

  it("keeps the dot at 3:1 against the chip's own tint, for every class", () => {
    renderWithProviders(
      <>
        {SERIES.map(([k, label]) => (
          <ClassChip key={k} k={k} label={label} />
        ))}
      </>
    );
    const page = getComputedStyle(document.body).backgroundColor;
    for (const [, label] of SERIES) {
      const chip = screen.getByText(label).closest(".MuiChip-root")!;
      const tint = flatten(getComputedStyle(chip).backgroundColor, page);
      expect(contrastRatio(getComputedStyle(dot(label)).backgroundColor, tint), label).toBeGreaterThanOrEqual(3);
    }
  });
});
