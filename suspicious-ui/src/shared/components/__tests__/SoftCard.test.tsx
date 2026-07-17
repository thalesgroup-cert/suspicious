import { describe, it, expect } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { SoftCard } from "@/shared/components/SoftCard";

describe("SoftCard", () => {
  it("renders its children", () => {
    renderWithProviders(
      <SoftCard>
        <span>card body</span>
      </SoftCard>
    );
    expect(screen.getByText("card body")).toBeInTheDocument();
  });

  it("merges a custom sx without throwing", () => {
    renderWithProviders(
      <SoftCard sx={{ p: 3 }}>
        <span>styled</span>
      </SoftCard>
    );
    expect(screen.getByText("styled")).toBeInTheDocument();
  });
});
