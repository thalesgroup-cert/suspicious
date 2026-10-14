import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ThemeProvider } from "@mui/material/styles";
import { themes } from "@/styles/themes";
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

  it("wears the paper theme's own surface and border", () => {
    render(
      <ThemeProvider theme={themes.paper}>
        <SoftCard>
          <span>paper card</span>
        </SoftCard>
      </ThemeProvider>
    );
    const card = screen.getByText("paper card").closest(".MuiCard-root") as HTMLElement;
    const cs = getComputedStyle(card);
    expect(cs.backgroundImage).toContain('url("data:image/svg+xml');
    expect(cs.borderTopColor).not.toMatch(/0\.9\)/);
  });
});
