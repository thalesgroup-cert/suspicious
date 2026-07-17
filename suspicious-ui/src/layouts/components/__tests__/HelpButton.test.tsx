import { describe, it, expect, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";

const start = vi.fn();
vi.mock("@/features/help/useHelpTour", async (orig) => {
  const actual = await orig<typeof import("@/features/help/useHelpTour")>();
  return { ...actual, useHelpTour: () => ({ start }) };
});

import { HelpButton } from "../navComponents";

describe("HelpButton", () => {
  it("starts the tour when clicked", async () => {
    renderWithProviders(<HelpButton slim={false} />);
    await userEvent.click(screen.getByRole("button", { name: /help/i }));
    expect(start).toHaveBeenCalledTimes(1);
  });
});
