import { describe, expect, it, vi } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { renderWithProviders } from "@/test/utils";
import { FactList } from "../FactList";

describe("FactList", () => {
  it("renders a description list with a dt and a dd per row", () => {
    const { container } = renderWithProviders(
      <FactList items={[{ key: "Status", value: "Connected" }, { key: "Author", value: "Thales" }]} />,
    );
    expect(container.querySelector("dl")).not.toBeNull();
    expect([...container.querySelectorAll("dt")].map((n) => n.textContent)).toEqual(["Status", "Author"]);
    expect([...container.querySelectorAll("dd")].map((n) => n.textContent)).toEqual(["Connected", "Thales"]);
  });

  it("names the row action '<label> <hiddenName>' and fires onClick", async () => {
    const onClick = vi.fn();
    renderWithProviders(
      <FactList items={[{ key: "Schedules", value: "every 15 min", action: { label: "Change", hiddenName: "schedules", onClick } }]} />,
    );
    const btn = screen.getByRole("button", { name: "Change schedules" });
    // The visible text is only the label; the key is read out but not shown twice.
    expect(within(btn).getByText("Change")).toBeVisible();
    await userEvent.click(btn);
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("renders no button for rows without an action", () => {
    renderWithProviders(<FactList items={[{ key: "A", value: "b" }]} />);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("separates rows with dividers", () => {
    const { container } = renderWithProviders(
      <FactList items={[{ key: "A", value: "1" }, { key: "B", value: "2" }]} />,
    );
    const rows = [...container.querySelectorAll("dl > div")];
    expect(rows).toHaveLength(2);
    expect(getComputedStyle(rows[1]).borderTopWidth).toBe("1px");
  });
});
