import { describe, it, expect } from "vitest";
import { filterItems, getPageTitle, type NavItemConfig } from "@/layouts/nav";

const item = (to: string, label: string, elevatedOnly?: boolean): NavItemConfig =>
  ({ to, label, elevatedOnly, icon: null as unknown as NavItemConfig["icon"] });

const items = [
  item("/", "Home"),
  item("/submit", "Submit"),
  item("/investigation", "Investigation", true),
];

describe("filterItems", () => {
  it("hides elevated-only items for non-elevated users", () => {
    expect(filterItems(items, false).map((i) => i.label)).toEqual(["Home", "Submit"]);
  });

  it("shows everything for elevated users", () => {
    expect(filterItems(items, true)).toHaveLength(3);
  });
});

describe("getPageTitle", () => {
  it("matches a non-root route by prefix", () => {
    expect(getPageTitle("/submit/new", items)).toBe("Submit");
    expect(getPageTitle("/investigation", items)).toBe("Investigation");
  });

  it("does not prefix-match the root route", () => {
    expect(getPageTitle("/unknown", items)).toBe("Workspace");
  });

  it("matches the root route exactly", () => {
    expect(getPageTitle("/", items)).toBe("Home");
  });
});
