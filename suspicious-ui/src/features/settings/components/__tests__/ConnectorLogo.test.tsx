import { afterEach, describe, expect, it } from "vitest";
import { fireEvent, screen } from "@testing-library/react";

import { renderWithProviders } from "@/test/utils";
import { themes } from "@/styles/themes";
import { ConnectorLogo } from "../ConnectorLogo";

afterEach(() => localStorage.removeItem("suspicious.theme"));

const tile = () => screen.getByTestId("connector-logo");

describe("ConnectorLogo", () => {
  it.each(["thehive", "misp", "chromadb", "watcher", "case_search"])("renders a decorative img for %s", (name) => {
    renderWithProviders(<ConnectorLogo name={name} />);
    const img = tile().querySelector("img")!;
    expect(img).not.toBeNull();
    expect(img.getAttribute("alt")).toBe("");
    expect(img.getAttribute("src")).toBeTruthy();
    expect(getComputedStyle(img).objectFit).toBe("contain");
  });

  it.each(["smtp_notify", "ai_narration", "something_new"])("falls back to the neutral icon tile for %s", (name) => {
    renderWithProviders(<ConnectorLogo name={name} />);
    expect(tile().querySelector("img")).toBeNull();
    expect(tile().querySelector("svg")).not.toBeNull();
  });

  it("uses distinct neutral icons for smtp_notify and ai_narration", () => {
    const a = renderWithProviders(<ConnectorLogo name="smtp_notify" />);
    const mail = a.container.querySelector("svg")!.getAttribute("data-testid");
    a.unmount();
    const b = renderWithProviders(<ConnectorLogo name="ai_narration" />);
    expect(b.container.querySelector("svg")!.getAttribute("data-testid")).not.toBe(mail);
  });

  it("falls back to the icon tile after the image errors", () => {
    renderWithProviders(<ConnectorLogo name="misp" />);
    fireEvent.error(tile().querySelector("img")!);
    expect(tile().querySelector("img")).toBeNull();
    expect(tile().querySelector("svg")).not.toBeNull();
  });

  it("keeps a fixed square tile, 40 px by default, with a divider border on the paper surface", () => {
    renderWithProviders(<ConnectorLogo name="misp" />);
    const cs = getComputedStyle(tile());
    expect([cs.width, cs.height]).toEqual(["40px", "40px"]);
    expect(cs.borderTopWidth).toBe("1px");
    expect(cs.backgroundColor).not.toBe("rgba(0, 0, 0, 0)");
  });

  it("honours the size prop for both a logo and a fallback", () => {
    renderWithProviders(<><ConnectorLogo name="misp" size={64} /><ConnectorLogo name="nope" size={24} /></>);
    const [a, b] = screen.getAllByTestId("connector-logo").map((n) => getComputedStyle(n));
    expect([a.width, a.height, b.width, b.height]).toEqual(["64px", "64px", "24px", "24px"]);
  });

  it("keeps the mark off the border with padding", () => {
    renderWithProviders(<ConnectorLogo name="misp" />);
    expect(parseFloat(getComputedStyle(tile()).paddingTop)).toBeGreaterThan(0);
  });

  it("puts a logo on white even on midnight, and the fallback and a failed image on the paper surface", () => {
    localStorage.setItem("suspicious.theme", "midnight");
    const paper = themes.midnight.palette.background.paper;
    const toRgb = (hex: string) => {
      const n = parseInt(hex.slice(1), 16);
      return `rgb(${n >> 16}, ${(n >> 8) & 255}, ${n & 255})`;
    };
    renderWithProviders(<><ConnectorLogo name="misp" /><ConnectorLogo name="smtp_notify" /><ConnectorLogo name="thehive" /></>);
    const [logo, fallback, broken] = screen.getAllByTestId("connector-logo");
    expect(getComputedStyle(logo).backgroundColor).toBe("rgb(255, 255, 255)");
    expect(getComputedStyle(fallback).backgroundColor).toBe(toRgb(paper));
    fireEvent.error(broken.querySelector("img")!);
    expect(getComputedStyle(broken).backgroundColor).toBe(toRgb(paper));
  });

  it("shows the new logo when the name changes after an image error", () => {
    const { rerender } = renderWithProviders(<ConnectorLogo name="misp" />);
    fireEvent.error(tile().querySelector("img")!);
    expect(tile().querySelector("img")).toBeNull();
    rerender(<ConnectorLogo name="thehive" />);
    expect(tile().querySelector("img")).not.toBeNull();
  });
});
