import { afterEach, describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";

import { renderWithProviders } from "@/test/utils";
import { themes } from "@/styles/themes";
import { composite, contrastRatio, flatten } from "@/shared/lib/contrast";
import { StatusLabel, connectorStatus } from "../StatusLabel";
import type { Connector } from "../connectors";

type Tone = "ok" | "warning" | "danger" | "neutral" | "info";
const TONES: Tone[] = ["ok", "warning", "danger", "neutral", "info"];

afterEach(() => localStorage.removeItem("suspicious.theme"));

describe("StatusLabel", () => {
  it.each(TONES)("shows an icon and the word for tone %s, icon first", (tone) => {
    renderWithProviders(<StatusLabel tone={tone} label={`word-${tone}`} />);
    const word = screen.getByText(`word-${tone}`);
    const icon = word.parentElement!.querySelector("svg")!;
    expect(icon).not.toBeNull();
    // Left aligned: the icon precedes the label in document order.
    expect(icon.compareDocumentPosition(word) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(icon.getAttribute("aria-hidden")).toBe("true");
  });

  it.each(["light", "midnight"] as const)("meets 4.5:1 for the text and 3:1 for the icon on the %s paper", (theme) => {
    localStorage.setItem("suspicious.theme", theme);
    const paper = themes[theme].palette.background.paper;
    renderWithProviders(
      <>
        {TONES.map((t) => <StatusLabel key={t} tone={t} label={`w-${t}`} />)}
      </>,
    );
    for (const t of TONES) {
      const word = screen.getByText(`w-${t}`);
      const icon = word.parentElement!.querySelector("svg")!;
      expect(contrastRatio(getComputedStyle(word).color, paper), `${t} text`).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(getComputedStyle(icon).color, paper), `${t} icon`).toBeGreaterThanOrEqual(3);
    }
  });

  // The label also sits on a hovered selected connector row (primary tint 12% light, 20% dark) and straight on the shell (primary glow up to 7% over the page colour).
  it.each(Object.keys(themes) as (keyof typeof themes)[])("stays readable on a selected row and on the shell in the %s theme", (theme) => {
    localStorage.setItem("suspicious.theme", theme);
    const { palette } = themes[theme];
    const primary = flatten(palette.primary.main, palette.background.paper);
    const backgrounds = {
      row: composite(primary, palette.mode === "dark" ? 0.2 : 0.12, palette.background.paper),
      shell: composite(primary, 0.07, palette.background.default),
    };
    renderWithProviders(
      <>
        {TONES.map((t) => <StatusLabel key={t} tone={t} label={`w-${t}`} />)}
      </>,
    );
    for (const [where, bg] of Object.entries(backgrounds)) {
      for (const t of TONES) {
        const word = screen.getByText(`w-${t}`);
        const icon = word.parentElement!.querySelector("svg")!;
        expect(contrastRatio(getComputedStyle(word).color, bg), `${theme} ${where} ${t} text`).toBeGreaterThanOrEqual(4.5);
        expect(contrastRatio(getComputedStyle(icon).color, bg), `${theme} ${where} ${t} icon`).toBeGreaterThanOrEqual(3);
      }
    }
  });

  it("is smaller at size small", () => {
    renderWithProviders(
      <>
        <StatusLabel tone="ok" label="s" size="small" />
        <StatusLabel tone="ok" label="m" size="medium" />
      </>,
    );
    const px = (l: string) => parseFloat(getComputedStyle(screen.getByText(l)).fontSize);
    expect(px("s")).toBeLessThan(px("m"));
  });
});

const c = (status: Connector["status"], ok: boolean | null): Pick<Connector, "status" | "last_health_ok"> =>
  ({ status, last_health_ok: ok });

describe("connectorStatus", () => {
  it.each([
    [c("connected", null), "ok", "Connected"],
    [c("connected", true), "ok", "Connected"],
    [c("partial", null), "warning", "Incomplete"],
    [c("disabled", null), "neutral", "Disabled"],
    [c("connected", false), "danger", "Unhealthy"],
    [c("partial", false), "danger", "Unhealthy"],
    [c("disabled", false), "neutral", "Disabled"],
  ])("%j -> %s %s", (conn, tone, label) => {
    expect(connectorStatus(conn)).toEqual({ tone, label });
  });
});
