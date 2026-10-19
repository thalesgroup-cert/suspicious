import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { page } from "vitest/browser";
import { QueryClient } from "@tanstack/react-query";
import { createTestQueryClient, renderWithProviders } from "@/test/utils";
import {
  fixtureMeSuperuser,
  fixtureSettingsList,
  fixtureFeederStatus,
  fixtureAnalyzers,
} from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/features/settings/api", () => ({
  listItems: vi.fn(),
  addItems: vi.fn(),
  removeItem: vi.fn(),
  addFromFile: vi.fn(),
  getFeederStatus: vi.fn(),
  setFeederStatus: vi.fn(),
  getFeederHealth: vi.fn(),
  listAnalyzers: vi.fn(),
  updateAnalyzerWeight: vi.fn(),
}));

vi.mock("@/features/settings/components/connectors", () => ({
  listConnectors: vi.fn().mockResolvedValue({ connectors: [], load_errors: {} }),
  setConnectorEnabled: vi.fn(),
  getConnectorConfig: vi.fn().mockResolvedValue({}),
  putConnectorConfig: vi.fn(),
  testConnector: vi.fn(),
  listDeliveries: vi.fn().mockResolvedValue([]),
}));


import { getMe } from "@/api/auth";
import {
  listItems,
  getFeederStatus,
  getFeederHealth,
  listAnalyzers,
} from "@/features/settings/api";
import SettingsPage from "../SettingsPage";
void getFeederStatus;

const ROUTE = "settings/:section?";

function open(path: string, queryClient?: QueryClient) {
  return renderWithProviders(<SettingsPage />, { initialPath: path, routePath: ROUTE, queryClient });
}

describe("SettingsPage - Test Suite", () => {
  beforeEach(async () => {
    // Desktop rail; the phone picker is covered separately.
    await page.viewport(1280, 900);
    vi.mocked(getMe).mockResolvedValue(fixtureMeSuperuser);
    vi.mocked(listItems).mockResolvedValue(fixtureSettingsList as never);
    vi.mocked(getFeederStatus).mockResolvedValue(fixtureFeederStatus);
    vi.mocked(getFeederHealth).mockResolvedValue({ online: true, last_successful_poll: null, emails_processed_total: 0, errors_total: 0, stale_seconds: 0, stale: false, checked_at: 0, error: null });
    vi.mocked(listAnalyzers).mockResolvedValue(fixtureAnalyzers);
  });

  describe("Access", () => {
    it("calls getMe on mount", async () => {
      open("/settings");
      await waitFor(() => expect(getMe).toHaveBeenCalled());
    });

    it("shows Not authorized for a user outside Admin and CERT", async () => {
      vi.mocked(getMe).mockResolvedValue({ ...fixtureMeSuperuser, groups: ["Analyst"] });
      open("/settings");
      expect(await screen.findByText(/not authorized/i)).toBeInTheDocument();
    });
  });

  describe("Sections by URL", () => {
    it("opens the first section at /settings", async () => {
      open("/settings");
      expect(await screen.findByRole("heading", { level: 2, name: "Domains allowlist" })).toBeInTheDocument();
    });

    it("opens the section named in the URL", async () => {
      open("/settings/scoring");
      expect(await screen.findByRole("heading", { level: 2, name: "Analyzer scoring" })).toBeInTheDocument();
    });

    it("redirects an unknown section to the first", async () => {
      const { router } = open("/settings/nope");
      await waitFor(() => expect(router!.state.location.pathname).toBe("/settings/domains_allow"));
      expect(await screen.findByRole("heading", { level: 2, name: "Domains allowlist" })).toBeInTheDocument();
    });

    it("tolerates a trailing slash", async () => {
      open("/settings/scoring/");
      expect(await screen.findByRole("heading", { level: 2, name: "Analyzer scoring" })).toBeInTheDocument();
    });

    it("changes the URL when a nav item is clicked and Back restores the previous section", async () => {
      const user = userEvent.setup();
      const { router } = open("/settings/domains_allow");
      const nav = await screen.findByRole("navigation", { name: "Settings sections" });
      await user.click(within(nav).getByRole("link", { name: "Connectors" }));
      await waitFor(() => expect(router!.state.location.pathname).toBe("/settings/connectors"));
      expect(await screen.findByRole("heading", { level: 2, name: "Connectors" })).toBeInTheDocument();
      await router!.navigate(-1);
      await waitFor(() => expect(router!.state.location.pathname).toBe("/settings/domains_allow"));
      expect(await screen.findByRole("heading", { level: 2, name: "Domains allowlist" })).toBeInTheDocument();
    });
  });

  describe("Navigation", () => {
    it("groups sections under the five labels with aria-current only on the active item", async () => {
      open("/settings/scoring");
      const nav = await screen.findByRole("navigation", { name: "Settings sections" });
      for (const label of ["Detection lists", "Access", "Ingestion", "Scoring", "Integrations"]) {
        expect(within(nav).getByText(label)).toBeInTheDocument();
      }
      expect(within(nav).queryAllByRole("heading")).toHaveLength(0);
      const current = within(nav)
        .getAllByRole("link")
        .filter((a) => a.getAttribute("aria-current") === "page");
      expect(current).toHaveLength(1);
      expect(current[0]).toHaveAccessibleName("Analyzer scoring");
    });

    it("uses a labelled picker on a phone", async () => {
      await page.viewport(390, 800);
      const { router } = open("/settings/domains_allow");
      expect(await screen.findByRole("heading", { level: 1, name: "Settings" })).toBeInTheDocument();
      expect(screen.queryByRole("navigation", { name: "Settings sections" })).not.toBeInTheDocument();
      const picker = await screen.findByLabelText("Settings section");
      await userEvent.selectOptions(picker, "scoring");
      await waitFor(() => expect(router!.state.location.pathname).toBe("/settings/scoring"));
    });
  });

  describe("Header", () => {
    it("has one h1, a subtitle naming every area, and no avatar or Admin console card", async () => {
      open("/settings");
      const h1 = await screen.findByRole("heading", { level: 1, name: "Settings" });
      expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
      const subtitle = h1.parentElement!.textContent ?? "";
      for (const word of ["lists", "access", "feeder", "scoring", "connectors"]) {
        expect(subtitle.toLowerCase()).toContain(word);
      }
      expect(screen.queryByText(/admin console/i)).not.toBeInTheDocument();
      expect(document.querySelector(".MuiAvatar-root")).toBeNull();
    });

    it("has a single Refresh that invalidates settings, connectors, config and deliveries", async () => {
      const user = userEvent.setup();
      const qc = createTestQueryClient();
      const spy = vi.spyOn(qc, "invalidateQueries");
      open("/settings", qc);
      const refresh = await screen.findAllByRole("button", { name: /refresh/i });
      expect(refresh).toHaveLength(1);
      await user.click(refresh[0]);
      const filters = spy.mock.calls.map((c) => c[0]);
      const predicate = filters.find((f) => f?.predicate)?.predicate;
      expect(predicate).toBeTypeOf("function");
      const hit = (key: unknown[]) => predicate!({ queryKey: key } as never);
      expect(hit(["settings", "list", "domains_allow"])).toBe(true);
      expect(hit(["connectors"])).toBe(true);
      expect(hit(["connector-config", "misp"])).toBe(true);
      expect(hit(["connector-deliveries", "misp"])).toBe(true);
      expect(hit(["me"])).toBe(false);
    });

    it("shows the status strip", async () => {
      open("/settings");
      expect(await screen.findByText("Running")).toBeInTheDocument();
    });
  });

  describe("Heading outline", () => {
    it("has h1 then a single panel h2 without per-panel refresh", async () => {
      open("/settings/email_feeder");
      await screen.findByRole("heading", { level: 2, name: "Email feeder" });
      expect(screen.getAllByRole("heading", { level: 2 })).toHaveLength(1);
    });
  });
});
