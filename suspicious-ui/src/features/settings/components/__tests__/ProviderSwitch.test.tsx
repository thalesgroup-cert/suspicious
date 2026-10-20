import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { page } from "@vitest/browser/context";

import { renderWithProviders } from "@/test/utils";
import { ConnectorDrawer } from "../ConnectorDrawer";
import type { ConfigField, Connector } from "../connectors";

vi.mock("../connectors", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../connectors")>();
  return { ...actual, getConnectorConfig: vi.fn(), putConnectorConfig: vi.fn(), testConnector: vi.fn(), listDeliveries: vi.fn().mockResolvedValue([]) };
});

const f = (key: string, type: ConfigField["type"] = "str"): ConfigField => ({ key, type, required: false, default: null, help: "" });
const AI: Connector = {
  name: "ai_narration",
  version: "0.1.0",
  description: "Narrates verdicts.",
  author: "",
  docs_url: "",
  category: "AI",
  events: [],
  schedules: [],
  config_schema: [
    f("narration_provider"),
    f("ollama_url", "url"),
    f("ollama_model"),
    f("openai_compatible_base_url", "url"),
    f("openai_compatible_api_key", "secret"),
    f("openai_compatible_model"),
    f("openai_api_key", "secret"),
    f("openai_model"),
    f("anthropic_api_key", "secret"),
    f("anthropic_model"),
    f("gemini_api_key", "secret"),
    f("gemini_model"),
  ],
  enabled: true,
  enabled_by_default: false,
  status: "connected",
  last_health_ok: true,
  last_health_detail: "",
  last_health_at: null,
};
const SAVED = {
  narration_provider: "ollama",
  ollama_url: "http://ollama:11434",
  ollama_model: "qwen",
  openai_compatible_base_url: "https://gw.example/v1",
  openai_compatible_api_key: "********",
  openai_compatible_model: "gpt-x",
  openai_api_key: "",
  openai_model: "",
  anthropic_api_key: "",
  anthropic_model: "",
  gemini_api_key: "",
  gemini_model: "",
};
const LABEL = "Provider used when narration runs automatically";

async function open(saved: Record<string, unknown> = SAVED) {
  const { getConnectorConfig } = await import("../connectors");
  vi.mocked(getConnectorConfig).mockResolvedValue(saved);
  renderWithProviders(<ConnectorDrawer connector={AI} onClose={vi.fn()} />, { initialPath: "/settings/connectors?tab=configuration" });
  return screen.findByRole("group", { name: LABEL });
}
const segment = (name: string) => screen.getByRole("button", { name });

beforeEach(async () => {
  await page.viewport(1280, 900);
});

describe("provider switch", () => {
  it("is a two-segment toggle group with an accessible name, the saved provider selected", async () => {
    const group = await open();
    expect(within(group).getAllByRole("button").map((b) => b.textContent)).toEqual(["Ollama", "OpenAI-compatible"]);
    expect(segment("Ollama")).toHaveAttribute("aria-pressed", "true");
    expect(segment("OpenAI-compatible")).toHaveAttribute("aria-pressed", "false");
  });

  it("puts only the selected provider's fields in the DOM and hides the raw provider input, keeping its key in the helper text", async () => {
    await open();
    expect(screen.getByLabelText("Ollama URL")).toBeInTheDocument();
    expect(screen.getByLabelText("Ollama Model")).toBeInTheDocument();
    expect(screen.queryByLabelText("OpenAI Compatible Base URL")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Narration Provider")).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /provider/i })).not.toBeInTheDocument();
    expect(screen.getByRole("group", { name: LABEL })).toHaveAccessibleDescription(/narration_provider/);
  });

  it("switching changes the visible fields and makes a draft, and the other provider's saved values are saved untouched", async () => {
    const { putConnectorConfig } = await import("../connectors");
    vi.mocked(putConnectorConfig).mockResolvedValueOnce({ ...SAVED, narration_provider: "openai_compatible" });
    await open();
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    await userEvent.click(segment("OpenAI-compatible"));
    expect(segment("OpenAI-compatible")).toHaveAttribute("aria-pressed", "true");
    expect(screen.queryByLabelText("Ollama URL")).not.toBeInTheDocument();
    expect(screen.getByLabelText("OpenAI Compatible Base URL")).toHaveValue("https://gw.example/v1");
    expect(screen.getByRole("button", { name: "Save changes" })).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(putConnectorConfig).toHaveBeenCalled());
    expect(vi.mocked(putConnectorConfig).mock.calls.at(-1)![1]).toMatchObject({
      narration_provider: "openai_compatible",
      ollama_url: "http://ollama:11434",
      ollama_model: "qwen",
      openai_compatible_base_url: "https://gw.example/v1",
    });
  });

  it("keeps what was typed for a provider when switching away and back", async () => {
    await open();
    await userEvent.type(screen.getByLabelText("Ollama URL"), "/x");
    await userEvent.click(segment("OpenAI-compatible"));
    await userEvent.click(segment("Ollama"));
    expect(screen.getByLabelText("Ollama URL")).toHaveValue("http://ollama:11434/x");
  });

  it("says an unset provider means Ollama and lets a click on Ollama make it explicit", async () => {
    await open({ ...SAVED, narration_provider: "" });
    expect(segment("Ollama")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("Not set: Ollama is used")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    await userEvent.click(segment("Ollama"));
    expect(segment("Ollama")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Save changes" })).toBeEnabled();
    expect(screen.queryByText("Not set: Ollama is used")).not.toBeInTheDocument();
  });

  it("names an unknown saved provider and says picking one replaces it", async () => {
    await open({ ...SAVED, narration_provider: "anthropic" });
    expect(screen.getByText("Unknown provider 'anthropic' is saved; pick one to replace it")).toBeInTheDocument();
    expect(segment("Ollama")).toHaveAttribute("aria-pressed", "true");
  });

  it("is operable from the keyboard: arrows move between the segments, Space and Enter select", async () => {
    await open();
    const user = userEvent.setup();
    segment("Ollama").focus();
    await user.keyboard("{ArrowRight}");
    expect(segment("OpenAI-compatible")).toHaveFocus();
    await user.keyboard(" ");
    expect(segment("OpenAI-compatible")).toHaveAttribute("aria-pressed", "true");
    await user.keyboard("{ArrowLeft}");
    expect(segment("Ollama")).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(segment("Ollama")).toHaveAttribute("aria-pressed", "true");
  });
});

describe("manual-run providers", () => {
  const DISCLOSURE = "Manual-run providers (OpenAI, Anthropic, Gemini)";

  it("is collapsed by default", async () => {
    await open();
    const toggle = screen.getByRole("button", { name: DISCLOSURE });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByLabelText("OpenAI API Key")).not.toBeInTheDocument();
    expect(screen.queryByText(/used only by manual runs/)).not.toBeInTheDocument();
  });

  it("opens to the note and the six fields", async () => {
    await open();
    await userEvent.click(screen.getByRole("button", { name: DISCLOSURE }));
    expect(screen.getByRole("button", { name: DISCLOSURE })).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("These keys are used only by manual runs (manage.py test_ai_narration), not when a case is finalised.")).toBeVisible();
    for (const label of ["OpenAI API Key", "OpenAI Model", "Anthropic API Key", "Anthropic Model", "Gemini API Key", "Gemini Model"]) {
      expect(screen.getByLabelText(label)).toBeInTheDocument();
    }
  });
});

describe("other connectors", () => {
  it("keep the generic grouped form without a switch", async () => {
    const { getConnectorConfig } = await import("../connectors");
    vi.mocked(getConnectorConfig).mockResolvedValue({});
    renderWithProviders(
      <ConnectorDrawer connector={{ ...AI, name: "other", config_schema: [f("ollama_url", "url"), f("ollama_model"), f("narration_provider")] }} onClose={vi.fn()} />,
      { initialPath: "/settings/connectors?tab=configuration" },
    );
    expect(await screen.findByLabelText("Narration Provider")).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: LABEL })).not.toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Ollama" })).toBeInTheDocument();
  });
});
