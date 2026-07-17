import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConfigFieldInput } from "../configFieldHelpers";
import { dottedGet, dottedSet, stripUnchangedSecrets } from "../configHelpers";

describe("dottedGet / dottedSet", () => {
  it("reads a nested value by dotted key", () => {
    expect(dottedGet({ a: { b: 1 } }, "a.b")).toBe(1);
  });

  it("returns undefined for a missing path", () => {
    expect(dottedGet({ a: {} }, "a.b.c")).toBeUndefined();
  });

  it("writes a nested value by dotted key, creating intermediate objects", () => {
    const obj: Record<string, unknown> = {};
    dottedSet(obj, "a.b", 2);
    expect(obj).toEqual({ a: { b: 2 } });
  });
});

describe("stripUnchangedSecrets", () => {
  it("removes a secret field left as the mask placeholder", () => {
    expect(stripUnchangedSecrets({ api_key: "********" }, ["api_key"])).toEqual({});
  });

  it("removes a secret field left empty", () => {
    expect(stripUnchangedSecrets({ api_key: "" }, ["api_key"])).toEqual({});
  });

  it("keeps a secret field the user actually changed", () => {
    expect(stripUnchangedSecrets({ api_key: "new-value" }, ["api_key"])).toEqual({
      api_key: "new-value",
    });
  });

  it("leaves non-secret fields untouched", () => {
    expect(stripUnchangedSecrets({ url: "https://x", api_key: "********" }, ["api_key"])).toEqual({
      url: "https://x",
    });
  });
});

describe("ConfigFieldInput", () => {
  it("renders a secret field as a password input with a mask placeholder", () => {
    render(
      <ConfigFieldInput
        field={{ key: "api_key", type: "secret", required: false, default: null, help: "" }}
        value=""
        onChange={vi.fn()}
      />,
    );
    const input = screen.getByLabelText("api_key") as HTMLInputElement;
    expect(input.type).toBe("password");
    expect(input.placeholder).toBe("********");
  });

  it("renders a bool field as a checked switch", () => {
    render(
      <ConfigFieldInput
        field={{ key: "verify_tls", type: "bool", required: false, default: false, help: "" }}
        value={true}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByRole("switch")).toBeChecked();
  });

  it("renders a str field as a text input with help text", () => {
    render(
      <ConfigFieldInput
        field={{ key: "url", type: "str", required: false, default: null, help: "Base URL" }}
        value="https://example.test"
        onChange={vi.fn()}
      />,
    );
    // required: false chosen to test plain str field rendering without the asterisk decoration,
    // which would break exact label matching in getByLabelText
    const input = screen.getByLabelText("url") as HTMLInputElement;
    expect(input.value).toBe("https://example.test");
    expect(screen.getByText("Base URL")).toBeInTheDocument();
  });
});
