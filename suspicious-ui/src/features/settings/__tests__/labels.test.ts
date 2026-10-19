import { describe, expect, it } from "vitest";

import { cleanDescription, fieldLabel } from "../labels";

const field = (key: string, extra: object = {}) => ({
  key,
  type: "str" as const,
  required: false,
  default: null,
  help: "",
  ...extra,
});

describe("fieldLabel", () => {
  it("title-cases a snake_case key and upper-cases acronyms", () => {
    expect(fieldLabel(field("ollama_url"))).toBe("Ollama URL");
    expect(fieldLabel(field("api_key"))).toBe("API Key");
    expect(fieldLabel(field("verify_ssl"))).toBe("Verify SSL");
    expect(fieldLabel(field("smtp_host"))).toBe("SMTP Host");
    expect(fieldLabel(field("imap_tls_id"))).toBe("IMAP TLS ID");
    expect(fieldLabel(field("source_ip"))).toBe("Source IP");
  });

  it("handles several words and a single word", () => {
    expect(fieldLabel(field("max_retry_count"))).toBe("Max Retry Count");
    expect(fieldLabel(field("timeout"))).toBe("Timeout");
  });

  it("treats the dots of a nested key as word breaks", () => {
    expect(fieldLabel(field("instances.primary.url"))).toBe("Instances Primary URL");
  });

  it("does not upper-case a word that merely contains an acronym", () => {
    expect(fieldLabel(field("identity"))).toBe("Identity");
  });

  it("prefers a schema label when the field carries one", () => {
    expect(fieldLabel(field("ollama_url", { label: "Ollama endpoint" }))).toBe("Ollama endpoint");
  });
});

describe("cleanDescription", () => {
  it("strips a trailing See sentence that points into docs/", () => {
    expect(
      cleanDescription(
        "Narrates verdicts. See docs/specs/2026-09-21-ai-narration-event-wiring-design.md.",
      ),
    ).toBe("Narrates verdicts.");
  });

  it("strips a docs/ sentence in the middle and keeps the rest", () => {
    expect(cleanDescription("First. See docs/a/b.md. Second.")).toBe("First. Second.");
  });

  it("only strips a sentence that is exactly a doc pointer", () => {
    expect(cleanDescription("See docs/x.md for details.")).toBe("See docs/x.md for details.");
    expect(cleanDescription("Pushes. See docs/x.md, then restart.")).toBe(
      "Pushes. See docs/x.md, then restart.",
    );
    expect(cleanDescription("See also docs/a.md and docs/b.md.")).toBe(
      "See also docs/a.md and docs/b.md.",
    );
  });

  it("strips a final pointer to a hyphenated spec path", () => {
    expect(cleanDescription("X. See docs/specs/a-b.md.")).toBe("X.");
  });

  it("strips the real ai_narration pointer and keeps the sentence before it", () => {
    expect(
      cleanDescription(
        "Generates a plain-language narration via a locally-run LLM. Fires on case finalisation; `manage.py test_ai_narration` can use any configured provider. See docs/specs/2026-09-21-ai-narration-event-wiring-design.md.",
      ),
    ).toBe(
      "Generates a plain-language narration via a locally-run LLM. Fires on case finalisation; `manage.py test_ai_narration` can use any configured provider.",
    );
  });

  it("keeps descriptions without a docs reference untouched", () => {
    expect(cleanDescription("Push to MISP")).toBe("Push to MISP");
  });

  it("keeps See sentences that do not point at docs/", () => {
    const text = "Pushes alerts. See the TheHive manual for details.";
    expect(cleanDescription(text)).toBe(text);
    expect(cleanDescription("Pushes. See https://example.test/docs/x.")).toBe(
      "Pushes. See https://example.test/docs/x.",
    );
  });

  it("returns an empty string unchanged", () => {
    expect(cleanDescription("")).toBe("");
  });
});
