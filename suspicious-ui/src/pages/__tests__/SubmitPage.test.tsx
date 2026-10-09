import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders, mockMe } from "@/test/utils";

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/api/client", () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
}));

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

import { getMe } from "@/api/auth";
import { api } from "@/api/client";
import SubmitPage from "@/pages/SubmitPage";

const mockGetMe = vi.mocked(getMe);
const mockApiGet = vi.mocked(api.get);
const mockApiPost = vi.mocked(api.post);

function renderSubmit() {
  return renderWithProviders(<SubmitPage />, { initialPath: "/submit" });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("SubmitPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetMe.mockResolvedValue(mockMe as never);
    mockApiGet.mockResolvedValue({ data: "suspicious@corp.test" } as never);
  });

  describe("mode selector", () => {
    const group = async () => screen.findByRole("group", { name: "Submission type" });
    const dropzone = () => screen.queryByText("Drag and drop or click to browse");

    it("defaults to Indicators: its panel shows, the file dropzone does not", async () => {
      renderSubmit();
      expect(await screen.findByLabelText("Indicators")).toBeInTheDocument();
      expect(dropzone()).not.toBeInTheDocument();
    });

    it("is a two-button group, Indicators first and pressed", async () => {
      renderSubmit();
      const buttons = within(await group()).getAllByRole("button");
      expect(buttons).toHaveLength(2);
      expect(buttons[0]).toHaveTextContent("Indicators");
      expect(buttons[1]).toHaveTextContent("File");
      expect(buttons[0]).toHaveAttribute("aria-pressed", "true");
      expect(buttons[1]).toHaveAttribute("aria-pressed", "false");
    });

    it("clicking File switches the panel and aria-pressed", async () => {
      const user = userEvent.setup();
      renderSubmit();
      const [ind, file] = within(await group()).getAllByRole("button");
      await user.click(file);
      expect(await screen.findByText("Drag and drop or click to browse")).toBeInTheDocument();
      expect(file).toHaveAttribute("aria-pressed", "true");
      expect(ind).toHaveAttribute("aria-pressed", "false");
    });

    it("clicking the active button keeps the selection", async () => {
      const user = userEvent.setup();
      renderSubmit();
      const [ind] = within(await group()).getAllByRole("button");
      await user.click(ind);
      expect(ind).toHaveAttribute("aria-pressed", "true");
      expect(await screen.findByLabelText("Indicators")).toBeInTheDocument();
    });

    it.each([[" "], ["{Enter}"]])("keyboard: arrow to File and press %j switches", async (key) => {
      const user = userEvent.setup();
      renderSubmit();
      const [ind, file] = within(await group()).getAllByRole("button");
      ind.focus();
      expect(ind).toHaveFocus();
      await user.keyboard("{ArrowRight}"); // roving tabindex: arrows move within the group
      expect(file).toHaveFocus();
      await user.keyboard(key);
      expect(file).toHaveAttribute("aria-pressed", "true");
      expect(await screen.findByText("Drag and drop or click to browse")).toBeInTheDocument();
    });

    it("has no Recommended or Selected chips", async () => {
      renderSubmit();
      await group();
      expect(screen.queryByText("Recommended")).not.toBeInTheDocument();
      expect(screen.queryByText("Selected")).not.toBeInTheDocument();
    });
  });

  describe("layout and honesty", () => {
    const CORR = /correlated as one case/;

    it("has one 'What to submit' card and no Accepted inputs or Guidance titles", async () => {
      renderSubmit();
      await screen.findByLabelText("Indicators");
      expect(screen.getAllByText("What to submit")).toHaveLength(1);
      expect(screen.queryByText("Accepted inputs")).not.toBeInTheDocument();
      expect(screen.queryByText("Guidance")).not.toBeInTheDocument();
    });

    it("shows the correlation note once, in Indicators mode only", async () => {
      const user = userEvent.setup();
      renderSubmit();
      await screen.findByLabelText("Indicators");
      expect(screen.getAllByText(CORR)).toHaveLength(1);
      const [, file] = within(await screen.findByRole("group", { name: "Submission type" })).getAllByRole("button");
      await user.click(file);
      await screen.findByText("Drag and drop or click to browse");
      expect(screen.queryByText(CORR)).not.toBeInTheDocument();
    });

    it("renders a disabled Submit visibly unlike an enabled one", async () => {
      const user = userEvent.setup();
      renderSubmit();
      const ta = await screen.findByLabelText("Indicators");
      const btn = screen.getByRole("button", { name: "Submit" });
      expect(btn).toBeDisabled();
      const off = getComputedStyle(btn).backgroundColor;
      await user.type(ta, "8.8.8.8");
      expect(btn).toBeEnabled();
      await waitFor(() => expect(getComputedStyle(btn).backgroundColor).not.toBe(off)); // bg transitions
    });

    it("headings carry no tight letter-spacing or extra-heavy weight", async () => {
      const user = userEvent.setup();
      renderSubmit();
      const [, file] = within(await screen.findByRole("group", { name: "Submission type" })).getAllByRole("button");
      await user.click(file);
      const h = await screen.findByText("File upload");
      const cs = getComputedStyle(h);
      const ls = cs.letterSpacing;
      expect(ls === "" || ls === "normal" || parseFloat(ls) >= -0.01 * parseFloat(cs.fontSize || "16")).toBe(true);
      expect(Number(cs.fontWeight)).toBeLessThanOrEqual(800);
    });
  });

  it("switches to indicators mode and shows the textarea + IOC upload", async () => {
    const user = userEvent.setup();
    renderSubmit();

    await user.click((await screen.findAllByText("Indicators"))[0]);

    expect(await screen.findByLabelText("Indicators")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /upload ioc list/i })
    ).toBeInTheDocument();
  });

  it("submit is disabled until a recognised indicator is entered", async () => {
    const user = userEvent.setup();
    renderSubmit();

    await user.click((await screen.findAllByText("Indicators"))[0]);
    const field = await screen.findByLabelText("Indicators");

    expect(screen.getByRole("button", { name: "Submit" })).toBeDisabled();
    await user.type(field, "8.8.8.8");
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Submit" })).not.toBeDisabled()
    );
  });

  it("submits a single indicator through /submit/indicators/", async () => {
    const user = userEvent.setup();
    mockApiPost.mockResolvedValue({
      data: { status: "success", case_id: 42, observable_count: 1, accepted: true, skipped: [] },
    } as never);

    renderSubmit();
    await user.click((await screen.findAllByText("Indicators"))[0]);
    await user.type(await screen.findByLabelText("Indicators"), "http://evil.example/x");

    const submitBtn = screen.getByRole("button", { name: "Submit" });
    await waitFor(() => expect(submitBtn).not.toBeDisabled());
    await user.click(submitBtn);

    await waitFor(() =>
      expect(mockApiPost).toHaveBeenCalledWith(
        "/submit/indicators/",
        expect.objectContaining({ indicators: expect.stringContaining("evil.example") })
      )
    );
  });

  it("uploads an IOC list and populates the textarea for review", async () => {
    const user = userEvent.setup();
    mockApiPost.mockResolvedValue({
      data: { status: "success", indicators: "1.1.1.1\nevil.test", found: 2, skipped: [] },
    } as never);

    renderSubmit();
    await user.click((await screen.findAllByText("Indicators"))[0]);
    await screen.findByLabelText("Indicators");

    const file = new File(["1.1.1.1\nevil.test\n"], "iocs.txt", { type: "text/plain" });
    const input = document.querySelector('input[type="file"][accept=".txt,.csv,.json"]');
    await user.upload(input as HTMLInputElement, file);

    await waitFor(() =>
      expect(mockApiPost).toHaveBeenCalledWith("/submit/indicators/extract/", expect.any(FormData))
    );
    await waitFor(() =>
      expect((screen.getByLabelText("Indicators") as HTMLTextAreaElement).value).toContain("evil.test")
    );
  });
  describe("file limit", () => {
    afterEach(() => vi.unstubAllEnvs());
    const cfg = (max?: number) => ({
      data: { status: "success", data: { suspicious_email: "s@corp.test", ...(max ? { max_file_bytes: max } : {}) } },
    });
    const renderFile = async () => {
      renderSubmit();
      await userEvent.setup().click(await screen.findByRole("button", { name: /^File/ }));
    };
    const fileInput = () => document.querySelector('input[type="file"]') as HTMLInputElement;
    const mk = (n: number, name = "a.eml") => new File([new Uint8Array(n)], name);

    it("rejects an oversized file with the real limit and no chip", async () => {
      mockApiGet.mockResolvedValue(cfg(1024) as never);
      await renderFile();
      await screen.findByText(/up to 1 KB/);
      await userEvent.setup({ applyAccept: false }).upload(fileInput(), mk(2048, "big.eml"));
      await waitFor(() =>
        expect(
          screen.getAllByRole("alert").some((a) => a.textContent === "big.eml is 2 KB; the limit is 1 KB.")
        ).toBe(true)
      );
      expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    });

    it("accepts a file of exactly the limit", async () => {
      mockApiGet.mockResolvedValue(cfg(1024) as never);
      await renderFile();
      await screen.findByText(/up to 1 KB/);
      await userEvent.setup().upload(fileInput(), mk(1024, "ok.eml"));
      expect(await screen.findByText("ok.eml")).toBeInTheDocument();
    });

    it("accepts a 0-byte file in the dropzone", async () => {
      mockApiGet.mockResolvedValue(cfg(1024) as never);
      await renderFile();
      await screen.findByText(/up to 1 KB/);
      await userEvent.setup().upload(fileInput(), mk(0, "empty.eml"));
      expect(await screen.findByText("empty.eml")).toBeInTheDocument();
    });

    it("without a loaded limit shows no 'undefined' and still selects a 10 MB file", async () => {
      mockApiGet.mockReturnValue(new Promise(() => {}) as never);
      await renderFile();
      await screen.findByText(/One file per submission/);
      expect(screen.queryByText(/undefined/)).not.toBeInTheDocument();
      await userEvent.setup().upload(fileInput(), mk(10 * 1024 * 1024, "huge.eml"));
      expect(await screen.findByText("huge.eml")).toBeInTheDocument();
    });

    it("rejects 1025 bytes when the limit is 1024", async () => {
      mockApiGet.mockResolvedValue(cfg(1024) as never);
      await renderFile();
      await screen.findByText(/up to 1 KB/);
      await userEvent.setup().upload(fileInput(), mk(1025, "over.eml"));
      expect(await screen.findByText(/over.eml is 1 KB; the limit is 1 KB\./)).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    });

    it("clears the rejection on the next good drop and on Remove", async () => {
      mockApiGet.mockResolvedValue(cfg(1024) as never);
      await renderFile();
      await screen.findByText(/up to 1 KB/);
      const user = userEvent.setup();
      await user.upload(fileInput(), mk(2048, "big.eml"));
      await screen.findByText(/big.eml is 2 KB/);
      await user.upload(fileInput(), mk(10, "ok.eml"));
      await screen.findByText("ok.eml");
      expect(screen.queryByText(/big.eml is/)).not.toBeInTheDocument();
      await user.upload(fileInput(), mk(2048, "big2.eml"));
      await screen.findByText(/big2.eml is 2 KB/);
      await user.click(screen.getByRole("button", { name: "Remove" }));
      expect(screen.queryByText(/big2.eml is/)).not.toBeInTheDocument();
    });

    it("with a failing config: dropzone works, no 'undefined', fallback email copyable", async () => {
      vi.stubEnv("VITE_SUSPICIOUS_EMAIL", ""); // .env sets it; these cases need it unset
      mockApiGet.mockRejectedValue(new Error("boom") as never);
      const user = userEvent.setup();
      const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
      await renderFile();
      const btn = await screen.findByRole("button", { name: "suspicious@example.com" });
      expect(btn).toBeEnabled();
      expect(screen.queryByText(/undefined/)).not.toBeInTheDocument();
      await user.upload(fileInput(), mk(3 * 1024 * 1024, "m.eml"));
      expect(await screen.findByText("m.eml")).toBeInTheDocument();
      await user.click(btn);
      expect(write).toHaveBeenCalledWith("suspicious@example.com");
    });

    it("disables the email copy while config is pending, then copies the resolved address", async () => {
      vi.stubEnv("VITE_SUSPICIOUS_EMAIL", ""); // .env sets it; these cases need it unset
      let resolve!: (v: unknown) => void;
      mockApiGet.mockReturnValue(new Promise((r) => (resolve = r)) as never);
      const user = userEvent.setup();
      const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
      await renderFile();
      const loading = await screen.findByRole("button", { name: "Loading address…" });
      expect(loading).toBeDisabled();
      resolve(cfg(1024).data && cfg(1024));
      const btn = await screen.findByRole("button", { name: "s@corp.test" });
      expect(btn).toBeEnabled();
      await user.click(btn);
      expect(write).toHaveBeenCalledWith("s@corp.test");
      expect(write).toHaveBeenCalledTimes(1);
    });

    it("shows the limit in the helper text", async () => {
      mockApiGet.mockResolvedValue(cfg(5242880) as never);
      await renderFile();
      expect(await screen.findByText("One file per submission, up to 5 MB.")).toBeInTheDocument();
    });
  });

  describe("indicator summary", () => {
    const cfg = (max?: number) => ({
      data: { status: "success", data: { suspicious_email: "s@corp.test", ...(max ? { max_indicators: max } : {}) } },
    });
    const open = async () => {
      const user = userEvent.setup();
      renderSubmit();
      await user.click((await screen.findAllByText("Indicators"))[0]);
      return { user, field: await screen.findByLabelText("Indicators") };
    };
    const ips = (n: number) => Array.from({ length: n }, (_, i) => `10.0.${Math.floor(i / 250)}.${(i % 250) + 1}`).join("\n");

    it("states what will be submitted and what is skipped", async () => {
      const { user, field } = await open();
      await user.click(field);
      await user.paste("not a thing  mail.example.org 999.1.1.1");
      expect(await screen.findByText("1 will be submitted · 2 skipped")).toBeInTheDocument();
      expect(screen.getAllByText("skipped").length).toBe(2);
      expect(screen.queryByText("unrecognised")).not.toBeInTheDocument();
      expect(screen.queryByText(/indicator\(s\)/)).not.toBeInTheDocument();
    });

    it("explains when nothing is recognisable", async () => {
      const { user, field } = await open();
      await user.click(field);
      await user.paste("just words");
      expect(await screen.findByText("Nothing recognisable yet. Add a URL, domain, IP or hash.")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Submit" })).toBeDisabled();
    });

    it("disables Submit above the default limit of 100", async () => {
      const { user, field } = await open();
      await user.click(field);
      await user.paste(ips(101));
      expect(await screen.findByText("101 indicators; the limit is 100.")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Submit" })).toBeDisabled();
    });

    it("says 'up to' with a note only when a URL row is present", async () => {
      const { user, field } = await open();
      await user.click(field);
      await user.paste("8.8.8.8");
      const status = await screen.findByText("1 will be submitted");
      expect(status).toHaveAttribute("role", "status");
      expect(screen.queryByText(/Links to private or internal/)).not.toBeInTheDocument();
      await user.type(field, " http://evil.example/x");
      expect(await screen.findByText("up to 2 will be submitted")).toBeInTheDocument();
      expect(screen.getByText(/Links to private or internal addresses are skipped/)).toBeInTheDocument();
    });

    it("links the disabled Submit to the summary", async () => {
      const { user, field } = await open();
      await user.click(field);
      await user.paste("just words");
      const status = await screen.findByText(/Nothing recognisable/);
      expect(screen.getByRole("button", { name: "Submit" })).toHaveAttribute("aria-describedby", status.id);
    });

    it("uses the configured limit and ignores skipped rows when counting", async () => {
      mockApiGet.mockResolvedValue(cfg(2) as never);
      const { user, field } = await open();
      await user.click(field);
      await user.paste("8.8.8.8 foo 1.1.1.1 bar baz");
      expect(await screen.findByText("2 will be submitted · 2 skipped")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Submit" })).not.toBeDisabled();
      await user.type(field, " 9.9.9.9");
      expect(await screen.findByText("3 indicators; the limit is 2.")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Submit" })).toBeDisabled();
    });
  });
});
