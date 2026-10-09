import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
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

  it("renders the two submission modes", async () => {
    renderSubmit();

    expect(
      await screen.findByText("Drag and drop or click to browse")
    ).toBeInTheDocument();
    // File mode is default; the mode cards show File + Indicators, no third.
    expect(screen.getAllByText("Indicators").length).toBeGreaterThan(0);
    expect(screen.queryByText("URL, Domain or Indicator")).not.toBeInTheDocument();
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
    const cfg = (max?: number) => ({
      data: { status: "success", data: { suspicious_email: "s@corp.test", ...(max ? { max_file_bytes: max } : {}) } },
    });
    const fileInput = () => document.querySelector('input[type="file"]') as HTMLInputElement;
    const mk = (n: number, name = "a.eml") => new File([new Uint8Array(n)], name);

    it("rejects an oversized file with the real limit and no chip", async () => {
      mockApiGet.mockResolvedValue(cfg(1024) as never);
      renderSubmit();
      await screen.findByText(/up to 1 KB/);
      await userEvent.setup({ applyAccept: false }).upload(fileInput(), mk(2048, "big.eml"));
      expect(await screen.findByText("big.eml is 2 KB; the limit is 1 KB.")).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    });

    it("accepts a file of exactly the limit", async () => {
      mockApiGet.mockResolvedValue(cfg(1024) as never);
      renderSubmit();
      await screen.findByText(/up to 1 KB/);
      await userEvent.setup().upload(fileInput(), mk(1024, "ok.eml"));
      expect(await screen.findByText("ok.eml")).toBeInTheDocument();
    });

    it("accepts a 0-byte file in the dropzone", async () => {
      mockApiGet.mockResolvedValue(cfg(1024) as never);
      renderSubmit();
      await screen.findByText(/up to 1 KB/);
      await userEvent.setup().upload(fileInput(), mk(0, "empty.eml"));
      expect(await screen.findByText("empty.eml")).toBeInTheDocument();
    });

    it("without a loaded limit shows no 'undefined' and still selects a 10 MB file", async () => {
      mockApiGet.mockReturnValue(new Promise(() => {}) as never);
      renderSubmit();
      await screen.findByText(/One file per submission/);
      expect(screen.queryByText(/undefined/)).not.toBeInTheDocument();
      await userEvent.setup().upload(fileInput(), mk(10 * 1024 * 1024, "huge.eml"));
      expect(await screen.findByText("huge.eml")).toBeInTheDocument();
    });

    it("shows the limit in the helper text", async () => {
      mockApiGet.mockResolvedValue(cfg(5242880) as never);
      renderSubmit();
      expect(await screen.findByText("One file per submission, up to 5 MB.")).toBeInTheDocument();
    });
  });
});
