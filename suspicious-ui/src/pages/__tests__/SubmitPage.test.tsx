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

// api.post / api.get used for submissions and config
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
    // getSubmitConfig response (returns suspicious_email or a config object)
    mockApiGet.mockResolvedValue({ data: "suspicious@corp.test" } as never);
  });

  it("renders both submission modes", async () => {
    renderSubmit();

    // File mode is the default; both mode cards are present.
    expect(
      await screen.findByText("Drag and drop or click to browse")
    ).toBeInTheDocument();
    expect(screen.getByText("URL, Domain or Indicator")).toBeInTheDocument();
  });

  it("shows file dropzone in file mode (default)", async () => {
    renderSubmit();

    expect(
      await screen.findByText("Drag and drop or click to browse")
    ).toBeInTheDocument();
  });

  it("switches to artifact mode and shows text input", async () => {
    const user = userEvent.setup();
    renderSubmit();

    await user.click(await screen.findByText("URL, Domain or Indicator"));

    // The artifact value field (label "URL, domain or indicator") appears.
    expect(
      await screen.findByLabelText(/url, domain or indicator/i)
    ).toBeInTheDocument();
  });

  it("submit button is disabled when artifact input is empty", async () => {
    const user = userEvent.setup();
    renderSubmit();

    await user.click(await screen.findByText("URL, Domain or Indicator"));
    await screen.findByLabelText(/url, domain or indicator/i);

    expect(screen.getByRole("button", { name: "Submit" })).toBeDisabled();
  });

  it("submits a URL artifact and calls api.post", async () => {
    const user = userEvent.setup();
    mockApiPost.mockResolvedValue({
      data: {
        status: "success",
        accepted: true,
        submission_type: "url",
        result_type: "case",
        case_id: 42,
        message: "Accepted",
      },
    } as never);

    renderSubmit();

    await user.click(await screen.findByText("URL, Domain or Indicator"));

    const field = await screen.findByLabelText(/url, domain or indicator/i);
    await user.type(field, "http://evil.example.com/phishing");

    const submitBtn = screen.getByRole("button", { name: "Submit" });
    await waitFor(() => expect(submitBtn).not.toBeDisabled());
    await user.click(submitBtn);

    await waitFor(() => expect(mockApiPost).toHaveBeenCalled());
  });
});
