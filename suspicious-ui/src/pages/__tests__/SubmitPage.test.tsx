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

    await waitFor(() => {
      // Both mode cards should be visible
      expect(screen.getByText(/file|email/i)).toBeInTheDocument();
      expect(screen.getByText(/url|artifact|indicator/i)).toBeInTheDocument();
    });
  });

  it("shows file dropzone in file mode (default)", async () => {
    renderSubmit();

    await waitFor(() => {
      // The drop zone or a label like "Drop a file" or "Choose file"
      expect(
        screen.getByText(/drop|drag|upload|choose|select/i)
      ).toBeInTheDocument();
    });
  });

  it("switches to artifact mode and shows text input", async () => {
    const user = userEvent.setup();
    renderSubmit();

    await waitFor(() => {
      // Look for the artifact/URL mode selector
      expect(screen.getByText(/url|artifact|indicator/i)).toBeInTheDocument();
    });

    // Click the artifact mode selector
    const artifactMode = screen.getByText(/url|artifact|indicator/i);
    await user.click(artifactMode);

    await waitFor(() => {
      // A text input for the artifact value should appear
      expect(
        screen.getByRole("textbox", { name: /url|indicator|value/i })
      ).toBeInTheDocument();
    });
  });

  it("submit button is disabled when artifact input is empty", async () => {
    const user = userEvent.setup();
    renderSubmit();

    await waitFor(() =>
      expect(screen.getByText(/url|artifact|indicator/i)).toBeInTheDocument()
    );

    await user.click(screen.getByText(/url|artifact|indicator/i));

    await waitFor(() => {
      const submitBtn = screen.getByRole("button", { name: /submit|analyze|send/i });
      expect(submitBtn).toBeDisabled();
    });
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

    await waitFor(() =>
      expect(screen.getByText(/url|artifact|indicator/i)).toBeInTheDocument()
    );

    await user.click(screen.getByText(/url|artifact|indicator/i));

    await waitFor(() =>
      expect(
        screen.getByRole("textbox", { name: /url|indicator|value/i })
      ).toBeInTheDocument()
    );

    await user.type(
      screen.getByRole("textbox", { name: /url|indicator|value/i }),
      "http://evil.example.com/phishing"
    );

    const submitBtn = screen.getByRole("button", { name: /submit|analyze|send/i });
    await waitFor(() => expect(submitBtn).not.toBeDisabled());
    await user.click(submitBtn);

    await waitFor(() => expect(mockApiPost).toHaveBeenCalled());
  });
});
