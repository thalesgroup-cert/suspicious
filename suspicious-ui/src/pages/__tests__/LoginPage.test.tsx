import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { mockMe } from "@/test/utils";

// ---------------------------------------------------------------------------
// Module mocks — must be top-level (vitest hoists these before imports)
// ---------------------------------------------------------------------------

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/styles/ThemeStore", () => ({
  default: ({ children }: { children: React.ReactNode }) => children,
  useThemeStore: () => ({ mode: "light", setMode: vi.fn() }),
}));

vi.mock("@/styles/colorStore", () => ({
  useColorStore: () => ({
    hydrateColors: vi.fn(),
    result: {},
    status: {},
  }),
  colorStore: { getState: () => ({ hydrateColors: vi.fn() }) },
}));

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

import { getMe, login } from "@/api/auth";
import LoginPage from "@/pages/LoginPage";

const mockGetMe = vi.mocked(getMe);
const mockLogin = vi.mocked(login);

function renderLogin(initialPath = "/login") {
  return renderWithProviders(<LoginPage />, { initialPath });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("LoginPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: unauthenticated
    mockGetMe.mockRejectedValue(new Error("401 Unauthorized"));
  });

  it("renders username and password fields", async () => {
    renderLogin();

    await waitFor(() => {
      expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    });
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
  });

  it("submit button is disabled when fields are empty", async () => {
    renderLogin();

    await waitFor(() => {
      expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    });

    const submitBtn = screen.getByRole("button", { name: /sign in|log in|login/i });
    expect(submitBtn).toBeDisabled();
  });

  it("enables submit once both fields are filled", async () => {
    const user = userEvent.setup();
    renderLogin();

    await waitFor(() =>
      expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    );

    await user.type(screen.getByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/password/i), "secret");

    const submitBtn = screen.getByRole("button", { name: /sign in|log in|login/i });
    expect(submitBtn).not.toBeDisabled();
  });

  it("calls login() with entered credentials on submit", async () => {
    const user = userEvent.setup();
    mockLogin.mockResolvedValue({ expiry: "2099-01-01T00:00:00Z" } as never);
    // After login success, getMe returns the user for color hydration
    mockGetMe
      .mockRejectedValueOnce(new Error("401"))
      .mockResolvedValue(mockMe as never);

    renderLogin();

    await waitFor(() =>
      expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    );

    await user.type(screen.getByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/password/i), "secret");
    await user.click(screen.getByRole("button", { name: /sign in|log in|login/i }));

    await waitFor(() =>
      expect(mockLogin).toHaveBeenCalledWith("alice", "secret")
    );
  });

  it("shows an error message on failed login", async () => {
    const user = userEvent.setup();
    mockLogin.mockRejectedValue({
      response: { data: { detail: "Invalid credentials." } },
    });

    renderLogin();

    await waitFor(() =>
      expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    );

    await user.type(screen.getByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/password/i), "wrong");
    await user.click(screen.getByRole("button", { name: /sign in|log in|login/i }));

    await waitFor(() =>
      expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument()
    );
  });

  it("redirects already-authenticated users away from login", async () => {
    mockGetMe.mockResolvedValue(mockMe as never);
    renderLogin();

    // MemoryRouter renders navigate — the login form should not appear
    await waitFor(() =>
      expect(screen.queryByLabelText(/username/i)).not.toBeInTheDocument()
    );
  });
});
