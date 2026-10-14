import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient } from "@tanstack/react-query";
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

async function revealPasswordForm(user: ReturnType<typeof userEvent.setup>) {
  const disclose = await screen.findByRole("button", {
    name: /sign in with username and password/i,
  });
  await user.click(disclose);
  await waitFor(() =>
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("LoginPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetMe.mockRejectedValue(new Error("401 Unauthorized"));
  });

  it("renders username and password fields", async () => {
    const user = userEvent.setup();
    renderLogin();

    await revealPasswordForm(user);
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^password/i)).toBeInTheDocument();
  });

  it("submit button is disabled when fields are empty", async () => {
    const user = userEvent.setup();
    renderLogin();

    await revealPasswordForm(user);

    const submitBtn = screen.getByRole("button", { name: "Sign in" });
    expect(submitBtn).toBeDisabled();
  });

  it("enables submit once both fields are filled", async () => {
    const user = userEvent.setup();
    renderLogin();

    await revealPasswordForm(user);

    await user.type(screen.getByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/^password/i), "secret");

    const submitBtn = screen.getByRole("button", { name: "Sign in" });
    expect(submitBtn).not.toBeDisabled();
  });

  it("calls login() with entered credentials on submit", async () => {
    const user = userEvent.setup();
    mockLogin.mockResolvedValue({ expiry: "2099-01-01T00:00:00Z" } as never);
    mockGetMe
      .mockRejectedValueOnce(new Error("401"))
      .mockResolvedValue(mockMe as never);

    renderLogin();

    await revealPasswordForm(user);

    await user.type(screen.getByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/^password/i), "secret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(mockLogin).toHaveBeenCalledWith("alice", "secret")
    );
  });

  it("clears the previous user's cached queries on a successful login", async () => {
    const user = userEvent.setup();
    mockLogin.mockResolvedValue({ expiry: "2099-01-01T00:00:00Z" } as never);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
    qc.setQueryData(["dashboardSummary", 10, 2026, "ALL"], { top_reporters: [{ label: "someone", value: 3 }] });
    qc.setQueryData(["dashboardScopes"], { default: "OWN_SCOPE", options: [] });
    renderWithProviders(<LoginPage />, { initialPath: "/login", queryClient: qc });
    await revealPasswordForm(user);
    await user.type(screen.getByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/^password/i), "secret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(mockLogin).toHaveBeenCalled());
    await waitFor(() => expect(qc.getQueryData(["dashboardScopes"])).toBeUndefined());
    expect(qc.getQueryData(["dashboardSummary", 10, 2026, "ALL"])).toBeUndefined();
  });

  it("shows an error message on failed login", async () => {
    const user = userEvent.setup();
    mockLogin.mockRejectedValue({
      response: { data: { detail: "Invalid credentials." } },
    });

    renderLogin();

    await revealPasswordForm(user);

    await user.type(screen.getByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/^password/i), "wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(screen.getByText(/check your credentials/i)).toBeInTheDocument()
    );
  });

  it("redirects already-authenticated users away from login", async () => {
    mockGetMe.mockResolvedValue(mockMe as never);
    renderLogin();

    await waitFor(() =>
      expect(screen.queryByLabelText(/username/i)).not.toBeInTheDocument()
    );
  });
});
