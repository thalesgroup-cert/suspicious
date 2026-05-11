import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { Routes, Route } from "react-router-dom";
import { renderWithProviders, mockMe } from "@/test/utils";

// ---------------------------------------------------------------------------
// Module mocks (hoisted)
// ---------------------------------------------------------------------------

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
}));

vi.mock("@/styles/components/PageLoader", () => ({
  default: () => <div data-testid="page-loader">loading</div>,
}));

import { getMe } from "@/api/auth";
import ProtectedRoute from "@/app/ProtectedRoute";

const mockGetMe = vi.mocked(getMe);

function ProtectedTree(props: { requireGroups?: string[] }) {
  return (
    <Routes>
      <Route path="/login" element={<div data-testid="login">login-page</div>} />
      <Route path="/" element={<div data-testid="home">home-page</div>} />
      <Route
        path="/secret"
        element={
          <ProtectedRoute requireGroups={props.requireGroups}>
            <div data-testid="secret">secret-page</div>
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}

describe("ProtectedRoute", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the loader while /me is in flight", async () => {
    // Never-resolving promise keeps the query in isLoading.
    mockGetMe.mockImplementation(() => new Promise(() => {}));

    renderWithProviders(<ProtectedTree />, { initialPath: "/secret" });

    expect(await screen.findByTestId("page-loader")).toBeInTheDocument();
    expect(screen.queryByTestId("secret")).not.toBeInTheDocument();
  });

  it("redirects to /login when /me rejects (unauthenticated)", async () => {
    mockGetMe.mockRejectedValue(new Error("401"));

    renderWithProviders(<ProtectedTree />, { initialPath: "/secret" });

    expect(await screen.findByTestId("login")).toBeInTheDocument();
    expect(screen.queryByTestId("secret")).not.toBeInTheDocument();
  });

  it("renders children once /me resolves", async () => {
    mockGetMe.mockResolvedValue({ ...mockMe });

    renderWithProviders(<ProtectedTree />, { initialPath: "/secret" });

    expect(await screen.findByTestId("secret")).toBeInTheDocument();
  });

  it("redirects to / when the user lacks the required group", async () => {
    mockGetMe.mockResolvedValue({ ...mockMe, groups: ["Basic"] });

    renderWithProviders(
      <ProtectedTree requireGroups={["Admin", "CERT"]} />,
      { initialPath: "/secret" }
    );

    expect(await screen.findByTestId("home")).toBeInTheDocument();
    expect(screen.queryByTestId("secret")).not.toBeInTheDocument();
  });

  it("renders children when the user has at least one required group", async () => {
    mockGetMe.mockResolvedValue({ ...mockMe, groups: ["CERT"] });

    renderWithProviders(
      <ProtectedTree requireGroups={["Admin", "CERT"]} />,
      { initialPath: "/secret" }
    );

    await waitFor(() => {
      expect(screen.getByTestId("secret")).toBeInTheDocument();
    });
  });
});
