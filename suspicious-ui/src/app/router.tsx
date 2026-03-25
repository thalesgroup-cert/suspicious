// src/app/router.tsx
import { createBrowserRouter, Navigate } from "react-router-dom";
import AppLayout from "@/layouts/AppLayout";

import ProtectedRoute from "@/app/ProtectedRoute";
import PublicOnlyRoute from "@/app/PublicOnlyRoute";

import LoginPage       from "@/pages/LoginPage";
import HomePage        from "@/pages/HomePage";
import DashboardPage   from "@/pages/DashboardPage";
import SubmitPage      from "@/pages/SubmitPage";
import ProfilePage     from "@/pages/ProfilePage";
import CampaignsPage   from "@/pages/CampaignsPage";
import SettingsPage    from "@/pages/SettingsPage";
import SubmissionsPage from "@/pages/SubmissionsPage";
import InvestigationPage from "@/pages/InvestigationPage";
import AboutPage       from "@/pages/AboutPage";
import NotFound        from "@/pages/NotFound";

// Groups that unlock elevated routes.
const ELEVATED = ["Admin", "CISO", "CERT"];
const ADMIN    = ["Admin", "CERT"];

export const router = createBrowserRouter([
  // ── Public routes (redirect to "/" if already authenticated) ───────────

  {
    path: "/login",
    element: (
      <PublicOnlyRoute>
        <LoginPage />
      </PublicOnlyRoute>
    ),
  },

  // ── Authenticated shell ────────────────────────────────────────────────
  {
    path: "/",
    element: (
      <ProtectedRoute>
        <AppLayout />
      </ProtectedRoute>
    ),
    children: [
      // ── General (any authenticated user) ──────────────────────────────
      { index: true,                  element: <HomePage /> },
      { path: "submit",               element: <SubmitPage /> },
      { path: "submissions",          element: <SubmissionsPage /> },
      { path: "profile",              element: <ProfilePage /> },
      { path: "about",                element: <AboutPage /> },

      // ── Elevated (CISO / CERT) ─────────────────────────────────────────
      {
        path: "campaigns",
        element: (
          <ProtectedRoute requireGroups={ELEVATED}>
            <CampaignsPage />
          </ProtectedRoute>
        ),
      },
      {
        path: "dashboard",
        element: (
          <ProtectedRoute requireGroups={ELEVATED}>
            <DashboardPage />
          </ProtectedRoute>
        ),
      },
      {
        path: "investigation",
        element: (
          <ProtectedRoute requireGroups={ELEVATED}>
            <InvestigationPage />
          </ProtectedRoute>
        ),
      },

      // ── Admin (Admin / CERT) ───────────────────────────────────────────
      {
        path: "settings",
        element: (
          <ProtectedRoute requireGroups={ADMIN}>
            <SettingsPage />
          </ProtectedRoute>
        ),
      },

      // ── 404 inside the authenticated shell ────────────────────────────
      // Renders the NotFound page inside the AppLayout (sidebar stays
      // visible — the user can navigate away without using the back button).
      { path: "*", element: <NotFound /> },
    ],
  },

  // ── Top-level 404 for paths that don't match any route at all ──────────
  // We DON'T silently redirect unknown paths to "/" — that hides bugs
  // and confuses users who follow a stale or typo'd link.
  { path: "*", element: <NotFound standalone /> },
]);