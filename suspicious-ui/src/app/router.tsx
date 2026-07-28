import React, { lazy, Suspense } from "react";
import { createBrowserRouter } from "react-router";
import AppLayout from "@/layouts/AppLayout";
import ProtectedRoute from "@/app/ProtectedRoute";
import PublicOnlyRoute from "@/app/PublicOnlyRoute";
import PageLoader from "@/styles/components/PageLoader";

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

const LoginPage        = lazy(() => import("@/pages/LoginPage"));
const HomePage         = lazy(() => import("@/pages/HomePage"));
const DashboardPage    = lazy(() => import("@/pages/DashboardPage"));
const SubmitPage       = lazy(() => import("@/pages/SubmitPage"));
const ProfilePage      = lazy(() => import("@/pages/ProfilePage"));
const CampaignsPage    = lazy(() => import("@/pages/CampaignsPage"));
const SettingsPage     = lazy(() => import("@/pages/SettingsPage"));
const SubmissionsPage  = lazy(() => import("@/pages/SubmissionsPage"));
const InvestigationPage = lazy(() => import("@/pages/InvestigationPage"));
const AboutPage        = lazy(() => import("@/pages/AboutPage"));
const NotFound         = lazy(() => import("@/pages/NotFound"));

const ELEVATED = ["Admin", "CISO", "CERT"];
const ADMIN    = ["Admin", "CERT"];

const fallback = <PageLoader />;
function S({ children }: { children: React.ReactElement }) {
  return <Suspense fallback={fallback}>{children}</Suspense>;
}

export const router = createBrowserRouter([
  // ── Public routes (redirect to "/" if already authenticated) ───────────

  {
    path: "/login",
    element: (
      <PublicOnlyRoute>
        <S><LoginPage /></S>
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
      { index: true,         element: <S><HomePage /></S> },
      { path: "submit",      element: <S><SubmitPage /></S> },
      { path: "submissions", element: <S><SubmissionsPage /></S> },
      { path: "profile",     element: <S><ProfilePage /></S> },
      { path: "about",       element: <S><AboutPage /></S> },

      // ── Elevated (CISO / CERT) ─────────────────────────────────────────
      {
        path: "campaigns",
        element: (
          <ProtectedRoute>
            <S><CampaignsPage /></S>
          </ProtectedRoute>
        ),
      },
      {
        path: "dashboard",
        element: (
          <ProtectedRoute>
            <S><DashboardPage /></S>
          </ProtectedRoute>
        ),
      },
      {
        path: "investigation",
        element: (
          <ProtectedRoute requireGroups={ELEVATED}>
            <S><InvestigationPage /></S>
          </ProtectedRoute>
        ),
      },

      // ── Admin (Admin / CERT) ───────────────────────────────────────────
      {
        path: "settings",
        element: (
          <ProtectedRoute requireGroups={ADMIN}>
            <S><SettingsPage /></S>
          </ProtectedRoute>
        ),
      },

      // ── 404 inside the authenticated shell ────────────────────────────
      { path: "*", element: <S><NotFound /></S> },
    ],
  },

  // ── Top-level 404 ──────────────────────────────────────────────────────
  { path: "*", element: <S><NotFound standalone /></S> },
]);
