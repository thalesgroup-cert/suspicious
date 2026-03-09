import { createBrowserRouter, Navigate } from "react-router-dom";
import AppLayout from "@/layouts/AppLayout";

import ProtectedRoute from "@/app/ProtectedRoute";
import PublicOnlyRoute from "@/app/PublicOnlyRoute";

import LoginPage from "@/pages/LoginPage";
import HomePage from "@/pages/HomePage";
import DashboardPage from "@/pages/DashboardPage";
import SubmitPage from "@/pages/SubmitPage";
import ProfilePage from "@/pages/ProfilePage";
import CampaignsPage from "@/pages/CampaignsPage";
import SettingsPage from "@/pages/SettingsPage";
import SubmissionsPage from "@/pages/SubmissionsPage";
import InvestigationPage from "@/pages/InvestigationPage";
import AboutPage from "@/pages/AboutPage";
import NotFound from "@/pages/NotFound";

export const router = createBrowserRouter([
  {
    path: "/login",
    element: (
      <PublicOnlyRoute>
        <LoginPage />
      </PublicOnlyRoute>
    ),
  },

  {
    path: "/",
    element: (
      <ProtectedRoute>
        <AppLayout />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <HomePage /> },
      { path: "campaigns", element: <CampaignsPage /> },
      { path: "dashboard", element: <DashboardPage /> },
      { path: "submit", element: <SubmitPage /> },
      { path: "submissions", element: <SubmissionsPage /> },
      { path: "investigation", element: <InvestigationPage /> },
      { path: "profile", element: <ProfilePage /> },
      { path: "settings", element: <SettingsPage /> },
      { path: "about", element: <AboutPage /> },
      { path: "*", element: <NotFound /> },
    ],
  },

  { path: "*", element: <Navigate to="/" replace /> },
]);