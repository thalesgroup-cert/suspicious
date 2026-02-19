import * as React from "react";
import { createBrowserRouter, Navigate } from "react-router-dom";
import AppLayout from "@/layouts/AppLayout";

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


// placeholders si pas encore migré
const Placeholder = (p: { title: string }) => (
  <div style={{ padding: 24 }}>{p.title}</div>
);

export const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },

  {
    path: "/",
    element: <AppLayout />,
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
      { path: "*", element: <NotFound /> }
    ],
  },

  // fallback global
  { path: "*", element: <Navigate to="/" replace /> },
]);
