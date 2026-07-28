import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider } from "react-router";
import { QueryClientProvider } from "@tanstack/react-query";
import { CssBaseline, ThemeProvider } from "@mui/material";
import { router } from "@/app/router";
import { queryClient } from "@/app/queryClient";
import { AppThemeProvider } from "@/styles/ThemeStore";
import { SnackbarProvider } from "notistack";

import "@/bones/registry";
import { env } from "@/lib/runtimeEnv";

const favicon = env("VITE_FAVICON");
if (favicon) {
  let link = document.querySelector<HTMLLinkElement>("link[rel='icon']");
  if (!link) {
    link = document.createElement("link");
    link.rel = "icon";
    document.head.appendChild(link);
  }
  link.href = favicon;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <AppThemeProvider>
        <CssBaseline />
        <SnackbarProvider maxSnack={3} autoHideDuration={3000}>
          <RouterProvider router={router} />
        </SnackbarProvider>
      </AppThemeProvider>
    </QueryClientProvider>
  </React.StrictMode>
);

